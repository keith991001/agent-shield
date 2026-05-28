//go:build linux

// agent-shield — Week 2 daemon.
//
// Loads the eBPF probes defined in bpf/probe.c, attaches them to 5 syscall
// tracepoints, runs each event through a YAML rule engine, and either
// logs / alerts / kills the offending process. Events are emitted as
// structured JSON on stdout.
//
//go:generate go tool bpf2go -tags linux -target amd64,arm64 bpf bpf/probe.c -- -I./headers
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Event type constants — must match enum event_type in bpf/probe.c
const (
	EventExec     = 1
	EventOpenat   = 2
	EventUnlinkat = 3
	EventConnect  = 4
	EventSocket   = 5
)

// Event is the JSON shape emitted on stdout and broadcast to dashboard
// clients. A given event may be broadcast twice:
//  1. immediately after rule evaluation (Risk fields empty)
//  2. again after the async LLM scorer completes (same ID, Risk filled)
//
// Frontends keep a map by ID and update in place.
type Event struct {
	ID   uint64 `json:"id"`
	Time string `json:"time"`
	Type string `json:"type"`
	PID  uint32 `json:"pid"`
	UID  uint32 `json:"uid"`
	Comm string `json:"comm"`

	// path: exec / openat / unlinkat
	Path string `json:"path,omitempty"`

	// network: connect / socket
	Dest     string `json:"dest,omitempty"`
	Family   string `json:"family,omitempty"`
	SockType string `json:"socktype,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// Rule engine annotations (filled after match)
	Rule     string   `json:"rule,omitempty"`
	Action   Action   `json:"action,omitempty"`
	Severity Severity `json:"severity,omitempty"`
	Blocked  bool     `json:"blocked,omitempty"`

	// LLM scoring (filled asynchronously by llm.go)
	Risk         int    `json:"risk,omitempty"`
	RiskCategory string `json:"risk_category,omitempty"`
	RiskReason   string `json:"risk_reason,omitempty"`
}

// Don't kill these processes even if a rule says so. PID 1 must never die.
// The daemon's own PID is added at startup.
var killSafeguard = map[int]bool{
	1: true,
}

// Monotonic event ID counter. Atomic-friendly: only one writer (event loop).
var nextEventID uint64

// main is laid out in three logical phases:
//
//  1. Parse flags + decide which mode to run:
//     - eval mode (-eval <file>): no eBPF, runs scenarios against LLM
//     agent, exits with pass-rate-based exit code.
//     - normal mode: eBPF + dashboard + (optional) LLM + (optional)
//     persistent archive.
//
//  2. Wire components: rules, dashboard, archive, LLM scorer.
//     Each is optional via flag; their nil-safety is what keeps the
//     event loop simple in phase 3.
//
//  3. Main event loop: ringbuf.Read → decode → rule match → action →
//     broadcast → history.Add → archive.Record → LLM.Submit.
//     Order matters: history is updated BEFORE LLM submit, so the
//     agent's recent_events_for_pid tool sees the triggering event
//     in its own history (1-event memory).
func main() {
	var (
		verbose       bool
		rulesPath     string
		dryRun        bool
		wsListen      string
		llmEnabled    bool
		llmModel      string
		archivePath   string
		evalScenarios string
		evalPrompts   string
	)
	flag.BoolVar(&verbose, "v", false, "verbose logging to stderr")
	flag.StringVar(&rulesPath, "rules", "rules.yaml", "path to rules YAML file")
	flag.BoolVar(&dryRun, "dry-run", false, "never kill, only log what would have been killed")
	flag.StringVar(&wsListen, "ws-listen", ":8090", "dashboard HTTP listen address (empty = disabled)")
	flag.BoolVar(&llmEnabled, "llm", false, "enable LLM risk scoring (requires ANTHROPIC_API_KEY)")
	flag.StringVar(&llmModel, "llm-model", defaultModel, "Claude model to use for risk scoring")
	flag.StringVar(&archivePath, "archive", "", "SQLite file path for persistent alert archive (enables get_pid_history tool); empty = disabled")
	flag.StringVar(&evalScenarios, "eval", "", "run eval scenarios from this YAML file and exit (requires ANTHROPIC_API_KEY; skips eBPF setup)")
	flag.StringVar(&evalPrompts, "eval-prompts", "", "with -eval: A/B test multiple prompt variants from this YAML file")
	flag.Parse()

	// Eval mode is a short-circuit: load scenarios, run them against
	// the LLM investigator, print aggregate metrics, then exit. Skips
	// eBPF setup and dashboard so it can run anywhere with network access.
	if evalScenarios != "" {
		runEvalMode(evalScenarios, evalPrompts, llmModel)
		return
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

	// Never kill ourselves.
	killSafeguard[os.Getpid()] = true

	rules, err := LoadRules(rulesPath)
	if err != nil {
		log.Printf("loading rules from %s: %v — running with empty ruleset", rulesPath, err)
		rules = &RuleSet{}
	} else {
		fmt.Fprintf(os.Stderr, "agent-shield: loaded %d rules from %s\n", len(rules.Rules), rulesPath)
	}
	if dryRun {
		fmt.Fprintln(os.Stderr, "agent-shield: DRY RUN — block actions will not actually kill")
	}

	var dash *Dashboard
	if wsListen != "" {
		dash = NewDashboard()
		go func() {
			if err := dash.Serve(wsListen); err != nil {
				log.Printf("dashboard server: %v", err)
			}
		}()
		fmt.Fprintf(os.Stderr, "agent-shield: dashboard at http://localhost%s\n", wsListen)
	}

	enc := json.NewEncoder(os.Stdout)

	// History buffer feeds the LLM investigator's tools; populated by
	// the main event loop below regardless of whether LLM is enabled.
	history := NewEventHistory(10_000)

	// Optional persistent alert archive (SQLite). Survives restarts;
	// gives the investigator agent the get_pid_history tool.
	var archive *AlertArchive
	if archivePath != "" {
		a, err := OpenAlertArchive(archivePath)
		if err != nil {
			log.Printf("alert archive disabled: %v", err)
		} else {
			archive = a
			defer archive.Close()
			fmt.Fprintf(os.Stderr, "agent-shield: alert archive open at %s\n", archivePath)
		}
	}

	// Optional LLM investigator agent (off by default — needs API key).
	var llm *LLMScorer
	if llmEnabled {
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			fmt.Fprintln(os.Stderr, "agent-shield: -llm set but ANTHROPIC_API_KEY env is empty — disabling LLM scoring")
		} else {
			llm = NewLLMScorer(apiKey, llmModel, dash, history, 256, enc).WithArchive(archive)
			llm.Start(4)
			fmt.Fprintf(os.Stderr, "agent-shield: LLM investigator agent enabled (%s)\n", llmModel)
		}
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attach execve: %v", err)
	}
	defer tpExec.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		log.Fatalf("attach openat: %v", err)
	}
	defer tpOpen.Close()

	tpUnlink, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.HandleUnlinkat, nil)
	if err != nil {
		log.Fatalf("attach unlinkat: %v", err)
	}
	defer tpUnlink.Close()

	tpConn, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		log.Fatalf("attach connect: %v", err)
	}
	defer tpConn.Close()

	tpSock, err := link.Tracepoint("syscalls", "sys_enter_socket", objs.HandleSocket, nil)
	if err != nil {
		log.Fatalf("attach socket: %v", err)
	}
	defer tpSock.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	go func() {
		<-stopper
		if verbose {
			log.Println("received signal, shutting down")
		}
		_ = rd.Close()
	}()

	fmt.Fprintln(os.Stderr, "agent-shield: 5 probes attached (execve/openat/unlinkat/connect/socket)")
	fmt.Fprintln(os.Stderr, "streaming JSON events on stdout (Ctrl-C to stop)")

	var raw bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}

		evt := decode(raw)
		nextEventID++
		evt.ID = nextEventID

		// Run through the rule engine.
		if matched := rules.Find(&evt); matched != nil {
			evt.Rule = matched.Name
			evt.Action = matched.Action
			evt.Severity = matched.Severity

			if matched.Action == ActionBlock && !dryRun {
				evt.Blocked = killPID(int(evt.PID))
			}
		}

		// `log` action (or no match) just emits; `alert` is identical from the
		// daemon's perspective (downstream tooling colors by severity); `block`
		// has already done its kill.
		if err := enc.Encode(evt); err != nil {
			log.Printf("encoding event: %v", err)
		}

		// Always feed the history buffer; the LLM agent's tools read from it.
		history.Add(evt)

		// Persist matched events to the archive (if configured).
		if archive != nil && evt.Rule != "" {
			if err := archive.Record(&evt); err != nil {
				log.Printf("archive: %v", err)
			}
		}

		if dash != nil {
			dash.Broadcast(&evt)
		}

		// Submit interesting events (severity ≥ medium) for the async
		// investigator agent.
		if llm != nil && shouldScore(&evt) {
			llm.Submit(evt)
		}
	}
}

// runEvalMode is the entrypoint for `agent-shield -eval ...`. It loads
// scenarios from YAML, runs each through the investigator agent, and
// prints aggregate metrics. Exit code 0 iff every scenario passed.
//
// If promptsPath is non-empty, this runs an A/B sweep across the
// listed prompt variants instead of the single default prompt.
func runEvalMode(scenariosPath, promptsPath, model string) {
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "agent-shield: -eval requires ANTHROPIC_API_KEY")
		os.Exit(2)
	}

	scenarios, err := LoadEvalScenarios(scenariosPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent-shield: %v\n", err)
		os.Exit(2)
	}
	if len(scenarios) == 0 {
		fmt.Fprintln(os.Stderr, "agent-shield: no scenarios in file")
		os.Exit(2)
	}

	hist := NewEventHistory(10_000)
	ctx := context.Background()

	if promptsPath != "" {
		variants, err := LoadPromptVariants(promptsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent-shield: %v\n", err)
			os.Exit(2)
		}
		makeScorer := func(prompt string) *LLMScorer {
			return NewLLMScorer(apiKey, model, nil, hist, 1, nil).WithSystemPrompt(prompt)
		}
		summaries := RunABEval(ctx, makeScorer, hist, variants, scenarios)
		// Exit success iff at least one variant passed every scenario.
		anyPerfect := false
		for _, s := range summaries {
			if s.Passed == s.Total {
				anyPerfect = true
				break
			}
		}
		if !anyPerfect {
			os.Exit(1)
		}
		return
	}

	llm := NewLLMScorer(apiKey, model, nil, hist, 1, nil)
	results := RunEvals(ctx, llm, hist, scenarios)
	PrintEvalSummary(results)

	if !EvalsAllPassed(results) {
		os.Exit(1)
	}
}

// shouldScore decides whether an event is worth spending an LLM call on.
// Skip log-only / info-severity / unmatched events to keep cost down.
func shouldScore(evt *Event) bool {
	if evt.Rule == "" {
		return false
	}
	switch evt.Severity {
	case SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// killPID sends SIGKILL to the target unless it's in the safeguard list.
// Returns true if kill was attempted and succeeded.
func killPID(pid int) bool {
	if killSafeguard[pid] {
		return false
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		// Process may have already exited — that's fine.
		return false
	}
	return true
}

// decode turns a raw BPF event into the JSON-shaped Event.
func decode(raw bpfEvent) Event {
	evt := Event{
		Time: time.Now().UTC().Format(time.RFC3339Nano),
		PID:  raw.Pid,
		UID:  raw.Uid,
		Comm: unix.ByteSliceToString(raw.Comm[:]),
	}

	switch raw.EventType {
	case EventExec:
		evt.Type = "exec"
		evt.Path = unix.ByteSliceToString(raw.Path[:])
	case EventOpenat:
		evt.Type = "openat"
		evt.Path = unix.ByteSliceToString(raw.Path[:])
	case EventUnlinkat:
		evt.Type = "unlinkat"
		evt.Path = unix.ByteSliceToString(raw.Path[:])
	case EventConnect:
		evt.Type = "connect"
		evt.Family = familyName(raw.SockFamily)
		if raw.SockFamily == unix.AF_INET {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, raw.DaddrV4)
			port := ntohs(raw.Dport)
			evt.Dest = fmt.Sprintf("%s:%d", ip.String(), port)
		}
	case EventSocket:
		evt.Type = "socket"
		evt.Family = familyName(raw.SockFamily)
		evt.SockType = sockTypeName(raw.SockType)
		evt.Protocol = protoName(raw.SockProtocol)
	default:
		evt.Type = fmt.Sprintf("unknown(%d)", raw.EventType)
	}
	return evt
}

// ntohs converts a network-byte-order u16 to host byte order.
func ntohs(n uint16) uint16 {
	return (n>>8)&0xff | (n&0xff)<<8
}

func familyName(f uint32) string {
	switch f {
	case unix.AF_INET:
		return "AF_INET"
	case unix.AF_INET6:
		return "AF_INET6"
	case unix.AF_UNIX:
		return "AF_UNIX"
	case unix.AF_NETLINK:
		return "AF_NETLINK"
	case unix.AF_PACKET:
		return "AF_PACKET"
	default:
		return fmt.Sprintf("AF(%d)", f)
	}
}

func sockTypeName(t uint32) string {
	switch t & 0xff {
	case unix.SOCK_STREAM:
		return "SOCK_STREAM"
	case unix.SOCK_DGRAM:
		return "SOCK_DGRAM"
	case unix.SOCK_RAW:
		return "SOCK_RAW"
	case unix.SOCK_SEQPACKET:
		return "SOCK_SEQPACKET"
	default:
		return fmt.Sprintf("SOCK(%d)", t&0xff)
	}
}

func protoName(p uint32) string {
	switch p {
	case 0:
		return "default"
	case unix.IPPROTO_TCP:
		return "TCP"
	case unix.IPPROTO_UDP:
		return "UDP"
	case unix.IPPROTO_ICMP:
		return "ICMP"
	default:
		return fmt.Sprintf("proto(%d)", p)
	}
}
