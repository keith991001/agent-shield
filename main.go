//go:build linux

// agent-shield — Week 2 daemon.
//
// Loads the eBPF probes defined in bpf/probe.c, attaches them to 5 syscall
// tracepoints, runs each event through a YAML rule engine, and either
// logs / alerts / kills the offending process. Events are emitted as
// structured JSON on stdout.
//
//go:generate go tool bpf2go -tags linux -target native bpf bpf/probe.c -- -I./headers
package main

import (
	"bytes"
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

// Event is the JSON shape emitted on stdout.
type Event struct {
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
}

// Don't kill these processes even if a rule says so. PID 1 must never die.
// The daemon's own PID is added at startup.
var killSafeguard = map[int]bool{
	1: true,
}

func main() {
	var (
		verbose   bool
		rulesPath string
		dryRun    bool
	)
	flag.BoolVar(&verbose, "v", false, "verbose logging to stderr")
	flag.StringVar(&rulesPath, "rules", "rules.yaml", "path to rules YAML file")
	flag.BoolVar(&dryRun, "dry-run", false, "never kill, only log what would have been killed")
	flag.Parse()

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
	enc := json.NewEncoder(os.Stdout)
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
