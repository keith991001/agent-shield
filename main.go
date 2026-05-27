//go:build linux

// agent-shield — Week 1 MVP daemon.
//
// Loads the eBPF probe defined in bpf/probe.c, attaches it to the
// sys_enter_execve tracepoint, and prints structured JSON events read
// from the BPF ring buffer to stdout.
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Event is the JSON shape emitted on stdout. Keep it stable — downstream
// consumers (rule engine, dashboard) will parse this.
type Event struct {
	Time     string `json:"time"`
	PID      uint32 `json:"pid"`
	UID      uint32 `json:"uid"`
	Comm     string `json:"comm"`
	Filename string `json:"filename"`
}

func main() {
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "verbose logging to stderr")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

	// Trap SIGINT / SIGTERM so we can shut down cleanly and detach the probe.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// eBPF needs to lock memory for the maps it creates. RLIMIT_MEMLOCK
	// is often too low by default; raise it.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	// Load the compiled BPF objects (programs + maps) into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the execve syscall tracepoint.
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// Open the ring buffer reader.
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

	fmt.Fprintln(os.Stderr, "agent-shield: probe attached, streaming events as JSON on stdout (Ctrl-C to stop)")

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

		evt := Event{
			Time:     time.Now().UTC().Format(time.RFC3339Nano),
			PID:      raw.Pid,
			UID:      raw.Uid,
			Comm:     unix.ByteSliceToString(raw.Comm[:]),
			Filename: unix.ByteSliceToString(raw.Filename[:]),
		}
		if err := enc.Encode(evt); err != nil {
			log.Printf("encoding event: %v", err)
		}
	}
}
