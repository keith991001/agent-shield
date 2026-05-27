//go:build linux

// agent-shield — Week 2 daemon.
//
// Loads the eBPF probes defined in bpf/probe.c, attaches them to 5
// syscall tracepoints, and prints structured JSON events from the BPF
// ring buffer to stdout.
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

// Event is the JSON shape emitted on stdout. omitempty keeps each event
// type's output focused on the fields that matter for it.
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
}

func main() {
	var verbose bool
	flag.BoolVar(&verbose, "v", false, "verbose logging to stderr")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stderr)

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

	// Attach each probe to its tracepoint. All five share the same ring
	// buffer, distinguished by the event_type field.
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
		if err := enc.Encode(evt); err != nil {
			log.Printf("encoding event: %v", err)
		}
	}
}

// decode turns a raw BPF event into the JSON-shaped Event, populating
// only the fields relevant to its type.
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
		// daddr_v4 / dport are in network byte order. Only meaningful for AF_INET.
		if raw.SockFamily == unix.AF_INET {
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, raw.DaddrV4) // kernel writes little-endian to map; addr bytes preserved
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

// ntohs converts a network-byte-order u16 (as stored in the BPF event)
// to host byte order. On little-endian hosts this is just a byte swap.
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
	// Mask out SOCK_NONBLOCK / SOCK_CLOEXEC flags.
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
