//go:build ignore

// agent-shield eBPF probe — Week 1 MVP
//
// Attaches to the execve syscall tracepoint and emits a structured event
// (pid / uid / comm / filename) into a ring buffer for the userspace daemon.
//
// Tracepoint is preferred over kprobe because:
//   - stable across kernel versions
//   - the args layout is documented in /sys/kernel/tracing/events/.../format

#include "common.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define MAX_FILENAME_LEN 256

char __license[] SEC("license") = "Dual MIT/GPL";

// Event written to the ring buffer. Field order/sizes must match the Go
// side (bpf2go generates `bpfEvent` from this struct).
struct event {
	u32 pid;
	u32 uid;
	u8 comm[TASK_COMM_LEN];
	u8 filename[MAX_FILENAME_LEN];
};

// Ring buffer map. 16 MiB is plenty for MVP scale.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

// Tracepoint context layout for sys_enter_* family.
// See: /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
struct trace_event_raw_sys_enter {
	unsigned long long pad;
	long syscall_nr;
	long args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
	struct event *e;

	// Reserve space in the ring buffer. NULL means the buffer is full —
	// we drop the event rather than block.
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	u64 id = bpf_get_current_pid_tgid();
	e->pid = id >> 32;
	e->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	bpf_get_current_comm(&e->comm, TASK_COMM_LEN);

	// args[0] of execve is `const char *filename`.
	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->filename, MAX_FILENAME_LEN, filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
