//go:build ignore

// agent-shield eBPF probes — Week 2: 5 syscalls.
//
// Attaches to 5 sys_enter_* tracepoints and emits typed events into a
// single ring buffer. The userspace daemon discriminates on event_type.
//
// Tracepoint over kprobe: stable across kernel versions, well-documented
// args layout under /sys/kernel/tracing/events/syscalls/<name>/format.

#include "common.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define MAX_PATH_LEN 256

char __license[] SEC("license") = "Dual MIT/GPL";

// Discriminator for the union of syscall events. Keep in sync with Go side.
enum event_type {
	EVENT_EXEC     = 1,
	EVENT_OPENAT   = 2,
	EVENT_UNLINKAT = 3,
	EVENT_CONNECT  = 4,
	EVENT_SOCKET   = 5,
};

// Flat event struct — wastes a bit of memory for unused fields but keeps
// the BPF verifier happy (no union access patterns) and Go decoding
// trivial.
struct event {
	u32 event_type;
	u32 pid;
	u32 uid;
	u8  comm[TASK_COMM_LEN];

	// path: filename / pathname for exec / openat / unlinkat
	u8  path[MAX_PATH_LEN];

	// net fields for connect / socket
	u32 sock_family;    // AF_INET=2, AF_INET6=10, ...
	u32 sock_type;      // SOCK_STREAM=1, SOCK_DGRAM=2, ...
	u32 sock_protocol;  // IPPROTO_TCP=6, ...
	u32 daddr_v4;       // IPv4 destination, network byte order
	u16 dport;          // destination port, network byte order
	u16 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
	__type(value, struct event);
} events SEC(".maps");

// Tracepoint context layout for sys_enter_* family.
struct trace_event_raw_sys_enter {
	unsigned long long pad;
	long syscall_nr;
	long args[6];
};

// Minimal sockaddr_in for parsing IPv4 connect() destinations.
struct sockaddr_in {
	u16 sin_family;
	u16 sin_port;
	u32 sin_addr;
};

// Reserve an event and fill in the common fields (pid/uid/comm/type).
// Zero-initialized so unused payload bytes are deterministic.
static __always_inline struct event *make_event(u32 type) {
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->event_type = type;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	bpf_get_current_comm(&e->comm, TASK_COMM_LEN);
	return e;
}

// execve(filename, argv, envp) — filename is args[0]
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
	struct event *e = make_event(EVENT_EXEC);
	if (!e) return 0;

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&e->path, MAX_PATH_LEN, filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// openat(dfd, filename, flags, mode) — filename is args[1]
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
	struct event *e = make_event(EVENT_OPENAT);
	if (!e) return 0;

	const char *filename = (const char *)ctx->args[1];
	bpf_probe_read_user_str(&e->path, MAX_PATH_LEN, filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// unlinkat(dfd, pathname, flag) — pathname is args[1]
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
	struct event *e = make_event(EVENT_UNLINKAT);
	if (!e) return 0;

	const char *pathname = (const char *)ctx->args[1];
	bpf_probe_read_user_str(&e->path, MAX_PATH_LEN, pathname);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// connect(fd, addr, addrlen) — addr is args[1]
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
	struct event *e = make_event(EVENT_CONNECT);
	if (!e) return 0;

	void *addr = (void *)ctx->args[1];
	struct sockaddr_in sa;
	bpf_probe_read_user(&sa, sizeof(sa), addr);

	e->sock_family = sa.sin_family;
	e->dport       = sa.sin_port;
	e->daddr_v4    = sa.sin_addr;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// socket(family, type, protocol) — args[0..2]
SEC("tracepoint/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx) {
	struct event *e = make_event(EVENT_SOCKET);
	if (!e) return 0;

	e->sock_family   = (u32)ctx->args[0];
	e->sock_type     = (u32)ctx->args[1];
	e->sock_protocol = (u32)ctx->args[2];

	bpf_ringbuf_submit(e, 0);
	return 0;
}
