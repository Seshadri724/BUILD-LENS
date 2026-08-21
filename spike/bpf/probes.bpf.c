// Phase 0 spike — M0.1/M0.3 (exec) and M0.5 (open + connect, the
// detection-proof probes). Answers whether the read-then-egress
// correlation BuildLens is built around is actually visible in raw
// kernel events, on a GitHub-hosted runner. This file is throwaway per
// ROADMAP.md Phase 0 and is expected to be deleted or rewritten once
// Phase 1 starts for real — no kernel-side path filtering, no DNS/SNI,
// no policy, just enough signal to prove the mechanism.
//
// vmlinux.h is NOT committed — it's generated at build time from the
// runner's own BTF so struct layouts always match the kernel under test.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  128

enum event_kind {
	EVT_EXEC    = 1,
	EVT_OPEN    = 2,
	EVT_CONNECT = 3,
};

// One tagged struct for all three event kinds, kept simple for a spike —
// real per-kind structs come in Phase 1. packed so the byte layout is
// deterministic and matches the Go decoder without guessing at compiler
// alignment/padding rules.
struct event {
	__u8  kind;
	__u32 pid;
	__u32 ppid;
	char  comm[TASK_COMM_LEN];
	char  path[MAX_PATH_LEN]; // EVT_OPEN only
	__u8  daddr[4];           // EVT_CONNECT only, raw network-order octets
	__u8  dport[2];           // EVT_CONNECT only, raw network-order bytes
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// tcp_v4_connect entry->return correlation: the kprobe stashes the sock*,
// the kretprobe reads the now-populated destination fields off it. This
// is the standard pattern (see libbpf-tools tcpconnect) — dest fields are
// set during connect() regardless of blocking/non-blocking or whether the
// handshake ultimately completes, so we don't gate on the return code.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // tid
	__type(value, __u64); // struct sock *
} connect_socks SEC(".maps");

static __always_inline void fill_common(struct event *e, __u8 kind)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVT_EXEC);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVT_OPEN);
	bpf_probe_read_user_str(&e->path, sizeof(e->path), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_connect_entry, struct sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;

	bpf_map_update_elem(&connect_socks, &tid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcp_connect_return, int ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&connect_socks, &tid);

	if (!skp)
		return 0;
	bpf_map_delete_elem(&connect_socks, &tid);

	struct sock *sk = (struct sock *)(*skp);
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVT_CONNECT);
	BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
