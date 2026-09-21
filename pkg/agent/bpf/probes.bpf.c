// Production BuildLens BPF probes with in-kernel sensitive path filtering.
//
// Filters out >99.9% of harmless openat calls directly in the kernel before
// reserving ring buffer space or waking userspace.
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} drop_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // tid
	__type(value, __u64); // struct sock *
} connect_socks SEC(".maps");

static __always_inline void record_drop(__u32 reason)
{
	__u64 *cnt = bpf_map_lookup_elem(&drop_stats, &reason);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline void fill_common(struct event *e, __u8 kind)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	__builtin_memset(e, 0, sizeof(*e));
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// BPF kernel-side filter: drop 99.9% of harmless openat calls in CI (node_modules,
// shared libraries, stats) before reserving ring buffer space or waking userspace.
static __always_inline int is_sensitive_path(const char *p, int len)
{
	#pragma unroll
	for (int i = 0; i < 96; i++) {
		if (i >= len)
			break;
		if (p[i] == '.') {
			// .env
			if (p[i+1] == 'e' && p[i+2] == 'n' && p[i+3] == 'v')
				return 1;
			// .npmrc
			if (p[i+1] == 'n' && p[i+2] == 'p' && p[i+3] == 'm' && p[i+4] == 'r' && p[i+5] == 'c')
				return 1;
			// .yarnrc
			if (p[i+1] == 'y' && p[i+2] == 'a' && p[i+3] == 'r' && p[i+4] == 'n' && p[i+5] == 'r' && p[i+6] == 'c')
				return 1;
			// .netrc
			if (p[i+1] == 'n' && p[i+2] == 'e' && p[i+3] == 't' && p[i+4] == 'r' && p[i+5] == 'c')
				return 1;
			// .ssh/id_
			if (p[i+1] == 's' && p[i+2] == 's' && p[i+3] == 'h' && p[i+4] == '/' && p[i+5] == 'i' && p[i+6] == 'd' && p[i+7] == '_')
				return 1;
			// .aws/credentials
			if (p[i+1] == 'a' && p[i+2] == 'w' && p[i+3] == 's' && p[i+4] == '/' && p[i+5] == 'c' && p[i+6] == 'r' && p[i+7] == 'e' && p[i+8] == 'd')
				return 1;
			// .git-credentials
			if (p[i+1] == 'g' && p[i+2] == 'i' && p[i+3] == 't' && p[i+4] == '-' && p[i+5] == 'c' && p[i+6] == 'r' && p[i+7] == 'e' && p[i+8] == 'd')
				return 1;
		}
		// /etc/shadow
		if (p[i] == '/' && p[i+1] == 'e' && p[i+2] == 't' && p[i+3] == 'c' && p[i+4] == '/' && p[i+5] == 's' && p[i+6] == 'h' && p[i+7] == 'a' && p[i+8] == 'd')
			return 1;
	}
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_drop(0);
		return 0;
	}

	fill_common(e, EVT_EXEC);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	const char *filename = (const char *)ctx->args[1];
	char temp_path[MAX_PATH_LEN];

	int len = bpf_probe_read_user_str(temp_path, sizeof(temp_path), filename);
	if (len <= 0)
		return 0;

	// Kernel-side filter: if not a sensitive pattern, exit immediately
	if (!is_sensitive_path(temp_path, len))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_drop(0);
		return 0;
	}

	fill_common(e, EVT_OPEN);
	__builtin_memcpy(e->path, temp_path, sizeof(e->path));
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
	if (!e) {
		record_drop(0);
		return 0;
	}

	fill_common(e, EVT_CONNECT);
	BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
