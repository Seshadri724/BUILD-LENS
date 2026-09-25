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
#define AF_INET       2
#define AF_INET6      10

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
	__u8  daddr[16];          // EVT_CONNECT only, raw network-order octets (IPv4 uses first 4)
	__u8  dport[2];           // EVT_CONNECT only, raw network-order bytes
	__u8  family;             // EVT_CONNECT only, AF_INET or AF_INET6
} __attribute__((packed));

// Per-(process, destination) bytes actually accepted by tcp_sendmsg.
// Userspace dumps this map once at shutdown — no ring buffer event per send.
struct flow_key {
	__u32 pid;
	__u8  daddr[16];
	__u8  dport[2];
	__u8  family;
	__u8  pad;
};

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);   // tid
	__type(value, __u64); // struct sock *
} send_socks SEC(".maps");

// ponytail: fixed-size map; flows past 16384 per run are silently not counted.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, __u64); // bytes sent
} send_bytes SEC(".maps");

struct open_path {
	char path[MAX_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); // tid
	__type(value, struct open_path);
} pending_opens SEC(".maps");

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
	// /proc/<pid>[/task/<tid>]/mem or /environ: runner memory scraping (tj-actions).
	// op.path is zero-filled, so a 0 after the suffix means end of string.
	if (p[0] == '/' && p[1] == 'p' && p[2] == 'r' && p[3] == 'o' && p[4] == 'c' && p[5] == '/') {
		#pragma unroll
		for (int i = 6; i < 48; i++) {
			if (p[i] != '/')
				continue;
			if (p[i+1] == 'm' && p[i+2] == 'e' && p[i+3] == 'm' && p[i+4] == 0)
				return 1;
			if (p[i+1] == 'e' && p[i+2] == 'n' && p[i+3] == 'v' && p[i+4] == 'i' && p[i+5] == 'r' && p[i+6] == 'o' && p[i+7] == 'n' && p[i+8] == 0)
				return 1;
		}
		return 0;
	}

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
			// .git/config (actions/checkout persists GITHUB_TOKEN here) and .gitconfig
			if (p[i+1] == 'g' && p[i+2] == 'i' && p[i+3] == 't' &&
			    ((p[i+4] == '/' && p[i+5] == 'c' && p[i+6] == 'o' && p[i+7] == 'n' && p[i+8] == 'f') ||
			     (p[i+4] == 'c' && p[i+5] == 'o' && p[i+6] == 'n' && p[i+7] == 'f')))
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
	struct open_path op = {};

	int len = bpf_probe_read_user_str(op.path, sizeof(op.path), filename);
	if (len <= 0)
		return 0;

	// Kernel-side filter: if not a sensitive pattern, exit immediately
	if (!is_sensitive_path(op.path, len))
		return 0;

	// Emitted from sys_exit_openat only if the open succeeded.
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&pending_opens, &tid, &op, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct open_path *op = bpf_map_lookup_elem(&pending_opens, &tid);

	if (!op)
		return 0;
	if (ctx->ret < 0) {
		bpf_map_delete_elem(&pending_opens, &tid);
		return 0;
	}

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_drop(0);
		bpf_map_delete_elem(&pending_opens, &tid);
		return 0;
	}

	fill_common(e, EVT_OPEN);
	__builtin_memcpy(e->path, op->path, sizeof(e->path));
	bpf_map_delete_elem(&pending_opens, &tid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Reads family, destination address and port from a connected/connecting sock.
// BPF_CORE_READ_INTO sizes the read by sizeof(*dst), so casts pick the width.
static __always_inline __u8 read_dest(struct sock *sk, __u8 *daddr, __u8 *dport)
{
	__u8 family = BPF_CORE_READ(sk, __sk_common.skc_family);

	if (family == AF_INET6)
		BPF_CORE_READ_INTO((struct in6_addr *)daddr, sk, __sk_common.skc_v6_daddr);
	else
		BPF_CORE_READ_INTO((__u32 *)daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO((__u16 *)dport, sk, __sk_common.skc_dport);
	return family;
}

static __always_inline int connect_entry(struct sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;

	bpf_map_update_elem(&connect_socks, &tid, &skp, BPF_ANY);
	return 0;
}

static __always_inline int connect_return(int ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&connect_socks, &tid);

	if (!skp)
		return 0;
	struct sock *sk = (struct sock *)(*skp);
	bpf_map_delete_elem(&connect_socks, &tid);
	if (ret != 0)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		record_drop(0);
		return 0;
	}

	fill_common(e, EVT_CONNECT);
	e->family = read_dest(sk, e->daddr, e->dport);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_connect_entry, struct sock *sk)
{
	return connect_entry(sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(handle_tcp_connect_return, int ret)
{
	return connect_return(ret);
}

// tcp_v6_connect calls tcp_v4_connect for v4-mapped addresses; the inner
// probe pair consumes the map entry, so each connect is emitted once.
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(handle_tcp6_connect_entry, struct sock *sk)
{
	return connect_entry(sk);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(handle_tcp6_connect_return, int ret)
{
	return connect_return(ret);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(handle_tcp_sendmsg_entry, struct sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 skp = (__u64)sk;

	bpf_map_update_elem(&send_socks, &tid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(handle_tcp_sendmsg_return, int ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	__u64 *skp = bpf_map_lookup_elem(&send_socks, &tid);

	if (!skp)
		return 0;
	struct sock *sk = (struct sock *)(*skp);
	bpf_map_delete_elem(&send_socks, &tid);
	if (ret <= 0)
		return 0;

	struct flow_key key = {};
	key.pid = bpf_get_current_pid_tgid() >> 32;
	key.family = read_dest(sk, key.daddr, key.dport);

	__u64 *total = bpf_map_lookup_elem(&send_bytes, &key);
	if (total) {
		__sync_fetch_and_add(total, (__u64)ret);
	} else {
		__u64 init = (__u64)ret;
		// Lost the insert race to another thread: add to its entry instead.
		if (bpf_map_update_elem(&send_bytes, &key, &init, BPF_NOEXIST) != 0) {
			total = bpf_map_lookup_elem(&send_bytes, &key);
			if (total)
				__sync_fetch_and_add(total, (__u64)ret);
		}
	}
	return 0;
}
