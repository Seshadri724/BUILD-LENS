// Enforce-audit cgroup hook (Phase 1 skeleton).
//
// Separate BPF object from probes.bpf.c ON PURPOSE: it is loaded only when
// recording with -enforce audit, so a verifier or attach failure here can
// never break the observe path. Fail-open is structural, not just handled.
//
// Semantics v1: every TCP/UDP connect outside the allowlist emits
// EVT_WOULDBLOCK and is ALLOWED. The verdict is hardcoded — returning
// anything but 1 here would break builds, and deny verdicts wait for the
// Phase 2 CP-2.3 gate (500 runs, zero wrongful blocks). The allowlist starts
// empty (everything is observed); populating it from policy.yml with live
// DNS refresh is Phase 2.
//
// Layout contract: struct enforce_event is __attribute__((packed)) and the Go
// decoder reads it with encoding/binary (which ignores alignment padding), so
// field ORDER and SIZES must match pkg/agent/enforce_linux.go exactly.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define AF_INET       2
#define AF_INET6      10

enum enforce_kind {
	EVT_WOULDBLOCK = 4,
};

struct enforce_event {
	__u8  kind;
	__u32 pid;
	__u32 ppid;
	char  comm[TASK_COMM_LEN];
	__u8  daddr[16]; // raw network-order octets (IPv4 uses first 4)
	__u8  family;    // AF_INET or AF_INET6 (no port: the trie is IP-based)
} __attribute__((packed));

struct lpm_key {
	__u32 prefixlen;
	__u8  data[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} egress_allowlist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} enforce_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} enforce_drop_stats SEC(".maps");

static __always_inline void record_drop(__u32 reason)
{
	__u64 *cnt = bpf_map_lookup_elem(&enforce_drop_stats, &reason);
	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline int audit_connect(struct bpf_sock_addr *ctx)
{
	__u8 family = (__u8)ctx->family;
	if (family != AF_INET && family != AF_INET6)
		return 1;

	// The trie is longest-prefix: v4 looks up the first 4 bytes (/32),
	// v6 the full address (/128). Key stack-zeroed so trailing bytes
	// cannot leak into the lookup.
	struct lpm_key key = {};
	if (family == AF_INET6) {
		__u32 a = ctx->user_ip6[0];
		__u32 b = ctx->user_ip6[1];
		__u32 c = ctx->user_ip6[2];
		__u32 d = ctx->user_ip6[3];
		key.prefixlen = 128;
		((__u32 *)key.data)[0] = a;
		((__u32 *)key.data)[1] = b;
		((__u32 *)key.data)[2] = c;
		((__u32 *)key.data)[3] = d;
	} else {
		__u32 ip4 = ctx->user_ip4;
		key.prefixlen = 32;
		((__u32 *)key.data)[0] = ip4;
	}
	if (bpf_map_lookup_elem(&egress_allowlist, &key))
		return 1;

	struct enforce_event *e = bpf_ringbuf_reserve(&enforce_events, sizeof(*e), 0);
	if (!e) {
		record_drop(0);
		return 1;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__builtin_memset(e, 0, sizeof(*e));
	e->kind = EVT_WOULDBLOCK;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	if (family == AF_INET6) {
		__u32 a = ctx->user_ip6[0];
		__u32 b = ctx->user_ip6[1];
		__u32 c = ctx->user_ip6[2];
		__u32 d = ctx->user_ip6[3];
		((__u32 *)e->daddr)[0] = a;
		((__u32 *)e->daddr)[1] = b;
		((__u32 *)e->daddr)[2] = c;
		((__u32 *)e->daddr)[3] = d;
	} else {
		__u32 ip4 = ctx->user_ip4;
		((__u32 *)e->daddr)[0] = ip4;
	}
	e->family = family;
	bpf_ringbuf_submit(e, 0);
	return 1;
}

SEC("cgroup/connect4")
int handle_cgroup_connect4(struct bpf_sock_addr *ctx)
{
	return audit_connect(ctx);
}

SEC("cgroup/connect6")
int handle_cgroup_connect6(struct bpf_sock_addr *ctx)
{
	return audit_connect(ctx);
}
