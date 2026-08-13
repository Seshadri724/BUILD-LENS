// Phase 0 spike — M0.1/M0.3: does a trivial CO-RE program load and emit
// events on a GitHub-hosted runner? Nothing more. This file is throwaway
// per ROADMAP.md Phase 0 and is expected to be deleted or rewritten once
// Phase 1 starts for real.
//
// vmlinux.h is NOT committed — it's generated at build time from the
// runner's own BTF (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`)
// so the struct layouts always match the kernel actually being tested.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct exec_event {
	__u32 pid;
	__u32 ppid;
	char comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct exec_event *e;
	struct task_struct *task;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
