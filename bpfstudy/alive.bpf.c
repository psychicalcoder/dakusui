// SPDX-License-Identifier: GPL-2.0
/*
 * Spike 3, part 2: can a hook tell that its loader is gone?
 *
 * A flagged task may open files only while the loader lives. The hook looks
 * the loader up by pid, checks that it is the same task (start time), and
 * that it is not exiting. If the loader is gone, exiting, or replaced by a
 * new task with the same pid, the open is denied.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EACCES 13
#define PF_EXITING 0x00000004

extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

struct helper_info {
	__s32 pid;   /* set by the loader */
	__u32 pad;
	__u64 start; /* learned from the loader's own first open */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct helper_info);
} helper SEC(".maps");

/* How often each state was seen: alive, gone, exiting, pid reused. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} confined SEC(".maps");

enum { ALIVE, GONE, EXITING, REUSED };

static __always_inline __u32 helper_state(struct helper_info *h)
{
	struct task_struct *t;
	__u32 st = ALIVE;

	if (!h->pid || !h->start)
		return GONE;
	t = bpf_task_from_pid(h->pid);
	if (!t)
		return GONE;
	if (t->start_time != h->start)
		st = REUSED;
	else if (t->flags & PF_EXITING)
		st = EXITING;
	bpf_task_release(t);
	return st;
}

SEC("lsm/file_open")
int BPF_PROG(a_file_open, struct file *file)
{
	struct task_struct *cur = bpf_get_current_task_btf();
	__u32 zero = 0, st;
	struct helper_info *h = bpf_map_lookup_elem(&helper, &zero);
	__u64 *n;

	if (!h)
		return 0;
	/* The loader opens a file once it has set its pid; learn its start. */
	if (h->pid && !h->start && cur->tgid == h->pid)
		h->start = cur->group_leader->start_time;
	if (!bpf_task_storage_get(&confined, cur, 0, 0))
		return 0;
	st = helper_state(h);
	n = bpf_map_lookup_elem(&seen, &st);
	if (n)
		__sync_fetch_and_add(n, 1);
	return st == ALIVE ? 0 : -EACCES;
}

SEC("lsm/task_alloc")
int BPF_PROG(a_inherit, struct task_struct *task, unsigned long clone_flags)
{
	if (bpf_task_storage_get(&confined, bpf_get_current_task_btf(), 0, 0)) {
		__u32 *v = bpf_task_storage_get(&confined, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);

		if (v)
			*v = 1;
	}
	return 0;
}
