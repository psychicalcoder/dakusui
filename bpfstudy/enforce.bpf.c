// SPDX-License-Identifier: GPL-2.0
/*
 * Spike 2 for spec 0001: the real enforcer, in miniature.
 *
 * For a confined task, each hook builds the path by walking dentries
 * (ADR 0006), looks up every path prefix and the last name in the rule map,
 * keeps the match with the highest sequence number per access kind (last
 * match wins), and returns -EACCES unless every needed kind is allowed.
 * Anything that goes wrong while building the path denies (fail closed).
 *
 * The questions this answers: does the verifier accept it, how much does it
 * cost per open, and does it give the right verdicts?
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "enforce.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define EACCES 13
#define M_READ 0x1  /* FMODE_READ */
#define M_WRITE 0x2 /* FMODE_WRITE */

/* The task flag (ADR 0004). Userspace sets it with a pidfd key. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} confined SEC(".maps");

struct scratch {
	char comp[MAX_COMP][COMP_LEN]; /* path components, leaf first */
	struct rule_key key;
	struct denial d;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} denials SEC(".maps");

/*
 * One slot holds the current rules. Userspace builds a new inner map and
 * swaps it in, so a change is atomic. Until then the slot holds the empty
 * template, which denies everything.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct rule_key);
	__type(value, struct rule_val);
} inner_template SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__array(values, typeof(inner_template));
} rules SEC(".maps") = {
	.values = { &inner_template },
};

static __always_inline int is_confined(struct task_struct *t)
{
	return bpf_task_storage_get(&confined, t, 0, 0) != NULL;
}

static __always_inline struct scratch *get_scratch(void)
{
	return bpf_task_storage_get(&scratch_map, bpf_get_current_task_btf(), 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Turn a typed pointer into a plain integer the verifier will not track. */
static __always_inline __u64 launder(const void *ptr)
{
	__u64 out = 0;

	bpf_probe_read_kernel(&out, sizeof(out), &ptr);
	return out;
}

static __always_inline __u64 mnt_of(const struct path *p)
{
	struct vfsmount *vfs = BPF_CORE_READ(p, mnt);
	struct mount *mz = NULL;

	if (!vfs)
		return 0;
	return (__u64)vfs - bpf_core_field_offset(mz->mnt);
}

/* ---- walk: leaf to root, crossing mounts ---- */

struct walk_ctx {
	__u64 dentry;
	__u64 mnt;
	__u32 n;
	__u32 status;
	int done;
};

static __noinline long walk_step(__u32 idx, void *data)
{
	struct walk_ctx *c = data;
	struct dentry *dentry = (struct dentry *)c->dentry;
	struct mount *mnt = (struct mount *)c->mnt;
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
	struct scratch *s;
	const unsigned char *nm;
	__u32 nl;

	if (mnt) {
		struct dentry *mroot = BPF_CORE_READ(mnt, mnt.mnt_root);

		if (dentry == mroot) {
			struct mount *up = BPF_CORE_READ(mnt, mnt_parent);

			if (up == mnt) {
				c->done = 1;
				return 1;
			}
			c->dentry = (__u64)BPF_CORE_READ(mnt, mnt_mountpoint);
			c->mnt = (__u64)up;
			return 0;
		}
	}
	if (dentry == parent) {
		c->done = 1;
		return 1;
	}
	if (c->n >= MAX_COMP) {
		c->status = ST_DEEP;
		return 1;
	}
	nl = BPF_CORE_READ(dentry, d_name.len);
	if (nl >= COMP_LEN) {
		c->status = ST_LONGNAME;
		return 1;
	}
	s = get_scratch();
	if (!s) {
		c->status = ST_ERR;
		return 1;
	}
	nm = BPF_CORE_READ(dentry, d_name.name);
	if (bpf_probe_read_kernel_str(s->comp[c->n & (MAX_COMP - 1)], COMP_LEN,
				      nm) < 0) {
		c->status = ST_ERR;
		return 1;
	}
	c->n++;
	c->dentry = (__u64)parent;
	return 0;
}

/* ---- match: prefixes from the root down, then the last name ---- */

struct match_ctx {
	__u32 n;
	__u32 off;
	__u32 status;
	__u32 seq[2];
	__u32 eff[2];
};

static __always_inline void lookup_merge(struct scratch *s,
					 struct match_ctx *c)
{
	__u32 zero = 0;
	void *inner = bpf_map_lookup_elem(&rules, &zero);
	struct rule_val *v;

	if (!inner)
		return;
	v = bpf_map_lookup_elem(inner, &s->key);
	if (!v)
		return;
	if (v->seq[0] > c->seq[0]) {
		c->seq[0] = v->seq[0];
		c->eff[0] = v->effect[0];
	}
	if (v->seq[1] > c->seq[1]) {
		c->seq[1] = v->seq[1];
		c->eff[1] = v->effect[1];
	}
}

/* Append "/<name>" to the key, then look the prefix up. Components are stored
 * leaf first, so step idx takes component n - 1 - idx. */
static __noinline long match_step(__u32 idx, void *data)
{
	struct match_ctx *c = data;
	struct scratch *s = get_scratch();
	__u32 off = c->off;
	__u32 i;
	long n;

	if (!s) {
		c->status = ST_ERR;
		return 1;
	}
	/* Room for "/" plus a full component must remain in the key. */
	if (off > KEY_LEN - COMP_LEN - 2) {
		c->status = ST_LONGPATH;
		return 1;
	}
	i = (c->n - 1 - idx) & (MAX_COMP - 1);
	s->key.s[off] = '/';
	n = bpf_probe_read_kernel_str(&s->key.s[off + 1], COMP_LEN, s->comp[i]);
	if (n <= 1 || n > COMP_LEN) {
		c->status = ST_ERR;
		return 1;
	}
	c->off = off + n; /* the next "/" overwrites the NUL */
	lookup_merge(s, c);
	return 0;
}

static __always_inline int deny(struct scratch *s, __u32 hook, __u32 need,
				__u32 status)
{
	s->d.pid = bpf_get_current_pid_tgid() >> 32;
	s->d.hook = hook;
	s->d.need = need;
	s->d.status = status;
	bpf_get_current_comm(s->d.comm, sizeof(s->d.comm));
	if (status == ST_NOMATCH || status == ST_DENYRULE)
		__builtin_memcpy(s->d.path, s->key.s, KEY_LEN);
	else
		s->d.path[0] = 0;
	bpf_ringbuf_output(&denials, &s->d, sizeof(s->d), BPF_RB_FORCE_WAKEUP);
	return -EACCES;
}

static __always_inline int decide(__u32 hook, __u32 need, __u64 start,
				  __u64 mnt)
{
	struct scratch *s = get_scratch();
	struct walk_ctx w = {};
	struct match_ctx m = {};

	if (!s)
		return -EACCES;
	if (!mnt)
		return deny(s, hook, need, ST_ERR);
	w.dentry = start;
	w.mnt = mnt;
	bpf_loop(MAX_STEPS, walk_step, &w, 0);
	if (w.status)
		return deny(s, hook, need, w.status);
	if (!w.done)
		return deny(s, hook, need, ST_STEPS);

	/* Name rule: the last component. Skipped for the root itself. */
	__builtin_memset(s->key.s, 0, KEY_LEN);
	s->key.tag = 1;
	if (w.n) {
		bpf_probe_read_kernel_str(s->key.s, COMP_LEN, s->comp[0]);
		lookup_merge(s, &m);
	}

	/* Path rules: "/" first, then each longer prefix. */
	__builtin_memset(s->key.s, 0, KEY_LEN);
	s->key.tag = 0;
	s->key.s[0] = '/';
	lookup_merge(s, &m);
	m.n = w.n;
	if (w.n)
		bpf_loop(w.n, match_step, &m, 0);
	if (m.status)
		return deny(s, hook, need, m.status);

	if (need & KIND_READ) {
		if (!m.seq[0])
			return deny(s, hook, need, ST_NOMATCH);
		if (!m.eff[0])
			return deny(s, hook, need, ST_DENYRULE);
	}
	if (need & KIND_WRITE) {
		if (!m.seq[1])
			return deny(s, hook, need, ST_NOMATCH);
		if (!m.eff[1])
			return deny(s, hook, need, ST_DENYRULE);
	}
	return 0;
}

/* ---- hooks ---- */

SEC("lsm/task_alloc")
int BPF_PROG(e_inherit, struct task_struct *task, unsigned long clone_flags)
{
	if (is_confined(bpf_get_current_task_btf())) {
		__u32 *v = bpf_task_storage_get(&confined, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);

		if (v)
			*v = 1;
	}
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(e_file_open, struct file *file)
{
	__u32 mode, need = 0;

	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	mode = BPF_CORE_READ(file, f_mode);
	if (mode & M_WRITE)
		need |= KIND_WRITE;
	if ((mode & M_READ) || !(mode & M_WRITE))
		need |= KIND_READ;
	return decide(H_FILE_OPEN, need,
		      (__u64)BPF_CORE_READ(&file->f_path, dentry),
		      mnt_of(&file->f_path));
}

SEC("lsm/file_truncate")
int BPF_PROG(e_file_truncate, struct file *file)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_FILE_TRUNC, KIND_WRITE,
		      (__u64)BPF_CORE_READ(&file->f_path, dentry),
		      mnt_of(&file->f_path));
}

SEC("lsm/path_truncate")
int BPF_PROG(e_path_truncate, const struct path *path)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_PATH_TRUNC, KIND_WRITE,
		      (__u64)BPF_CORE_READ(path, dentry), mnt_of(path));
}

/* The next five name a child (dentry) of a directory (dir). Walking from the
 * child gives the full path of the thing being created or removed. */

SEC("lsm/path_mknod")
int BPF_PROG(e_path_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_MKNOD, KIND_WRITE, launder(dentry), mnt_of(dir));
}

SEC("lsm/path_mkdir")
int BPF_PROG(e_path_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_MKDIR, KIND_WRITE, launder(dentry), mnt_of(dir));
}

SEC("lsm/path_rmdir")
int BPF_PROG(e_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_RMDIR, KIND_WRITE, launder(dentry), mnt_of(dir));
}

SEC("lsm/path_unlink")
int BPF_PROG(e_path_unlink, const struct path *dir, struct dentry *dentry)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_UNLINK, KIND_WRITE, launder(dentry), mnt_of(dir));
}

SEC("lsm/path_symlink")
int BPF_PROG(e_path_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return decide(H_SYMLINK, KIND_WRITE, launder(dentry), mnt_of(dir));
}

SEC("lsm/path_rename")
int BPF_PROG(e_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	int r;

	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	r = decide(H_RENAME_OLD, KIND_WRITE, launder(old_dentry),
		   mnt_of(old_dir));
	if (r)
		return r;
	return decide(H_RENAME_NEW, KIND_WRITE, launder(new_dentry),
		      mnt_of(new_dir));
}

/* Deny, and log it (R7), for hooks that refuse every confined caller. */
static __always_inline int deny_always(__u32 hook)
{
	struct scratch *s = get_scratch();

	if (s)
		deny(s, hook, 0, ST_ALWAYS);
	return -EPERM;
}

/* Hard links are always denied (R6). */
SEC("lsm/path_link")
int BPF_PROG(e_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return deny_always(H_LINK);
}

/* No new user namespaces, so no private mounts (R12). */
SEC("lsm/userns_create")
int BPF_PROG(e_userns_create, const struct cred *cred)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	return deny_always(H_USERNS);
}

/* A confined task may not trace a task outside the confined set (R11). */
SEC("lsm/ptrace_access_check")
int BPF_PROG(e_ptrace_access_check, struct task_struct *child, unsigned int mode)
{
	if (!is_confined(bpf_get_current_task_btf()))
		return 0;
	if (is_confined(child))
		return 0;
	return deny_always(H_PTRACE);
}
