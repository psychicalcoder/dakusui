// SPDX-License-Identifier: GPL-2.0
/*
 * Spike for spec 0001, Q7: which LSM hooks can give us a path string?
 *
 * Every hook gets three programs, one per way of building the path:
 *   d_<hook>  bpf_d_path() helper
 *   k_<hook>  bpf_path_d_path() kfunc (needs a sleepable program)
 *   w_<hook>  walk dentries and mounts by hand
 * The loader loads each program alone, so the verifier tells us which
 * combinations work.
 *
 * Only tasks flagged in `watched` produce events. The flag is copied to
 * children in task_alloc, which also tests the task flag design (Q8).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "probe.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} watched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Per-task scratch space for the dentry walk. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct event);
} scratch SEC(".maps");

extern int bpf_path_d_path(struct path *path, char *buf, size_t buf__sz)
	__ksym __weak;

#define MAX_STEPS 32

static __always_inline int is_watched(void)
{
	struct task_struct *t = bpf_get_current_task_btf();

	return bpf_task_storage_get(&watched, t, 0, 0) != NULL;
}

static __always_inline struct event *new_event(__u32 hook, __u32 strat,
					       __u32 extra)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return NULL;
	e->hook = hook;
	e->strat = strat;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->extra = extra;
	e->err = 0;
	e->ncomp = 0;
	e->path[0] = 0;
	e->name[0] = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

static __always_inline void put_name(struct event *e, struct dentry *d)
{
	const unsigned char *n;

	if (!d)
		return;
	n = BPF_CORE_READ(d, d_name.name);
	bpf_probe_read_kernel_str(e->name, sizeof(e->name), n);
}

static __always_inline void emit_d(__u32 hook, const struct path *p,
				   struct dentry *name_d, __u32 extra)
{
	struct event *e = new_event(hook, S_DPATH, extra);

	if (!e)
		return;
	e->err = bpf_d_path((struct path *)p, e->path, sizeof(e->path));
	put_name(e, name_d);
	bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_k(__u32 hook, const struct path *p,
				   struct dentry *name_d, __u32 extra)
{
	struct event *e = new_event(hook, S_KFUNC, extra);

	if (!e)
		return;
	e->err = bpf_path_d_path((struct path *)p, e->path, sizeof(e->path));
	put_name(e, name_d);
	bpf_ringbuf_submit(e, 0);
}

/*
 * Walk from a dentry to the global root, crossing mounts when a struct path
 * is given. With only a dentry (path_link's old_dentry) the walk stops at the
 * root of that filesystem.
 *
 * The first version unrolled the loop and the verifier gave up after a
 * million instructions. bpf_loop() runs the step as a callback, so the
 * verifier checks it once. The callback keeps only plain integers in its
 * context and builds the event in per-task scratch space.
 */
struct walk_ctx {
	__u64 dentry;
	__u64 mnt;
	__u32 n;
	int done;
	int trunc;
};

static __always_inline struct event *scratch_event(void)
{
	return bpf_task_storage_get(&scratch, bpf_get_current_task_btf(), 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/* Turn a typed pointer into a plain integer the verifier will not track. */
static __always_inline __u64 launder(const void *ptr)
{
	__u64 out = 0;

	bpf_probe_read_kernel(&out, sizeof(out), &ptr);
	return out;
}

static __noinline long walk_step(__u32 idx, void *data)
{
	struct walk_ctx *c = data;
	struct dentry *dentry = (struct dentry *)c->dentry;
	struct mount *mnt = (struct mount *)c->mnt;
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);

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
		c->trunc = 1;
	} else {
		const unsigned char *nm = BPF_CORE_READ(dentry, d_name.name);
		struct event *e = scratch_event();

		if (!e)
			return 1;
		bpf_probe_read_kernel_str(e->comp[c->n & (MAX_COMP - 1)],
					  COMP_LEN, nm);
		c->n++;
	}
	c->dentry = (__u64)parent;
	return 0;
}

static __always_inline void emit_w(__u32 hook, const struct path *p,
				   struct dentry *start, struct dentry *name_d,
				   __u32 extra)
{
	struct event *e = scratch_event();
	struct walk_ctx c = {};

	if (!e)
		return;
	e->hook = hook;
	e->strat = S_WALK;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->extra = extra;
	e->path[0] = 0;
	e->name[0] = 0;
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	if (p) {
		struct vfsmount *vfs = BPF_CORE_READ(p, mnt);
		struct mount *mz = NULL;

		c.dentry = (__u64)BPF_CORE_READ(p, dentry);
		if (vfs)
			c.mnt = (__u64)vfs - bpf_core_field_offset(mz->mnt);
	} else {
		c.dentry = launder(start);
	}
	bpf_loop(MAX_STEPS, walk_step, &c, 0);
	e->ncomp = c.n;
	e->err = c.trunc ? -7 : (c.done ? 0 : -8);
	put_name(e, name_d);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
}

/* Copy the flag to every new task. This is the Q8 inheritance mechanism. */
SEC("lsm/task_alloc")
int BPF_PROG(inherit, struct task_struct *task, unsigned long clone_flags)
{
	struct task_struct *cur = bpf_get_current_task_btf();

	if (bpf_task_storage_get(&watched, cur, 0, 0)) {
		__u32 *v = bpf_task_storage_get(&watched, task, 0,
						BPF_LOCAL_STORAGE_GET_F_CREATE);

		if (v)
			*v = 1;
	}
	return 0;
}

/* ---- file_open ---- */
SEC("lsm/file_open")
int BPF_PROG(d_file_open, struct file *file)
{
	if (is_watched())
		emit_d(H_FILE_OPEN, &file->f_path, NULL,
		       BPF_CORE_READ(file, f_flags));
	return 0;
}
SEC("lsm.s/file_open")
int BPF_PROG(k_file_open, struct file *file)
{
	if (is_watched())
		emit_k(H_FILE_OPEN, &file->f_path, NULL,
		       BPF_CORE_READ(file, f_flags));
	return 0;
}
SEC("lsm/file_open")
int BPF_PROG(w_file_open, struct file *file)
{
	if (is_watched())
		emit_w(H_FILE_OPEN, &file->f_path, NULL, NULL,
		       BPF_CORE_READ(file, f_flags));
	return 0;
}

/* ---- file_permission: runs on every read and write ---- */
SEC("lsm/file_permission")
int BPF_PROG(d_file_permission, struct file *file, int mask)
{
	if (is_watched())
		emit_d(H_FILE_PERM, &file->f_path, NULL, mask);
	return 0;
}
SEC("lsm.s/file_permission")
int BPF_PROG(k_file_permission, struct file *file, int mask)
{
	if (is_watched())
		emit_k(H_FILE_PERM, &file->f_path, NULL, mask);
	return 0;
}
SEC("lsm/file_permission")
int BPF_PROG(w_file_permission, struct file *file, int mask)
{
	if (is_watched())
		emit_w(H_FILE_PERM, &file->f_path, NULL, NULL, mask);
	return 0;
}

/* ---- file_truncate(file): ftruncate() goes here, not through path_truncate ---- */
SEC("lsm/file_truncate")
int BPF_PROG(d_file_truncate, struct file *file)
{
	if (is_watched())
		emit_d(H_FTRUNC, &file->f_path, NULL, 0);
	return 0;
}
SEC("lsm.s/file_truncate")
int BPF_PROG(k_file_truncate, struct file *file)
{
	if (is_watched())
		emit_k(H_FTRUNC, &file->f_path, NULL, 0);
	return 0;
}
SEC("lsm/file_truncate")
int BPF_PROG(w_file_truncate, struct file *file)
{
	if (is_watched())
		emit_w(H_FTRUNC, &file->f_path, NULL, NULL, 0);
	return 0;
}

/* ---- path_truncate(path) ---- */
SEC("lsm/path_truncate")
int BPF_PROG(d_path_truncate, const struct path *path)
{
	if (is_watched())
		emit_d(H_TRUNCATE, path, NULL, 0);
	return 0;
}
SEC("lsm.s/path_truncate")
int BPF_PROG(k_path_truncate, const struct path *path)
{
	if (is_watched())
		emit_k(H_TRUNCATE, path, NULL, 0);
	return 0;
}
SEC("lsm/path_truncate")
int BPF_PROG(w_path_truncate, const struct path *path)
{
	if (is_watched())
		emit_w(H_TRUNCATE, path, NULL, NULL, 0);
	return 0;
}

/* ---- path_unlink(dir, dentry) ---- */
SEC("lsm/path_unlink")
int BPF_PROG(d_path_unlink, const struct path *dir, struct dentry *dentry)
{
	if (is_watched())
		emit_d(H_UNLINK, dir, dentry, 0);
	return 0;
}
SEC("lsm.s/path_unlink")
int BPF_PROG(k_path_unlink, const struct path *dir, struct dentry *dentry)
{
	if (is_watched())
		emit_k(H_UNLINK, dir, dentry, 0);
	return 0;
}
SEC("lsm/path_unlink")
int BPF_PROG(w_path_unlink, const struct path *dir, struct dentry *dentry)
{
	if (is_watched())
		emit_w(H_UNLINK, dir, NULL, dentry, 0);
	return 0;
}

/* ---- path_mkdir(dir, dentry, mode) ---- */
SEC("lsm/path_mkdir")
int BPF_PROG(d_path_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (is_watched())
		emit_d(H_MKDIR, dir, dentry, mode);
	return 0;
}
SEC("lsm.s/path_mkdir")
int BPF_PROG(k_path_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (is_watched())
		emit_k(H_MKDIR, dir, dentry, mode);
	return 0;
}
SEC("lsm/path_mkdir")
int BPF_PROG(w_path_mkdir, const struct path *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (is_watched())
		emit_w(H_MKDIR, dir, NULL, dentry, mode);
	return 0;
}

/* ---- path_rmdir(dir, dentry) ---- */
SEC("lsm/path_rmdir")
int BPF_PROG(d_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	if (is_watched())
		emit_d(H_RMDIR, dir, dentry, 0);
	return 0;
}
SEC("lsm.s/path_rmdir")
int BPF_PROG(k_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	if (is_watched())
		emit_k(H_RMDIR, dir, dentry, 0);
	return 0;
}
SEC("lsm/path_rmdir")
int BPF_PROG(w_path_rmdir, const struct path *dir, struct dentry *dentry)
{
	if (is_watched())
		emit_w(H_RMDIR, dir, NULL, dentry, 0);
	return 0;
}

/* ---- path_mknod(dir, dentry, mode, dev): creates regular files, fifos ---- */
SEC("lsm/path_mknod")
int BPF_PROG(d_path_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev)
{
	if (is_watched())
		emit_d(H_MKNOD, dir, dentry, mode);
	return 0;
}
SEC("lsm.s/path_mknod")
int BPF_PROG(k_path_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev)
{
	if (is_watched())
		emit_k(H_MKNOD, dir, dentry, mode);
	return 0;
}
SEC("lsm/path_mknod")
int BPF_PROG(w_path_mknod, const struct path *dir, struct dentry *dentry,
	     umode_t mode, unsigned int dev)
{
	if (is_watched())
		emit_w(H_MKNOD, dir, NULL, dentry, mode);
	return 0;
}

/* ---- path_symlink(dir, dentry, old_name) ---- */
SEC("lsm/path_symlink")
int BPF_PROG(d_path_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name)
{
	if (is_watched())
		emit_d(H_SYMLINK, dir, dentry, 0);
	return 0;
}
SEC("lsm.s/path_symlink")
int BPF_PROG(k_path_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name)
{
	if (is_watched())
		emit_k(H_SYMLINK, dir, dentry, 0);
	return 0;
}
SEC("lsm/path_symlink")
int BPF_PROG(w_path_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name)
{
	if (is_watched())
		emit_w(H_SYMLINK, dir, NULL, dentry, 0);
	return 0;
}

/*
 * ---- path_link(old_dentry, new_dir, new_dentry) ----
 * The old side has a dentry but no struct path, so only the walk can
 * describe it. That is the interesting case for hard links.
 */
SEC("lsm/path_link")
int BPF_PROG(d_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (is_watched())
		emit_d(H_LINK_NEW, new_dir, new_dentry, 0);
	return 0;
}
SEC("lsm.s/path_link")
int BPF_PROG(k_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (is_watched())
		emit_k(H_LINK_NEW, new_dir, new_dentry, 0);
	return 0;
}
SEC("lsm/path_link")
int BPF_PROG(w_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry)
{
	if (is_watched()) {
		emit_w(H_LINK_OLD, NULL, old_dentry, NULL, 0);
		emit_w(H_LINK_NEW, new_dir, NULL, new_dentry, 0);
	}
	return 0;
}

/* ---- path_rename(old_dir, old_dentry, new_dir, new_dentry, flags) ---- */
SEC("lsm/path_rename")
int BPF_PROG(d_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	if (is_watched()) {
		emit_d(H_RENAME_OLD, old_dir, old_dentry, flags);
		emit_d(H_RENAME_NEW, new_dir, new_dentry, flags);
	}
	return 0;
}
SEC("lsm.s/path_rename")
int BPF_PROG(k_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	if (is_watched()) {
		emit_k(H_RENAME_OLD, old_dir, old_dentry, flags);
		emit_k(H_RENAME_NEW, new_dir, new_dentry, flags);
	}
	return 0;
}
SEC("lsm/path_rename")
int BPF_PROG(w_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags)
{
	if (is_watched()) {
		emit_w(H_RENAME_OLD, old_dir, NULL, old_dentry, flags);
		emit_w(H_RENAME_NEW, new_dir, NULL, new_dentry, flags);
	}
	return 0;
}
