/* SPDX-License-Identifier: GPL-2.0 */
/* Shared by the BPF programs and the loader. */
#ifndef PROBE_H
#define PROBE_H

/* vmlinux.h already defines the kernel integer types. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* One id per place a path can be observed. */
enum hook_id {
	H_FILE_OPEN,
	H_FILE_PERM,
	H_TRUNCATE,
	H_UNLINK,
	H_MKDIR,
	H_RMDIR,
	H_MKNOD,
	H_SYMLINK,
	H_LINK_OLD,
	H_LINK_NEW,
	H_RENAME_OLD,
	H_RENAME_NEW,
	H_FTRUNC,
	H_COUNT
};

/* Three ways to get a path string. */
enum strat_id {
	S_DPATH, /* bpf_d_path() helper */
	S_KFUNC, /* bpf_path_d_path() kfunc, sleepable programs */
	S_WALK,  /* walk dentries and mounts by hand */
	S_COUNT
};

#define PATH_LEN 256
#define NAME_LEN 64
#define MAX_COMP 16 /* power of two: used as a mask */
#define COMP_LEN 32

struct event {
	__u32 hook;
	__u32 strat;
	__u32 pid;
	__u32 extra; /* open flags or permission mask */
	__s32 err;   /* d_path result, or walk status (0 = reached the root) */
	__u32 ncomp;
	char comm[16];
	char path[PATH_LEN]; /* S_DPATH, S_KFUNC */
	char name[NAME_LEN]; /* name of the dentry being created, removed, ... */
	char comp[MAX_COMP][COMP_LEN]; /* S_WALK: names, leaf first */
};

#endif
