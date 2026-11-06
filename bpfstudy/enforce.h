/* SPDX-License-Identifier: GPL-2.0 */
/* Shared by the enforcer (BPF) and its test driver. Spike 2 for spec 0001. */
#ifndef ENFORCE_H
#define ENFORCE_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define KEY_LEN 256
#define MAX_COMP 32  /* power of two: used as a mask */
#define COMP_LEN 64  /* longest path component handled: 63 bytes */
#define MAX_STEPS 96 /* walk steps, mount crossings included */

enum { KIND_READ = 1, KIND_WRITE = 2 };

/* Why a request was denied. Everything but the last two fails closed. */
enum {
	ST_OK,
	ST_DEEP,
	ST_LONGNAME,
	ST_LONGPATH,
	ST_STEPS,
	ST_ERR,
	ST_NOMATCH,
	ST_DENYRULE,
	ST_ALWAYS, /* hooks that deny every confined caller */
};

enum {
	H_FILE_OPEN,
	H_FILE_TRUNC,
	H_PATH_TRUNC,
	H_MKNOD,
	H_MKDIR,
	H_RMDIR,
	H_UNLINK,
	H_SYMLINK,
	H_RENAME_OLD,
	H_RENAME_NEW,
	H_LINK,
	H_USERNS,
	H_PTRACE,
	H_COUNT
};

/* tag 0: path prefix, tag 1: file name. The string is zero padded, so keys
 * compare as exact bytes and no hash collision can change a verdict. */
struct rule_key {
	__u32 tag;
	char s[KEY_LEN];
};

/* Index 0 is read, index 1 is write. seq 0 means "no rule for this kind". */
struct rule_val {
	__u32 seq[2];
	__u8 effect[2]; /* 1 allow, 0 deny */
	__u8 pad[2];
};

struct denial {
	__u32 pid;
	__u32 hook;
	__u32 need;
	__u32 status;
	char comm[16];
	char path[KEY_LEN];
};

#endif
