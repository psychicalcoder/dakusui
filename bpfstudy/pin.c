// SPDX-License-Identifier: GPL-2.0
/*
 * Spike 3: does enforcement outlive its loader?
 *
 *   ./pin MODE DIR SANDBOX
 *
 * MODE is one of:
 *   nopin  load the enforcer, pin nothing (the control: today's design)
 *   pin    load the enforcer and pin its links and maps in DIR
 *   alive  load alive.bpf.o, which denies once the loader is gone, and pin it
 *
 * The loader installs "allow read /, allow write SANDBOX and /dev/null, deny
 * read SANDBOX/secret", then starts a confined victim in its own session. The
 * victim tries to read SANDBOX/secret and SANDBOX/ok every 10 ms and logs
 * "<secret><ok>" (1 read, 0 denied) to SANDBOX/log. The loader prints
 * "ready <victim pid>" and waits to be killed. spike3.sh does the rest.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "enforce.h"

static const char *loop =
	"while :; do "
	"if cat secret >/dev/null 2>&1; then s=1; else s=0; fi; "
	"if cat ok >/dev/null 2>&1; then o=1; else o=0; fi; "
	"echo \"$s$o\"; sleep 0.01 || :; "
	"done";

static int pin_failed;

static void pin_one(int is_link, void *obj, const char *dir, const char *name)
{
	char path[512];
	int rc;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	unlink(path); /* a stale pin from an earlier run */
	rc = is_link ? bpf_link__pin(obj, path) : bpf_map__pin(obj, path);
	printf("pin %-4s %-22s %s\n", is_link ? "link" : "map", name,
	       rc ? strerror(-rc) : "ok");
	if (rc)
		pin_failed = 1;
}

/*
 * One entry per pattern, as the library's compiler does: allow read /,
 * allow write SANDBOX, allow write /dev/null (for the victim's redirects),
 * deny read SANDBOX/secret.
 */
static int install(int outer_fd, const char *sandbox)
{
	struct {
		struct rule_key k;
		struct rule_val v;
	} ent[4];
	int inner, zero = 0;

	memset(ent, 0, sizeof(ent));
	snprintf(ent[0].k.s, KEY_LEN, "/");
	ent[0].v.seq[0] = 1, ent[0].v.effect[0] = 1;
	snprintf(ent[1].k.s, KEY_LEN, "%s", sandbox);
	ent[1].v.seq[1] = 2, ent[1].v.effect[1] = 1;
	snprintf(ent[2].k.s, KEY_LEN, "/dev/null");
	ent[2].v.seq[1] = 3, ent[2].v.effect[1] = 1;
	snprintf(ent[3].k.s, KEY_LEN, "%s/secret", sandbox);
	ent[3].v.seq[0] = 4, ent[3].v.effect[0] = 0;
	inner = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct rule_key),
			       sizeof(struct rule_val), 1024, NULL);
	if (inner < 0)
		return -1;
	for (int i = 0; i < 4; i++)
		if (bpf_map_update_elem(inner, &ent[i].k, &ent[i].v, BPF_ANY))
			return -1;
	if (bpf_map_update_elem(outer_fd, &zero, &inner, BPF_ANY))
		return -1;
	close(inner);
	return 0;
}

static pid_t start_victim(int confined_fd, const char *sandbox)
{
	char log[512];
	int gate[2], one = 1, pidfd;
	pid_t pid;

	snprintf(log, sizeof(log), "%s/log", sandbox);
	if (pipe(gate))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC, 0600);

		/* Its own session, so it outlives the loader like a nohup job. */
		setsid();
		if (fd < 0 || chdir(sandbox) || dup2(fd, 1) < 0 || dup2(fd, 2) < 0 ||
		    dup2(gate[0], 3) < 0)
			_exit(126);
		close(gate[1]);
		execl("/bin/sh", "sh", "-c",
		      "read _ <&3 && exec sh -c \"$1\" 3<&-", "sh", loop,
		      (char *)NULL);
		_exit(127);
	}
	close(gate[0]);
	pidfd = syscall(SYS_pidfd_open, pid, 0);
	if (pidfd < 0 || bpf_map_update_elem(confined_fd, &pidfd, &one, BPF_ANY)) {
		fprintf(stderr, "cannot flag the victim: %s\n", strerror(errno));
		return -1;
	}
	close(pidfd);
	if (write(gate[1], "go\n", 3) != 3)
		return -1;
	close(gate[1]);
	return pid;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	const char *mode, *dir, *sandbox;
	int alive, pinning;
	pid_t victim;

	if (argc != 4) {
		fprintf(stderr, "usage: %s nopin|pin|alive DIR SANDBOX\n", argv[0]);
		return 2;
	}
	mode = argv[1], dir = argv[2], sandbox = argv[3];
	alive = !strcmp(mode, "alive");
	pinning = strcmp(mode, "nopin");
	setvbuf(stdout, NULL, _IOLBF, 0);

	obj = bpf_object__open_file(alive ? "alive.bpf.o" : "enforce.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		return 1;
	}
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link = bpf_program__attach(prog);

		if (!link) {
			fprintf(stderr, "attach %s failed: %s\n",
				bpf_program__name(prog), strerror(errno));
			return 1;
		}
		if (pinning)
			pin_one(1, link, dir, bpf_program__name(prog));
	}
	if (pinning) {
		pin_one(0, bpf_object__find_map_by_name(obj, "confined"), dir, "map_confined");
		if (!alive)
			pin_one(0, bpf_object__find_map_by_name(obj, "rules"), dir, "map_rules");
	}
	if (pin_failed)
		return 3;

	if (alive) {
		struct { __s32 pid; __u32 pad; __u64 start; } h = { getpid(), 0, 0 };
		int zero = 0, fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "helper"));

		if (bpf_map_update_elem(fd, &zero, &h, BPF_ANY))
			return 1;
		close(open("/dev/null", O_RDONLY)); /* lets the hook learn our start */
	} else if (install(bpf_map__fd(bpf_object__find_map_by_name(obj, "rules")),
			   sandbox)) {
		fprintf(stderr, "policy failed: %s\n", strerror(errno));
		return 1;
	}

	victim = start_victim(bpf_map__fd(bpf_object__find_map_by_name(obj, "confined")),
			      sandbox);
	if (victim < 0)
		return 1;
	printf("ready %d\n", victim);
	for (;;)
		pause();
}
