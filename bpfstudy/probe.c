// SPDX-License-Identifier: GPL-2.0
/*
 * Loader for the Q7 spike.
 *
 * Phase 1 loads each BPF program alone, so the verifier's verdict tells us
 * which hook/strategy pairs are allowed.
 * Phase 2 loads and attaches the survivors, flags a child shell with the
 * `watched` task flag, runs test.sh in it, and tallies the events.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "probe.h"

static const char *hook_label[H_COUNT] = {
	"file_open",	 "file_permission", "path_truncate",
	"path_unlink",	 "path_mkdir",	    "path_rmdir",
	"path_mknod",	 "path_symlink",    "path_link (old)",
	"path_link (new)", "path_rename (old)", "path_rename (new)",
	"file_truncate",
};
static const char *prog_suffix[H_COUNT] = {
	"file_open",   "file_permission", "path_truncate", "path_unlink",
	"path_mkdir",  "path_rmdir",	  "path_mknod",	   "path_symlink",
	"path_link",   "path_link",	  "path_rename",   "path_rename",
	"file_truncate",
};
static const char strat_char[S_COUNT] = { 'd', 'k', 'w' };
static const char *strat_label[S_COUNT] = { "d_path helper", "d_path kfunc",
					    "dentry walk" };

struct prog_state {
	char name[64];
	int loaded;
	int attached;
	char reason[256];
};
static struct prog_state progs[64];
static int nprogs;

struct cell {
	unsigned events, bad, shm;
	char sample[PATH_LEN + NAME_LEN + 8];
};
static struct cell cells[H_COUNT][S_COUNT];

static char logbuf[1 << 17];
static size_t loglen;
static int capturing;
static int verbose;

static int print_cb(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (capturing) {
		int r;

		if (loglen >= sizeof(logbuf) - 1)
			return 0;
		r = vsnprintf(logbuf + loglen, sizeof(logbuf) - loglen, fmt, ap);
		if (r > 0)
			loglen += r;
		if (loglen > sizeof(logbuf) - 1)
			loglen = sizeof(logbuf) - 1;
		return 0;
	}
	if (lvl == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

/* Keep the end of the captured log: that is where the verifier says why. */
static void log_tail(char *out, size_t n)
{
	char *end = strstr(logbuf, "-- END PROG LOAD LOG --");
	size_t len = end ? (size_t)(end - logbuf) : loglen;
	size_t start = len > n - 1 ? len - (n - 1) : 0;
	size_t j = 0;

	for (size_t i = start; i < len && j < n - 1; i++)
		out[j++] = logbuf[i] == '\n' ? '|' : logbuf[i];
	out[j] = 0;
}

static struct prog_state *find_prog(const char *name)
{
	for (int i = 0; i < nprogs; i++)
		if (!strcmp(progs[i].name, name))
			return &progs[i];
	return NULL;
}

static struct prog_state *prog_for(int h, int s)
{
	char name[64];

	snprintf(name, sizeof(name), "%c_%s", strat_char[s], prog_suffix[h]);
	return find_prog(name);
}

static int probe_all(const char *path)
{
	struct bpf_object *tmpl = bpf_object__open_file(path, NULL);
	struct bpf_program *p;

	if (!tmpl) {
		fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}
	bpf_object__for_each_program(p, tmpl) {
		if (nprogs >= 64)
			break;
		snprintf(progs[nprogs++].name, sizeof(progs[0].name), "%s",
			 bpf_program__name(p));
	}
	bpf_object__close(tmpl);

	for (int i = 0; i < nprogs; i++) {
		struct bpf_object *obj;
		int err;

		if (!strcmp(progs[i].name, "inherit"))
			continue;
		obj = bpf_object__open_file(path, NULL);
		if (!obj) {
			snprintf(progs[i].reason, sizeof(progs[i].reason),
				 "open failed: %s", strerror(errno));
			continue;
		}
		bpf_object__for_each_program(p, obj)
			bpf_program__set_autoload(
				p, !strcmp(bpf_program__name(p), progs[i].name));
		loglen = 0;
		logbuf[0] = 0;
		capturing = 1;
		err = bpf_object__load(obj);
		capturing = 0;
		progs[i].loaded = !err;
		if (err)
			log_tail(progs[i].reason, sizeof(progs[i].reason));
		bpf_object__close(obj);
	}
	return 0;
}

static void walk_path(const struct event *e, char *out, size_t n)
{
	size_t j = 0;

	out[0] = 0;
	if (!e->ncomp) {
		snprintf(out, n, "/");
		return;
	}
	for (int i = (int)e->ncomp - 1; i >= 0 && j < n - 1; i--)
		j += snprintf(out + j, n - j, "/%s", e->comp[i % MAX_COMP]);
}

static int on_event(void *ctx, void *data, size_t sz)
{
	const struct event *e = data;
	struct cell *c;
	char path[PATH_LEN + 64];

	if (e->hook >= H_COUNT || e->strat >= S_COUNT)
		return 0;
	if (e->strat == S_WALK)
		walk_path(e, path, sizeof(path));
	else
		snprintf(path, sizeof(path), "%s", e->path);

	c = &cells[e->hook][e->strat];
	c->events++;
	if (e->err < 0)
		c->bad++;
	if (!strncmp(path, "/dev/shm", 8))
		c->shm++;
	if (c->events == 1)
		snprintf(c->sample, sizeof(c->sample), "%s%s%s", path,
			 e->name[0] ? "/" : "", e->name);
	if (verbose)
		printf("%-5u %-10s %-16s %-13s err=%d %s%s%s\n", e->pid,
		       e->comm, hook_label[e->hook], strat_label[e->strat],
		       e->err, path, e->name[0] ? "/" : "", e->name);
	return 0;
}

static int run_test(int watched_fd, struct ring_buffer *rb, const char *script,
		    const char *dir)
{
	int pfd[2], status = 0, pidfd;
	__u32 one = 1;
	pid_t pid;
	char c = 'x';

	if (pipe(pfd))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		close(pfd[1]);
		if (read(pfd[0], &c, 1) != 1)
			_exit(126);
		execl("/bin/sh", "sh", script, dir, (char *)NULL);
		_exit(127);
	}
	close(pfd[0]);

	/* The task flag keys on a pidfd. The child waits until it is set. */
	pidfd = syscall(SYS_pidfd_open, pid, 0);
	if (pidfd < 0 || bpf_map_update_elem(watched_fd, &pidfd, &one, BPF_ANY)) {
		fprintf(stderr, "cannot flag child: %s\n", strerror(errno));
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		return -1;
	}
	if (write(pfd[1], &c, 1) != 1)
		fprintf(stderr, "pipe write failed\n");
	close(pfd[1]);

	for (;;) {
		ring_buffer__poll(rb, 50);
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
	}
	for (int i = 0; i < 5; i++)
		ring_buffer__poll(rb, 50);
	close(pidfd);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static const char *cell_text(int h, int s, char *buf, size_t n)
{
	struct prog_state *ps;
	struct cell *c = &cells[h][s];

	if (h == H_LINK_OLD && s != S_WALK)
		return "n/a";
	ps = prog_for(h, s);
	if (!ps || !ps->loaded)
		return "noload";
	if (!ps->attached)
		return "noattach";
	if (!c->events)
		return "quiet";
	if (c->bad)
		snprintf(buf, n, "ERR %u/%u", c->bad, c->events);
	else
		snprintf(buf, n, "ok %u", c->events);
	return buf;
}

int main(int argc, char **argv)
{
	const char *obj_path = "probe.bpf.o";
	const char *script = "./test.sh";
	struct bpf_object *obj;
	struct bpf_program *p;
	struct ring_buffer *rb;
	char cwd[PATH_MAX], d1[PATH_MAX + 32], d2[64];
	const char *dirs[2];
	int watched_fd, events_fd;

	verbose = getenv("PROBE_VERBOSE") != NULL;
	libbpf_set_print(print_cb);

	if (probe_all(obj_path))
		return 1;

	/* Phase 2: load and attach what the verifier accepted. */
	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "cannot open %s\n", obj_path);
		return 1;
	}
	bpf_object__for_each_program(p, obj) {
		const char *nm = bpf_program__name(p);
		struct prog_state *ps = find_prog(nm);

		bpf_program__set_autoload(
			p, !strcmp(nm, "inherit") || (ps && ps->loaded));
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "final load failed: %s\n", strerror(errno));
		return 1;
	}
	bpf_object__for_each_program(p, obj) {
		const char *nm = bpf_program__name(p);
		struct prog_state *ps = find_prog(nm);
		struct bpf_link *l;

		if (!bpf_program__autoload(p))
			continue;
		capturing = 1;
		loglen = 0;
		l = bpf_program__attach(p);
		capturing = 0;
		if (ps)
			ps->attached = l != NULL;
		if (!l) {
			if (ps)
				log_tail(ps->reason, sizeof(ps->reason));
			if (!strcmp(nm, "inherit")) {
				fprintf(stderr, "cannot attach task_alloc: %s\n",
					strerror(errno));
				return 1;
			}
		}
	}
	watched_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "watched"));
	events_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
	rb = ring_buffer__new(events_fd, on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring buffer failed\n");
		return 1;
	}

	/* One directory on the current filesystem, one on tmpfs (a mount). */
	if (!getcwd(cwd, sizeof(cwd)))
		return 1;
	snprintf(d1, sizeof(d1), "%s/bpfstudy-sandbox", cwd);
	snprintf(d2, sizeof(d2), "/dev/shm/bpfstudy-sandbox");
	dirs[0] = d1;
	dirs[1] = d2;
	for (int i = 0; i < 2; i++) {
		int rc = run_test(watched_fd, rb, script, dirs[i]);

		printf("test in %s: exit %d\n", dirs[i], rc);
	}

	printf("\nProgram loading and events per hook\n");
	printf("%-18s", "hook");
	for (int s = 0; s < S_COUNT; s++)
		printf("%-16s", strat_label[s]);
	printf("\n");
	for (int h = 0; h < H_COUNT; h++) {
		printf("%-18s", hook_label[h]);
		for (int s = 0; s < S_COUNT; s++) {
			char buf[32] = "";

			printf("%-16s", cell_text(h, s, buf, sizeof(buf)));
		}
		printf("\n");
	}

	printf("\nEvents under /dev/shm, a separate mount. Each row must match.\n");
	for (int h = 0; h < H_COUNT; h++) {
		printf("%-18s", hook_label[h]);
		for (int s = 0; s < S_COUNT; s++)
			printf("%-16u", cells[h][s].shm);
		printf("\n");
	}

	printf("\nFirst path seen per hook\n");
	for (int h = 0; h < H_COUNT; h++)
		for (int s = 0; s < S_COUNT; s++)
			if (cells[h][s].events)
				printf("%-18s %-14s %s\n", hook_label[h],
				       strat_label[s], cells[h][s].sample);

	printf("\nWhy programs failed to load or attach\n");
	for (int i = 0; i < nprogs; i++)
		if ((!progs[i].loaded || !progs[i].attached) &&
		    strcmp(progs[i].name, "inherit"))
			printf("%-22s %s\n", progs[i].name,
			       progs[i].reason[0] ? progs[i].reason : "(no detail)");
	return 0;
}
