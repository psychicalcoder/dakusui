// SPDX-License-Identifier: GPL-2.0
/*
 * Test driver for spike 2. It loads the enforcer, compiles rule lists into
 * the rule map, runs shell commands as confined processes, and checks each
 * outcome. Then it measures what the checks cost per open.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "enforce.h"

static const char *hook_name[H_COUNT] = {
	"file_open",   "file_truncate", "path_truncate", "path_mknod",
	"path_mkdir",  "path_rmdir",	"path_unlink",	 "path_symlink",
	"rename(old)", "rename(new)",	"path_link",	 "userns_create",
	"ptrace",
};
static const char *why_name[] = {
	"ok",	     "too many components", "name too long",  "path too long",
	"walk step limit", "internal error", "no matching rule",
	"denied by rule", "always denied", "helper gone",
};

struct rule {
	int allow, kinds;
	char pattern[KEY_LEN];
};
struct rules {
	struct rule r[128];
	int n;
};

static int outer_fd, confined_fd;
static struct ring_buffer *rb;
static int verbose, npass, nfail, nskip;
static unsigned ndenials;
static struct denial first;

static void add(struct rules *rs, int allow, int kinds, const char *fmt, ...)
{
	struct rule *r = &rs->r[rs->n++];
	va_list ap;

	r->allow = allow;
	r->kinds = kinds;
	va_start(ap, fmt);
	vsnprintf(r->pattern, sizeof(r->pattern), fmt, ap);
	va_end(ap);
}

/* Compile an ordered rule list into a fresh inner map and swap it in. */
static int apply_policy(const struct rules *rs)
{
	static struct {
		struct rule_key k;
		struct rule_val v;
	} ent[256];
	int ne = 0, inner, zero = 0;

	for (int i = 0; i < rs->n; i++) {
		const struct rule *r = &rs->r[i];
		struct rule_key k;
		int j;

		memset(&k, 0, sizeof(k));
		if (!strncmp(r->pattern, "name:", 5)) {
			k.tag = 1;
			snprintf(k.s, KEY_LEN, "%s", r->pattern + 5);
		} else {
			size_t len;

			k.tag = 0;
			snprintf(k.s, KEY_LEN, "%s", r->pattern);
			len = strlen(k.s);
			while (len > 1 && k.s[len - 1] == '/')
				k.s[--len] = 0;
		}
		for (j = 0; j < ne; j++)
			if (!memcmp(&ent[j].k, &k, sizeof(k)))
				break;
		if (j == ne) {
			memset(&ent[ne], 0, sizeof(ent[ne]));
			ent[ne].k = k;
			ne++;
		}
		for (int b = 0; b < 2; b++) {
			if (r->kinds & (1 << b)) {
				ent[j].v.seq[b] = i + 1; /* later rules win */
				ent[j].v.effect[b] = r->allow;
			}
		}
	}
	inner = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(struct rule_key),
			       sizeof(struct rule_val), 1024, NULL);
	if (inner < 0) {
		perror("bpf_map_create");
		return -1;
	}
	for (int j = 0; j < ne; j++) {
		if (bpf_map_update_elem(inner, &ent[j].k, &ent[j].v, BPF_ANY)) {
			perror("rule insert");
			close(inner);
			return -1;
		}
	}
	if (bpf_map_update_elem(outer_fd, &zero, &inner, BPF_ANY)) {
		perror("swap rules");
		close(inner);
		return -1;
	}
	close(inner);
	return 0;
}

static int on_denial(void *ctx, void *data, size_t sz)
{
	const struct denial *d = data;

	if (ndenials++ == 0)
		first = *d;
	if (verbose)
		printf("      denial: pid %u %s %s need=%u %s %s\n", d->pid,
		       d->comm, hook_name[d->hook < H_COUNT ? d->hook : 0],
		       d->need, why_name[d->status < 9 ? d->status : 5],
		       d->path);
	return 0;
}

static int flag_pid(pid_t pid)
{
	__u32 one = 1;
	int pidfd = syscall(SYS_pidfd_open, pid, 0), rc;

	if (pidfd < 0)
		return -1;
	rc = bpf_map_update_elem(confined_fd, &pidfd, &one, BPF_ANY);
	close(pidfd);
	return rc;
}

/*
 * The launcher from the plan: a shell blocks on fd 3 until it is flagged,
 * then execs the command without fd 3.
 */
static pid_t spawn(const char *cmd, int flag)
{
	int p[2];
	pid_t pid;

	if (pipe(p))
		return -1;
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		close(p[1]);
		if (dup2(p[0], 3) < 0)
			_exit(126);
		if (p[0] != 3)
			close(p[0]);
		execl("/bin/sh", "sh", "-c",
		      "read _ <&3 && exec sh -c \"$1\" 3<&-", "sh", cmd,
		      (char *)NULL);
		_exit(127);
	}
	close(p[0]);
	if (flag && flag_pid(pid)) {
		fprintf(stderr, "cannot flag child: %s\n", strerror(errno));
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		close(p[1]);
		return -1;
	}
	if (write(p[1], "x\n", 2) != 2)
		fprintf(stderr, "release failed\n");
	close(p[1]);
	return pid;
}

static void report(const char *name, int expect_ok, int status)
{
	int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	/* A command that should be denied must also leave a denial record. */
	int pass = ok == expect_ok && (expect_ok || ndenials > 0);

	printf("%-4s %-52s expect %-4s got %-4s", pass ? "PASS" : "FAIL", name,
	       expect_ok ? "ok" : "deny", ok ? "ok" : "fail");
	if (ndenials)
		printf("  [%u denial(s); first: %s %s \"%s\"]", ndenials,
		       hook_name[first.hook < H_COUNT ? first.hook : 0],
		       why_name[first.status < 9 ? first.status : 5],
		       first.path);
	printf("\n");
	pass ? npass++ : nfail++;
}

static void run(const char *name, int expect_ok, const char *fmt, ...)
{
	char cmd[1024];
	va_list ap;
	int status = 0;
	pid_t pid;

	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	ring_buffer__poll(rb, 0);
	ndenials = 0;
	pid = spawn(cmd, 1);
	if (pid < 0) {
		printf("FAIL %s: cannot spawn\n", name);
		nfail++;
		return;
	}
	waitpid(pid, &status, 0);
	ring_buffer__poll(rb, 50);
	ring_buffer__consume(rb);
	report(name, expect_ok, status);
}

static void sh(const char *fmt, ...)
{
	char cmd[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	if (system(cmd))
		fprintf(stderr, "setup command failed: %s\n", cmd);
}

/* A7: a descriptor opened before a rule change keeps working after it. */
static void test_open_fd_survives(const char *S)
{
	char cmd[1024], fifo[PATH_MAX];
	struct rules none = { .n = 0 };
	int status = 0, wf;
	pid_t pid;

	snprintf(fifo, sizeof(fifo), "%s/fifo", S);
	snprintf(cmd, sizeof(cmd),
		 "exec 3< '%s/ok.txt'; exec 4< '%s'; read x <&4; read y <&3",
		 S, fifo);
	ring_buffer__poll(rb, 0);
	ndenials = 0;
	pid = spawn(cmd, 1);
	/* Returns once the command has opened the fifo, so it already holds fd 3. */
	wf = open(fifo, O_WRONLY);
	apply_policy(&none); /* now deny everything */
	if (write(wf, "x\n", 2) != 2)
		fprintf(stderr, "fifo write failed\n");
	close(wf);
	waitpid(pid, &status, 0);
	ring_buffer__poll(rb, 50);
	ring_buffer__consume(rb);
	report("A7 open fd keeps working after a deny-all swap", 1, status);
}

static void bench(const char *label, const char *path, int flag)
{
	int p[2], status = 0;
	pid_t pid;

	if (pipe(p))
		return;
	fflush(stdout);
	pid = fork();
	if (pid == 0) {
		struct timespec a, b;
		const int n = 50000;
		char c;

		close(p[1]);
		if (read(p[0], &c, 1) != 1)
			_exit(1);
		clock_gettime(CLOCK_MONOTONIC, &a);
		for (int i = 0; i < n; i++) {
			int fd = open(path, O_RDONLY);

			if (fd < 0)
				_exit(2);
			close(fd);
		}
		clock_gettime(CLOCK_MONOTONIC, &b);
		printf("%-26s %-9s %7.0f ns/open\n", label,
		       flag ? "confined" : "baseline",
		       ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) /
			       n);
		fflush(stdout);
		_exit(0);
	}
	close(p[0]);
	if (flag)
		flag_pid(pid);
	if (write(p[1], "x", 1) != 1)
		fprintf(stderr, "release failed\n");
	close(p[1]);
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		printf("%-26s %-9s open failed (denied?)\n", label,
		       flag ? "confined" : "baseline");
}

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *p;
	char S[PATH_MAX], cwd[PATH_MAX], chain[512] = "", chain40[512] = "";
	struct rules A = { .n = 0 }, B, C, bench_rules;
	int unshare_ok, victim_ok;
	pid_t victim;

	verbose = getenv("PROBE_VERBOSE") != NULL;

	obj = bpf_object__open_file("enforce.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "load failed\n");
		return 1;
	}
	bpf_object__for_each_program(p, obj) {
		if (!bpf_program__attach(p)) {
			fprintf(stderr, "attach failed: %s: %s\n",
				bpf_program__name(p), strerror(errno));
			return 1;
		}
	}
	/* Register as the live helper (ADR 0008), or every confined open is
	 * denied: write our pid, then open a file so the hook records our start. */
	{
		struct helper_info h = { .pid = getpid() };
		int zero = 0;

		if (bpf_map_update_elem(bpf_map__fd(bpf_object__find_map_by_name(obj, "helper")),
					&zero, &h, BPF_ANY))
			return 1;
		close(open("/", O_RDONLY));
	}
	outer_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "rules"));
	confined_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "confined"));
	rb = ring_buffer__new(
		bpf_map__fd(bpf_object__find_map_by_name(obj, "denials")),
		on_denial, NULL, NULL);
	if (!rb)
		return 1;

	if (!getcwd(cwd, sizeof(cwd)))
		return 1;
	snprintf(S, sizeof(S), "%s/enforce-sandbox", cwd);
	for (int i = 0; i < 20; i++)
		strcat(chain, "/a");
	for (int i = 0; i < 40; i++)
		strcat(chain40, "/b");

	/* Fixtures, created by this unconfined driver. */
	sh("rm -rf '%s'; mkdir -p '%s/secret' '%s/deep20%s' '%s/deep40%s'", S, S,
	   S, chain, S, chain40);
	sh("echo hello > '%s/ok.txt'; echo s > '%s/secret/x'; echo k > '%s/.env'",
	   S, S, S);
	sh("echo d > '%s/deep20%s/file'; echo d > '%s/deep40%s/file'; "
	   "mkfifo '%s/fifo'",
	   S, chain, S, chain40, S);
	unshare_ok = system("unshare -Urm true >/dev/null 2>&1") == 0;

	/* An unconfined, dumpable process of ours for the R11 test. The driver
	 * itself is not dumpable (it has file capabilities), so its /proc
	 * files are closed to us by ordinary permissions. */
	sh("echo r > /tmp/enforce-ro");
	victim = fork();
	if (victim == 0) {
		execlp("sleep", "sleep", "120", (char *)NULL);
		_exit(127);
	}
	usleep(200000);
	{
		char chk[128];

		snprintf(chk, sizeof(chk),
			 "cat /proc/%d/environ >/dev/null 2>&1", (int)victim);
		victim_ok = system(chk) == 0;
	}

	/* Policy A: read everything, write the sandbox, deny a few things. */
	add(&A, 1, KIND_READ, "/");
	add(&A, 1, KIND_READ | KIND_WRITE, "%s", S);
	add(&A, 1, KIND_WRITE, "/dev/null");
	add(&A, 0, KIND_READ | KIND_WRITE, "%s/secret", S);
	add(&A, 0, KIND_READ | KIND_WRITE, "name:.env");
	apply_policy(&A);

	printf("== Policy A ==\n");
	run("read allowed file", 1, "cat '%s/ok.txt' >/dev/null", S);
	run("read inside denied directory", 0, "cat '%s/secret/x' >/dev/null", S);
	run("read .env (name rule)", 0, "cat '%s/.env' >/dev/null", S);
	run("write inside sandbox", 1, "echo hi > '%s/new.txt'", S);
	run("write outside sandbox", 0, "echo hi > /tmp/enforce-x");
	run("mkdir inside sandbox", 1, "mkdir '%s/d1'", S);
	run("mkdir inside denied directory", 0, "mkdir '%s/secret/d'", S);
	run("rmdir inside sandbox", 1, "rmdir '%s/d1'", S);
	run("unlink inside sandbox", 1, "rm '%s/new.txt'", S);
	run("rename inside sandbox", 1,
	    "mv '%s/ok.txt' '%s/ok2.txt' && mv '%s/ok2.txt' '%s/ok.txt'", S, S,
	    S, S);
	run("rename out of sandbox", 0, "mv '%s/ok.txt' /tmp/enforce-y", S);
	run("hard link (R6, A9)", 0, "ln '%s/ok.txt' '%s/h'", S, S);
	run("symlink to a denied file, then read (A5)", 0,
	    "ln -s '%s/secret/x' '%s/sl' && cat '%s/sl' >/dev/null", S, S, S);
	run("write /dev/null", 1, "echo x > /dev/null");
	run("open read-write inside sandbox", 1, "exec 5<> '%s/ok.txt'", S);
	run("open read-write where only read is allowed", 0,
	    "exec 5<> /tmp/enforce-ro");
	run("path 22 components deep", 1, "cat '%s/deep20%s/file' >/dev/null", S,
	    chain);
	run("path over the component limit (fail closed)", 0,
	    "cat '%s/deep40%s/file' >/dev/null", S, chain40);
	if (unshare_ok)
		run("create user namespace (R12, A10)", 0, "unshare -Urm true");
	else {
		printf("SKIP create user namespace: unshare fails even unconfined\n");
		nskip++;
	}
	if (victim_ok)
		run("read another process's environment (R11)", 0,
		    "cat /proc/%d/environ >/dev/null", (int)victim);
	else {
		printf("SKIP read another process's environment: not readable even unconfined\n");
		nskip++;
	}
	run("a file in /dev/shm, a separate mount, is not writable", 0,
	    "echo x > /dev/shm/enforce-z");
	test_open_fd_survives(S);

	/* Policy B: live update, appended allow beats the earlier deny (A4). */
	B = A;
	add(&B, 1, KIND_READ, "%s/secret", S);
	apply_policy(&B);
	printf("== Policy B (A plus a later allow read on the denied directory) ==\n");
	run("read secret after live update", 1, "cat '%s/secret/x' >/dev/null", S);
	run("write secret still denied", 0, "echo y > '%s/secret/x'", S);

	/* Policy C: order matters (A3). */
	memset(&C, 0, sizeof(C));
	add(&C, 1, KIND_READ, "/");
	add(&C, 1, KIND_READ, "%s/secret/x", S);
	add(&C, 0, KIND_READ, "%s/secret", S);
	apply_policy(&C);
	printf("== Policy C (allow a file, then deny its directory) ==\n");
	run("last match wins: deny after allow (A3)", 0, "cat '%s/secret/x'", S);

	/* Cost per open, with a realistic number of rules. */
	bench_rules = A;
	for (int i = 0; i < 15; i++)
		add(&bench_rules, 0, KIND_READ | KIND_WRITE, "/nonexistent/dir%d",
		    i);
	apply_policy(&bench_rules);
	printf("== Cost per open (%d rules) ==\n", bench_rules.n);
	for (int f = 0; f < 2; f++) {
		char deep[PATH_MAX];

		bench("/etc/hostname", "/etc/hostname", f);
		snprintf(deep, sizeof(deep), "%s/ok.txt", S);
		bench("sandbox/ok.txt", deep, f);
		snprintf(deep, sizeof(deep), "%s/deep20%s/file", S, chain);
		bench("22 components deep", deep, f);
	}

	printf("\n%d passed, %d failed, %d skipped\n", npass, nfail, nskip);
	kill(victim, SIGKILL);
	waitpid(victim, NULL, 0);
	sh("rm -rf '%s' /tmp/enforce-x /tmp/enforce-y /tmp/enforce-ro "
	   "/dev/shm/enforce-z",
	   S);
	return nfail != 0;
}
