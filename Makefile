SBCL := sbcl --noinform --non-interactive --load scripts/tools.lisp
SOURCES := dakusui.asd scripts/tools.lisp $(shell find src -name '*.ct')
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: build bpf test options-check attach-check clean
# Each build compiles the shared systems, so builds must not race.
.NOTPARALLEL:
.DELETE_ON_ERROR:

build: build/dakusui build/dakusui-agent

# The helper's image embeds the enforcer object (T9, R11).
build/dakusui: $(SOURCES) build/enforce.bpf.o
	$(SBCL) --eval '(build-binary "dakusui/helper" "$@")'

build/dakusui-agent: $(SOURCES)
	$(SBCL) --eval '(build-binary "dakusui/agent" "$@")'

bpf: build/enforce.bpf.o

build/vmlinux.h:
	mkdir -p build
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

build/enforce.bpf.o: bpf/enforce.bpf.c bpf/enforce.h build/vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Ibuild -c $< -o $@

test: build/enforce.bpf.o
	$(SBCL) --eval '(run-tests)'

build/attach-check: $(SOURCES) test/attach-check.ct build/enforce.bpf.o
	$(SBCL) --eval '(build-binary "dakusui/attach-check" "$@")'

# No SBCL option of either binary runs code (T15, R11, part of A8).
options-check: build
	sh test/options-check.sh

# A copy of the real helper starts the check agent next to it, as it starts
# dakusui-agent (T17).
build/check/dakusui: build/dakusui
	mkdir -p build/check
	cp $< $@

build/check/dakusui-agent: $(SOURCES) test/check-agent.ct
	$(SBCL) --eval '(build-binary "dakusui/check-agent" "$@")'

# Needs sudo for setcap. The checks install any policy they like, so they
# hold the capabilities only while they run. The helper gets an API key and
# BASH_ENV, which no command may see. The check agent kills the helper last
# (A6), so the helper's exit code says nothing: the agent's last line does.
attach-check: build/attach-check build/check/dakusui build/check/dakusui-agent
	sudo setcap cap_bpf,cap_perfmon=ep build/attach-check
	sudo setcap cap_bpf,cap_perfmon=ep build/check/dakusui
	build/attach-check && \
	{ env OPENAI_API_KEY=attach-check BASH_ENV=/nonexistent build/check/dakusui; true; } \
	  | tee build/check/report && \
	grep -q '^check-agent passed' build/check/report; \
	status=$$?; sudo setcap -r build/attach-check; sudo setcap -r build/check/dakusui; \
	exit $$status

clean:
	rm -rf build
