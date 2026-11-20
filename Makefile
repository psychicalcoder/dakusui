SBCL := sbcl --noinform --non-interactive --load scripts/tools.lisp
SOURCES := dakusui.asd scripts/tools.lisp $(shell find src -name '*.ct')
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: build bpf test options-check agent-check attach-check clean
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

# The agent under a stand-in helper and a test provider: spec 0002 A11 and
# whole turns. Needs no privilege; commands run unconfined (T6).
agent-check: build/dakusui-agent
	python3 test/agent-check.py build/dakusui-agent

# A copy of the real helper starts the check agent next to it, as it starts
# dakusui-agent (T17).
build/check/dakusui: build/dakusui
	mkdir -p build/check
	cp $< $@

build/check/dakusui-agent: $(SOURCES) test/check-agent.ct test/check-stress.ct test/check-main.ct \
		test/mcp-server.py
	$(SBCL) --eval '(build-binary "dakusui/check-agent" "$@")'

# Copies of the real helper and agent, for spec 0002 A11 under the kernel.
build/check/real/dakusui: build/dakusui
	mkdir -p build/check/real
	cp $< $@

build/check/real/dakusui-agent: build/dakusui-agent
	mkdir -p build/check/real
	cp $< $@

# Needs sudo for setcap, and the bpffs at /run/dakusui/<uid> (ADR 0008; see
# docs/install.md). The checks install any policy they like, so they hold
# the capabilities only while they run. test/attach-check.sh says what runs.
attach-check: build/attach-check build/check/dakusui build/check/dakusui-agent \
		build/check/real/dakusui build/check/real/dakusui-agent
	sudo setcap cap_bpf,cap_perfmon=ep build/attach-check
	sudo setcap cap_bpf,cap_perfmon=ep build/check/dakusui
	sudo setcap cap_bpf,cap_perfmon=ep build/check/real/dakusui
	sh test/attach-check.sh; \
	status=$$?; sudo setcap -r build/attach-check; sudo setcap -r build/check/dakusui; \
	sudo setcap -r build/check/real/dakusui; exit $$status

clean:
	rm -rf build
