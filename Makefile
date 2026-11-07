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

# Needs sudo for setcap. The check installs any policy it likes, so it holds
# the capabilities only while it runs.
attach-check: build/attach-check
	sudo setcap cap_bpf,cap_perfmon=ep build/attach-check
	build/attach-check; \
	status=$$?; sudo setcap -r build/attach-check; exit $$status

clean:
	rm -rf build
