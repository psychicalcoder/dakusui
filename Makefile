SBCL := sbcl --noinform --non-interactive --load scripts/tools.lisp
SOURCES := dakusui.asd scripts/tools.lisp $(shell find src -name '*.ct')
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: build bpf test clean
# Each build compiles the shared systems, so builds must not race.
.NOTPARALLEL:
.DELETE_ON_ERROR:

build: build/dakusui build/dakusui-agent

build/dakusui: $(SOURCES)
	$(SBCL) --eval '(build-binary "dakusui/helper" "$@")'

build/dakusui-agent: $(SOURCES)
	$(SBCL) --eval '(build-binary "dakusui/agent" "$@")'

bpf: build/enforce.bpf.o

build/vmlinux.h:
	mkdir -p build
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

build/enforce.bpf.o: bpf/enforce.bpf.c bpf/enforce.h build/vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Ibuild -c $< -o $@

test:
	$(SBCL) --eval '(run-tests)'

clean:
	rm -rf build
