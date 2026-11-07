SBCL := sbcl --noinform --non-interactive --load scripts/tools.lisp
SOURCES := dakusui.asd scripts/tools.lisp $(shell find src -name '*.ct')
CLANG ?= clang
BPFTOOL ?= bpftool

.PHONY: build bpf test attach-check clean
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

build/attach-check: $(SOURCES) test/attach-check.ct
	$(SBCL) --eval '(build-binary "dakusui/attach-check" "$@")'

# Needs sudo for setcap. The capabilities stay on the file only for this run,
# because this image still honors SBCL's runtime options (T15).
attach-check: build/attach-check build/enforce.bpf.o
	sudo setcap cap_bpf,cap_perfmon=ep build/attach-check
	build/attach-check build/enforce.bpf.o; \
	status=$$?; sudo setcap -r build/attach-check; exit $$status

clean:
	rm -rf build
