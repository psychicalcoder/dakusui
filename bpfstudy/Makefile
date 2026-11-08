CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
LIBBPF  := $(shell pkg-config --cflags --libs libbpf)

all: probe probe.bpf.o enforce enforce.bpf.o pin alive.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

probe.bpf.o: probe.bpf.c probe.h vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g -Wall -c $< -o $@

probe: probe.c probe.h
	$(CC) -O2 -g -Wall $< -o $@ $(LIBBPF)

# The enforcer itself now lives in ../bpf.
enforce.bpf.o: ../bpf/enforce.bpf.c ../bpf/enforce.h vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g -Wall -I. -c $< -o $@

enforce: enforce.c ../bpf/enforce.h
	$(CC) -O2 -g -Wall -I../bpf $< -o $@ $(LIBBPF)

# File capabilities are lost on every rebuild, so set them before each run.
run: probe probe.bpf.o
	sudo setcap cap_bpf,cap_perfmon+ep ./probe
	./probe

# Spike 2: the real enforcer.
run2: enforce enforce.bpf.o
	sudo setcap cap_bpf,cap_perfmon+ep ./enforce
	./enforce

alive.bpf.o: alive.bpf.c vmlinux.h
	$(CLANG) -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g -Wall -I. -c $< -o $@

pin: pin.c ../bpf/enforce.h
	$(CC) -O2 -g -Wall -I../bpf $< -o $@ $(LIBBPF)

# Spike 3: pinning. Needs `sudo sh pin-setup.sh` once per boot.
run3: pin enforce.bpf.o alive.bpf.o
	sudo setcap cap_bpf,cap_perfmon+ep ./pin
	sh spike3.sh

clean:
	rm -f probe probe.bpf.o enforce enforce.bpf.o pin alive.bpf.o vmlinux.h

.PHONY: all run run2 run3 clean
