# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

CC := clang
CFLAGS := -g -O2 -Wall

PROGS := xdp-example.o
.PHONY: all
all: $(PROGS)

# Stripping .BTF section for https://github.com/cilium/ebpf/issues/43
xdp-example.o: xdp-example.c
	$(CC) $(CFLAGS) -target bpf -c -o $@ $<
	llvm-strip --no-strip-all -R .BTF $@

.PHONY: load
load:
	sudo ip link set dev lo xdp obj xdp-example.o

.PHONY: unload
unload:
	sudo ip link set dev lo xdp off

.PHONY: show
show:
	sudo ip link show dev lo
	@echo
	sudo bpftool net list

.PHONY: clean
clean:
	rm -f $(PROGS)
