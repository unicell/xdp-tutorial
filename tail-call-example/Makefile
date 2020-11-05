# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

CC := clang
CFLAGS := -g -O2 -Wall

PROGS := tail-call-example.o
.PHONY: all
all: $(PROGS)

tail-call-example.o: tail-call-example.c
	$(CC) $(CFLAGS) -target bpf -c -o $@ $<
	llvm-strip --no-strip-all -R .BTF $@

.PHONY: load
load:
	sudo ip link set dev lo xdp obj tail-call-example.o

.PHONY: unload
unload:
	sudo ip link set dev lo xdp off

.PHONY: show
show:
	sudo ip link show dev lo
	@echo
	sudo bpftool net list
	@echo
	mount | grep bpf
	sudo tree /sys/fs/bpf

.PHONY: update
update:
	tc exec bpf graft m:globals/jmp_map key 0 obj new.o sec foo

.PHONY: clean
clean:
	rm -f $(PROGS)
