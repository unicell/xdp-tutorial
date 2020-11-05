# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

CC := clang
CFLAGS := -g -O2 -Wall

PROGS := tc-example.o
.PHONY: all
all: $(PROGS)

tc-example.o: tc-example.c
	$(CC) $(CFLAGS) -target bpf -c -o $@ $<
	llvm-strip --no-strip-all -R .BTF $@

.PHONY: load
load:
	sudo tc qdisc add dev lo clsact
	sudo tc filter add dev lo ingress bpf da obj tc-example.o sec ingress
	sudo tc filter add dev lo egress bpf da obj tc-example.o sec egress

.PHONY: unload
unload:
	sudo tc qdisc del dev lo clsact

.PHONY: show
show:
	sudo tc filter show dev lo ingress
	@echo
	sudo tc filter show dev lo egress
	@echo
	sudo bpftool net list
	@echo
	mount | grep bpf
	sudo tree /sys/fs/bpf

.PHONY: clean
clean:
	rm -f $(PROGS)
