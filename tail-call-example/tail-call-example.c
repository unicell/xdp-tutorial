#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>

#ifndef __stringify
# define __stringify(X)   #X
#endif

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)          \
   __section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
   (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif

#define BPF_JMP_MAP_ID   1

static void BPF_FUNC(tail_call, struct __sk_buff *skb, void *map,
                     uint32_t index);

static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

struct bpf_elf_map jmp_map __section("maps") = {
    .type           = BPF_MAP_TYPE_PROG_ARRAY,
    .id             = BPF_JMP_MAP_ID,
    .size_key       = sizeof(uint32_t),
    .size_value     = sizeof(uint32_t),
    .pinning        = PIN_GLOBAL_NS,
    .max_elem       = 1,
};

__section_tail(JMP_MAP_ID, 0)
int looper(struct __sk_buff *skb)
{
    printk("skb cb: %u\n", skb->cb[0]++);
    tail_call(skb, &jmp_map, 0);
    return TC_ACT_OK;
}

__section("prog")
int entry(struct __sk_buff *skb)
{
    skb->cb[0] = 0;
    tail_call(skb, &jmp_map, 0);
    return TC_ACT_OK;
}

char __license[] __section("license") = "GPL";
