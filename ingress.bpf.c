#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#ifndef PASS_ONLY
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packets SEC(".maps");

static __always_inline void count_packet(void)
{
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&packets, &key);

    if (count)
        (*count)++;
}
#endif

SEC("xdp")
int count_xdp(struct xdp_md *ctx)
{
#ifndef PASS_ONLY
    count_packet();
#endif
    return XDP_PASS;
}

SEC("classifier")
int count_tc(struct __sk_buff *skb)
{
#ifndef PASS_ONLY
    count_packet();
#endif
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
