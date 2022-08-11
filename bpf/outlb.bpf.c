#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define memset __builtin_memset

// see rfc 2460
// https://datatracker.ietf.org/doc/html/rfc2460#section-4.1
#define MAX_IP6_EXT_HDR 9

#define CHECK_CTX_DATA(CTX, TYPE, DATA)  \
    void *data = (void*)(long)CTX->data + off;\
    void *data_end = (void*)(long)CTX->data_end;\
    TYPE DATA = data;\
    if ((void*)(DATA + 1) > data_end) \
        return TC_ACT_SHOT;
#define CHECK_COPY_CTX_DATA(CTX, TYPE, DATA)  \
    if ((void*)(long)CTX->data + off + sizeof(TYPE) > (void*)(long)CTX->data_end) \
        return TC_ACT_SHOT; \
    TYPE DATA;\
    bpf_probe_read_kernel(&DATA, sizeof(TYPE), (void*)(long)CTX->data + off)

#include "bpf_maps.h"
#include "bpf_ipv4_fragment.h"
#include "bpf_ipv6_fragment.h"

static __always_inline __u8 check_need_fragmentation(struct __sk_buff *skb, struct Config* cfg_)
{
    int tot_len = skb->len - sizeof(struct ethhdr);
    return tot_len > cfg_->settings.interface.mtu;
}

static __always_inline int process_ipv4_redirect(struct ebpf_context *ctx, struct __sk_buff *skb, struct Config* icfg, __u32 is_fragment, __u32 node_id)
{
    if(!is_fragment && check_need_fragmentation(skb, icfg)) {
        is_fragment = 1;
        int ret = TC_ACT_OK;
        __u32 off = sizeof(struct ethhdr);
        CHECK_CTX_DATA(skb, struct iphdr*, iph);
        ret = check_in_maps_ip4_fragment(ctx, skb, iph);
        if(ret != TC_ACT_OK)
            return ret;
    }
    ctx->state = IPv4_REDIRECT_STATE;
    ctx->is_fragment = is_fragment;
    if(!ctx->cur_info.checked) {
        ctx->cur_info.if_index = icfg->settings.interface.ifindex;
        ctx->cur_info.checked = 1;
        ctx->cur_info.node_id = node_id;
        bpf_map_update_elem(&BPF_FRAG_INFO_MAP, &ctx->cur_id, &ctx->cur_info, BPF_ANY);
    }
    return TC_ACT_UNSPEC;
}

static __always_inline int process_ipv6_redirect(struct ebpf_context *ctx, struct __sk_buff *skb, struct Config* icfg, __u32 is_fragment, __u32 node_id)
{
    if(!is_fragment && check_need_fragmentation(skb, icfg)) {
        is_fragment = 1;
        int ret = TC_ACT_OK;
        ret = check_in_maps_ip6_fragment(ctx, skb, 0);
        if(ret != TC_ACT_OK)
            return ret;
    }
    ctx->state = IPv6_REDIRECT_STATE;
    ctx->is_fragment = is_fragment;
    if(!ctx->cur_info.checked) {
        ctx->cur_info.if_index = icfg->settings.interface.ifindex;
        ctx->cur_info.checked = 1;
        ctx->cur_info.node_id = node_id;
        bpf_map_update_elem(&BPF_FRAG_INFO_MAP, &ctx->cur_id, &ctx->cur_info, BPF_ANY);
    }
    return TC_ACT_UNSPEC;
}

static __always_inline int process_tcpudp_packet(struct ebpf_context *ctx, struct __sk_buff *skb, __u16 off, __u8 protocol, struct Config** cfg_)
{
    __u16 port = 0;
    if(protocol == IPPROTO_UDP) {
        CHECK_COPY_CTX_DATA(skb, struct udphdr, udph);
        port = htons(udph.dest);
        ctx->payload_size -= sizeof(struct udphdr);
    } else if(protocol == IPPROTO_TCP) {
        CHECK_COPY_CTX_DATA(skb, struct tcphdr, tcph);
        port = htons(tcph.dest);
    }

    __u32 id = 0;
    struct Config *pcfg = bpf_map_lookup_elem(&BPF_CFG_MAP, &id);
    if(!pcfg || pcfg->type != CLUSTER_SETTINGS) {
        return TC_ACT_OK;
    }

#pragma clang loop unroll(full)
    for(int i = 0; i < MAX_INTERFACES && pcfg->settings.cluster.node_ids[i]; i++) {
        id = pcfg->settings.cluster.node_ids[i];
        struct Config* icfg = bpf_map_lookup_elem(&BPF_CFG_MAP, &id);
        if(!icfg || icfg->type != INTERFACE_SETTINGS) {
            return TC_ACT_OK;
        }

        if((protocol == IPPROTO_UDP && 
            port >= icfg->settings.interface.udp_range_min &&
            port <= icfg->settings.interface.udp_range_max) ||
           (protocol == IPPROTO_TCP && 
            port >= icfg->settings.interface.tcp_range_min &&
            port <= icfg->settings.interface.tcp_range_max)) {
                *cfg_ = icfg;
                ctx->cur_info.node_id = id;
                return TC_ACT_REDIRECT;
        }
    }

    return TC_ACT_OK;
}

static __always_inline int process_ipv4_packet(struct ebpf_context *ctx, struct __sk_buff *skb, __u16 off)
{
    CHECK_CTX_DATA(skb, struct iphdr*, iph);
    // minimal size of ethernet packet is 60
    if ((htons(iph->tot_len) != data_end - data && data_end - data > 60) ||
        iph->ttl <= 1) {
        return TC_ACT_SHOT;
    }

    ctx->is_fragment = ipv4_is_fragment(iph);
    if(ctx->is_fragment) {
        int ret = check_in_maps_ip4_fragment(ctx, skb, iph);
        if(ret != TC_ACT_OK)
            return ret;
    }

    struct Config* cfg_ = 0;
    int ret = process_tcpudp_packet(ctx, skb, off + sizeof(struct iphdr), iph->protocol, &cfg_);
    if(ret == TC_ACT_REDIRECT) {
        return process_ipv4_redirect(ctx, skb, cfg_, ctx->is_fragment, ctx->cur_info.node_id);
    }
    return ret;
}

static __always_inline int process_ipv6_packet(struct ebpf_context *ctx, struct __sk_buff *skb, __u16 off)
{
    CHECK_CTX_DATA(skb, struct ipv6hdr*, ip6h);
    ctx->last_hdr_off = off;
    off += sizeof(struct ipv6hdr);
    if(htons(ip6h->payload_len) + sizeof(struct ipv6hdr) != data_end - data || ip6h->hop_limit <= 1)
        return TC_ACT_SHOT;

    __u8 next_proto = ip6h->nexthdr;
    for(int i= 0; i < MAX_IP6_EXT_HDR && off < data_end - data; i++) {
        if(next_proto == IPPROTO_FRAGMENT) {
            CHECK_CTX_DATA(skb, struct ipv6_fragment_hdr*, ipfrag);
            ctx->is_fragment = 1;
            ctx->frag_off = off;
            ctx->last_hdr_off = off;
            next_proto = ipfrag->opt.nexthdr;
             off += sizeof(struct ipv6_fragment_hdr);
            int ret = check_in_maps_ip6_fragment(ctx, skb, ipfrag);
            if(ret != TC_ACT_OK)
                return ret;
       } else  if(next_proto == IPPROTO_HOPOPTS ||
                  next_proto == IPPROTO_ROUTING ||
                  next_proto == IPPROTO_NONE ||
                  next_proto == IPPROTO_DSTOPTS ||
                  next_proto == IPPROTO_MH) {
            CHECK_CTX_DATA(skb, struct ipv6_opt_hdr*, exthdr);
            next_proto = exthdr->nexthdr;
            ctx->last_hdr_off = off;
            off += (exthdr->hdrlen + 1)*8;
         } else if(next_proto == IPPROTO_UDP ||
                   next_proto == IPPROTO_TCP) {
            ctx->frag_off = off;
            struct Config* cfg_ = 0;
            int ret = process_tcpudp_packet(ctx, skb, off, next_proto, &cfg_);
            if(ret == TC_ACT_REDIRECT)
                return process_ipv6_redirect(ctx, skb, cfg_, ctx->is_fragment,  ctx->cur_info.node_id);
            return ret;    
        } else {
            return TC_ACT_OK;
        }
    }

    return TC_ACT_OK;
}

static struct ebpf_context empty_ctx = {0};
static __u32 index = 0;

static __always_inline __u32 get_packet_index()
{
    __u32 id = 0;
    struct Config *pcfg = bpf_map_lookup_elem(&BPF_CFG_MAP, &id);
    if(!pcfg || pcfg->type != CLUSTER_SETTINGS) return 0;    
    if(pcfg->settings.cluster.is_unit_test) return 0;
    return index++;
}

SEC(BPF_IPv4_PROG_NAME)
int BPF_IPV4_FUNCTION(struct __sk_buff *skb)
{
    __u32 off = 0;
    CHECK_CTX_DATA(skb, struct ethhdr*, eth);
    __u32 eth_proto = htons(eth->h_proto);
    if (eth_proto == ETH_P_IP) {
        __u32 key = get_packet_index();
        skb->cb[0] = key;
        bpf_map_update_elem(&BPF_CONTEXT_MAP, &key, &empty_ctx, BPF_ANY);
        struct ebpf_context *ctx = bpf_map_lookup_elem(&BPF_CONTEXT_MAP, &key);
        if(!ctx) return TC_ACT_OK;
        return process_ipv4_packet(ctx, skb, sizeof(struct ethhdr));
    }
    return TC_ACT_UNSPEC;
}

SEC(BPF_IPv6_PROG_NAME)
int BPF_IPV6_FUNCTION(struct __sk_buff *skb)
{
    __u32 off = 0;
    CHECK_CTX_DATA(skb, struct ethhdr*, eth);
    __u32 eth_proto = htons(eth->h_proto);
    if (eth_proto == ETH_P_IPV6) {
        __u32 key = get_packet_index();
        skb->cb[0] = key;
        bpf_map_update_elem(&BPF_CONTEXT_MAP, &key, &empty_ctx, BPF_ANY);
        struct ebpf_context *ctx = bpf_map_lookup_elem(&BPF_CONTEXT_MAP, &key);
        if(!ctx) return TC_ACT_OK;
        return process_ipv6_packet(ctx, skb, sizeof(struct ethhdr));
    }
    return TC_ACT_UNSPEC;
}

SEC(BPF_IPv4_RDR_PROG_NAME)
int BPF_IPv4_RDR_FUNCTION(struct __sk_buff *skb)
{
    __u32 key = skb->cb[0];
    struct ebpf_context *ctx = bpf_map_lookup_elem(&BPF_CONTEXT_MAP, &key);
    if(!ctx) return TC_ACT_OK;

    if(ctx->state != IPv4_REDIRECT_STATE) {
        return TC_ACT_UNSPEC;
    }

    struct Config* cfg_ = bpf_map_lookup_elem(&BPF_CFG_MAP, &ctx->cur_info.node_id);
    if(!cfg_ || cfg_->type != INTERFACE_SETTINGS) {
        return TC_ACT_OK;
    }

    if(!ctx->is_fragment) {
       bpf_clone_redirect(skb, cfg_->settings.interface.ifindex, 0);
       return TC_ACT_REDIRECT;
    }

    return redirect_ip4_fragment(ctx, skb, ctx->cur_info.if_index);
}

SEC(BPF_IPv6_RDR_PROG_NAME)
int BPF_IPv6_RDR_FUNCTION(struct __sk_buff *skb)
{
    __u32 key = skb->cb[0];
    struct ebpf_context *ctx = bpf_map_lookup_elem(&BPF_CONTEXT_MAP, &key);
    if(!ctx) return TC_ACT_OK;

    if(ctx->state != IPv6_REDIRECT_STATE) {
        return TC_ACT_UNSPEC;
    }

    struct Config* cfg_ = bpf_map_lookup_elem(&BPF_CFG_MAP, &ctx->cur_info.node_id);
    if(!cfg_ || cfg_->type != INTERFACE_SETTINGS) {
        return TC_ACT_OK;
    }

    if(!ctx->is_fragment) {
       bpf_clone_redirect(skb, cfg_->settings.interface.ifindex, 0);
       return TC_ACT_REDIRECT;
    }

    return redirect_ip6_fragment(ctx, skb, ctx->cur_info.if_index);
}

char LICENSE[] SEC("license") = "GPL";
