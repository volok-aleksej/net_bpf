#ifndef BPF_IPV6_FRAGMENT_H
#define BPF_IPV6_FRAGMENT_H

#define REDIRECT_IP6_FLAG   0x4
#define PART_REDIRECT_IP6_FLAG   0x2

#define CHECK_SIZE(data) \
    if(data > 0x3ff) data &= 0x5ff; \
    else data &= 0x3ff;

/* The `fragment` header consists of:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Header  |   Reserved    |    Fragment Offset   |  RS |MF|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Identification                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * RS - Reserved
 * MF - More fragments
 * Fragment Offset - 13 bits of fragment offset of current fragment
 * (RFC2460).
 * 
 * The `fragment` header in fragment map has another description
 * and consists of:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Next Header  |   Reserved    |    Fragment Offset   |RH|RP|MF|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Remain Size           |         Payload size          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * RH - Redirect happened
 * RP - Redirected partially
 * MF - More fragments
 * Fragment Offset - 13 bits of fragment offset of next fragment
 * Payload size has network byte order.
 * Remain Size has host byte order
 */

struct ipv6_redirect_info_hdr {
    struct ipv6_opt_hdr opt;
    __u16 frag_data;
    __u16 remain_size;
    __u16 payload_size;
};

struct ipv6_fragment_hdr {
     struct ipv6_opt_hdr opt;
     __u16 frag_data;
     __s32 id;
};

static __always_inline int ipv6_is_first_fragment(const struct ipv6_fragment_hdr *ipfrag)
{
	return !(ipfrag->frag_data & htons(0xfff8));
}

static __always_inline int ipv6_more_fragments(const struct ipv6_fragment_hdr *ipfrag)
{
	return ipfrag->frag_data & htons(0x1);
}

static __always_inline int ipv6_frag_offset(const struct ipv6_fragment_hdr* ipfrag)
{
    return (htons(ipfrag->frag_data)>>3) * 8;
}

static __always_inline int ipv6_is_redirected(const struct ipv6_fragment_hdr *ipfrag)
{
    return ipfrag->frag_data & htons(REDIRECT_IP6_FLAG);
}

static __always_inline int ipv6_is_redirect_partially(const struct ipv6_fragment_hdr *ipfrag)
{
    return ipfrag->frag_data & htons(PART_REDIRECT_IP6_FLAG);
}

static __always_inline int redirect_ip6_fragment(struct ebpf_context* ctx, struct __sk_buff* skb, __u16 if_index)
{
    struct Config* cfg_ = bpf_map_lookup_elem(&BPF_CFG_MAP, &ctx->cur_info.node_id);
    if(!cfg_) return TC_ACT_OK;

    struct ipv6hdr* prev_data = 0;
    __u16 prev_frag_offset = 0;
    __u16 mtu = cfg_->settings.interface.mtu;
    __u16 offset = 0, frag_offset = 0;
    __u16 absent_data_size = 0;
    __u32 skb_size = skb->len - sizeof(struct ethhdr);
#pragma clang loop unroll(full)
    for(int i = 0; i < MAX_FRAGMENTS; i++) {
        struct fragment_data fd = {.id = ctx->cur_id, .offset = offset};
        struct ipv6hdr* data = bpf_map_lookup_elem(&BPF_FRAG_DATA_MAP, &fd);
        if(!data) break;

        bpf_probe_read_kernel(ctx->buffer, MTU, data);
        struct ipv6hdr* ipv6 = (struct ipv6hdr*)ctx->buffer;
       
        __u16 ipfragoff = ipv6->payload_len;
        if(ipfragoff < sizeof(*ipv6)) break;
        ipfragoff &= MASK_MTU;

        struct ipv6_fragment_hdr* ip_frag = (struct ipv6_fragment_hdr*)((char*)ipv6 + ipfragoff);
        struct ipv6_redirect_info_hdr* ip_rdr_info = (struct ipv6_redirect_info_hdr*)ip_frag;
        __u16 ext_hdr_size = ipfragoff - sizeof(struct ipv6hdr) + sizeof(struct ipv6_redirect_info_hdr);
        offset += ip_rdr_info->payload_size - ext_hdr_size;

        if(ipv6_is_redirected(ip_frag)) continue;
        if(ipv6_is_redirect_partially(ip_frag)) {
            absent_data_size = ip_rdr_info->remain_size;
            prev_data = data;
            prev_frag_offset = ipfragoff;
            frag_offset += ipv6_frag_offset(ip_frag);
            continue;
        }
 
        int more_fragment = ipv6_more_fragments(ip_frag);
        if(prev_data) {
            bpf_probe_read_kernel(ctx->buffer, MTU, prev_data);
            struct ipv6_redirect_info_hdr* prev_rdr_info = (struct ipv6_redirect_info_hdr*)(ctx->buffer + prev_frag_offset);
            prev_rdr_info->frag_data |= htons(REDIRECT_IP6_FLAG);
            prev_rdr_info->remain_size = 0;
            bpf_probe_read_kernel(prev_data, MTU, ctx->buffer);
            bpf_probe_read_kernel(ctx->buffer, MTU, data);
        }
        char* buf_pos = ctx->buffer;
        bpf_probe_read_kernel(data, MTU, buf_pos);
        buf_pos += ipfragoff + sizeof(struct ipv6_fragment_hdr);

        if(prev_data) {
            absent_data_size &= MASK_MTU;
            bpf_probe_read_kernel(ctx->buffer + MTU, MTU, buf_pos);
            bpf_probe_read_kernel(buf_pos, absent_data_size, (char*)prev_data + prev_frag_offset + sizeof(struct ipv6_fragment_hdr));
            buf_pos += absent_data_size;
            bpf_probe_read_kernel(buf_pos, MTU, ctx->buffer + MTU);
        }
        if(ip_rdr_info->remain_size > 0) {
            __u16 newlen = 0;
            __u32 totlen = 0;
            __u16 packet_size = ip_rdr_info->remain_size + ipfragoff + sizeof(struct ipv6_fragment_hdr) + absent_data_size;
            __u8 dofrag = packet_size > mtu;
            __u16 len_diff = 0;

            if(dofrag) {
                len_diff = packet_size - mtu;
                newlen = ip_rdr_info->remain_size + absent_data_size - len_diff;
                __u8 rem_div = newlen%8;
                newlen -= rem_div;
                len_diff += rem_div;
                CHECK_SIZE(newlen);
                bpf_probe_read_kernel(buf_pos, newlen, ip_frag+1);
                buf_pos += newlen;
            } else {
                newlen = ip_rdr_info->remain_size + absent_data_size;
                newlen &= MASK_MTU;
            }
            totlen = newlen + ipfragoff + sizeof(struct ipv6_fragment_hdr);
            __u16 oldoffset = frag_offset;
            frag_offset += newlen;
            
            ip_frag->frag_data = htons((newlen/8)<<3);
            if(dofrag) {
                ip_frag->frag_data |= htons(PART_REDIRECT_IP6_FLAG | 1);
                ip_rdr_info->remain_size = len_diff;
            } else {
                ip_frag->frag_data |= htons(REDIRECT_IP6_FLAG);
                ip_rdr_info->remain_size = 0;
            }
            bpf_probe_read_kernel(data, MTU, ctx->buffer);

            ip_frag->frag_data = ipv6_more_fragments(ip_frag);
            ip_frag->frag_data |= htons((oldoffset/8)<<3);
            ipv6->payload_len = htons(totlen - sizeof(struct ipv6hdr));
            ip_frag->id = ctx->cur_id;
            if(skb_size != totlen) {
                int diff = totlen - skb_size;
                bpf_skb_adjust_room(skb, diff, BPF_ADJ_ROOM_MAC, 0);
                skb_size = skb->len - sizeof(struct ethhdr);
            }
            if(!totlen) totlen = 1;
            bpf_skb_store_bytes(skb, sizeof(struct ethhdr), ctx->buffer, totlen, 0);
            bpf_clone_redirect(skb, if_index, 0);

            bpf_probe_read_kernel(ctx->buffer, MTU, data);
            if(dofrag) {
                __u32 off = totlen - absent_data_size;
                char* ldata = (char*)data + off;
                bpf_probe_read_kernel(ctx->buffer + ipfragoff + sizeof(struct ipv6_fragment_hdr), MTU, ldata);
                bpf_probe_read_kernel(data, MTU, ctx->buffer);

                absent_data_size = len_diff;
                prev_data = data;
                prev_frag_offset = ipfragoff;
            } else {
                prev_data = 0;
                prev_frag_offset = 0;
            }
        }

        if(!more_fragment && !ipv6_is_redirected(ip_frag)) {
            if(prev_data) {
                ip_frag->frag_data |= htons(REDIRECT_IP6_FLAG);
                ip_rdr_info->remain_size = 0;
            }

            absent_data_size &= MASK_MTU;
            __u32 totlen = absent_data_size + ipfragoff + sizeof(struct ipv6_fragment_hdr);
            ip_frag->frag_data = htons((frag_offset/8)<<3);
            ip_rdr_info->payload_size = totlen - sizeof(struct ipv6hdr);
            ip_rdr_info->remain_size = 0;
            bpf_probe_read_kernel(data, MTU, buf_pos);
            ipv6->payload_len = htons(totlen - sizeof(struct ipv6hdr));
            ip_frag->id = ctx->cur_id;

            if(skb_size != totlen) {
                int diff = totlen - skb_size;
                bpf_skb_adjust_room(skb, diff, BPF_ADJ_ROOM_MAC, 0);
                skb_size = skb->len - sizeof(struct ethhdr);
            }
            if(!totlen) totlen = 1;
            bpf_skb_store_bytes(skb, sizeof(struct ethhdr), ctx->buffer, totlen, 0);
            bpf_clone_redirect(skb, if_index, 0);
            absent_data_size = 0;
            break;
        }
    }
    return TC_ACT_REDIRECT;
}

/*
 * If the not fragmented packet has to fragment, added a fragment header.
 * If the packet with added a fragment header more than MAX_FRAGMENTED_SIZE created 2 fragments are added in fragment map.
 * ipfrag == 0 - is a case of the packet is not fragmented
 * MAX_FRAGMENTED_SIZE = MTU - (MTU-sizeof(struct ipv6hdr))%8 + sizeof(struct ethhdr)
 */
static __always_inline int check_in_maps_ip6_fragment(struct ebpf_context* ctx, struct __sk_buff *skb, const struct ipv6_fragment_hdr* ipfrag)
{
     if(!ipfrag) {
        ctx->cur_id = bpf_get_prandom_u32();
        ctx->cur_frag.id = ctx->cur_id;
        ctx->cur_frag.offset = 0;
     } else {
        ctx->cur_id = ipfrag->id;
        ctx->cur_frag.id = ipfrag->id;
        ctx->cur_frag.offset = ipv6_frag_offset(ipfrag);
     }

     struct fragment_info* info = bpf_map_lookup_elem(&BPF_FRAG_INFO_MAP, &ctx->cur_id);
     if(!info) {
         memset(&ctx->cur_info, 0, sizeof(ctx->cur_info));
         bpf_map_update_elem(&BPF_FRAG_INFO_MAP, &ctx->cur_id, &ctx->cur_info, BPF_ANY);
     } else {
         ctx->cur_info = *info;
     }

     __u8 cur_proto = 0;
     __u32 off = sizeof(struct ethhdr);
     CHECK_CTX_DATA(skb, struct ipv6hdr*, ipv6);
    __u16 ipv6maxlen = MTU - sizeof(struct ipv6hdr);
    ipv6maxlen -= ipv6maxlen%8;
    __u8 need_new_frag = !ipfrag && htons(ipv6->payload_len) + sizeof(struct ipv6_redirect_info_hdr) > ipv6maxlen;
    __u16 payload_len = htons(ipv6->payload_len);
     char* buf_pos = ctx->buffer;
     bpf_probe_read_kernel(buf_pos, MTU, ipv6);
     ipv6 = (struct ipv6hdr*)ctx->buffer;
     if(!ipfrag) {
        if(need_new_frag) ipv6->payload_len = htons(ipv6maxlen);
        if(ctx->last_hdr_off == sizeof(struct ethhdr)) {
            cur_proto = ipv6->nexthdr;
            ipv6->nexthdr = IPPROTO_FRAGMENT;
        } else {
            off = ctx->last_hdr_off&MASK_MTU;
            struct ipv6_opt_hdr* exthdr = (struct ipv6_opt_hdr*)(ctx->buffer + off - sizeof(struct ethhdr));
            cur_proto = exthdr->nexthdr;
            exthdr->nexthdr = IPPROTO_FRAGMENT;
        }
     }
     __u32 off_ = ctx->frag_off&MASK_MTU;
     buf_pos += (off_ - sizeof(struct ethhdr))&MASK_MTU;
     struct ipv6_redirect_info_hdr* ipv6_rdi_hdr = (struct ipv6_redirect_info_hdr*)buf_pos;
    __u16 frag_offset = ((char*)ipv6_rdi_hdr - ctx->buffer) - sizeof(struct ipv6hdr);
     __u16 data_offset = frag_offset + sizeof(struct ipv6_fragment_hdr);
     if(ipfrag) {
        bpf_probe_read_kernel(buf_pos, sizeof(struct ipv6_fragment_hdr), ipfrag);
        buf_pos += sizeof(struct ipv6_fragment_hdr);
        bpf_probe_read_kernel(buf_pos, MTU, (void*)(ipfrag + 1));
     } else {
        struct ipv6_redirect_info_hdr new_hdr = {0};
        new_hdr.opt.nexthdr = cur_proto;
        bpf_probe_read_kernel(buf_pos, sizeof(struct ipv6_redirect_info_hdr), &new_hdr);
        if(need_new_frag) ipv6_rdi_hdr->frag_data = htons(1);
        else ipv6_rdi_hdr->frag_data &= htons(~1);
        buf_pos += sizeof(struct ipv6_redirect_info_hdr);
        bpf_probe_read_kernel(buf_pos, MTU, (void*)(long)skb->data + off_);
        if(!need_new_frag) data_offset -= sizeof(struct ipv6_fragment_hdr);
     }

     // clear redirect flag and set remain size
     ipv6_rdi_hdr->remain_size = htons(ipv6->payload_len) - data_offset;
     ipv6_rdi_hdr->frag_data &= htons(~(REDIRECT_IP6_FLAG|PART_REDIRECT_IP6_FLAG));
     ipv6_rdi_hdr->payload_size = htons(ipv6->payload_len);
     struct ipv6hdr* ipv6buf = (struct ipv6hdr*)ctx->buffer;
     ipv6buf->payload_len = off_ - sizeof(struct ethhdr);
     ctx->payload_size = ipv6_rdi_hdr->remain_size;

     bpf_map_update_elem(&BPF_FRAG_DATA_MAP, &ctx->cur_frag, ctx->buffer, BPF_ANY);
     // create additional element in frag map
     if(need_new_frag) {
        struct fragment_data last_frag = ctx->cur_frag;
        last_frag.offset = ipv6_rdi_hdr->remain_size;
        ipv6_rdi_hdr->payload_size = payload_len - last_frag.offset + sizeof(struct ipv6_fragment_hdr);
        ipv6_rdi_hdr->remain_size = payload_len - frag_offset - last_frag.offset;
        ipv6_rdi_hdr->frag_data &= htons(~1);
        ipv6_rdi_hdr->frag_data |= htons((last_frag.offset/8)<<3);
        bpf_probe_read_kernel(ipv6_rdi_hdr + 1, MTU, (char*)(ipv6_rdi_hdr + 1) + last_frag.offset);
        bpf_map_update_elem(&BPF_FRAG_DATA_MAP, &last_frag, ctx->buffer, BPF_ANY);
     }

     if(!ipfrag || ipv6_is_first_fragment(ipfrag) || !ipv6_frag_offset(ipfrag)) return TC_ACT_OK;
     if(!ctx->cur_info.checked) {
         return TC_ACT_SHOT;
     }

     ctx->state = IPv6_REDIRECT_STATE;
     ctx->is_fragment = 1;
     return TC_ACT_UNSPEC;
}

#endif/*BPF_IPV6_FRAGMENT_H*/
