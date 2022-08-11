#ifndef BPF_IPV4_FRAGMENT_H
#define BPF_IPV4_FRAGMENT_H

#define REDIRECT_IP4_FLAG   0x8000
#define PART_REDIRECT_IP4_FLAG   0x4000

/* The `frag_off` portion of the header consists of:
 *
 * +----+----+----+----------------------------------------------------+
 * | RS | DF | MF | ...13 bits of fragment offset of current packet... |
 * +----+----+----+----------------------------------------------------+
 *
 * RS - Reserved
 * DF - Don't fragment
 * MF - More fragments
 * If "More fragments" or the offset is nonzero, then this is an IP
 * fragment (RFC791).
 *
 * The `frag_off` portion of the header in fragment map has another description
 * and consists of:
 * +----+----+----+----------------------------------------------------+
 * | RH | RP | MF | ...13 bits of fragment offset for next fragment... |
 * +----+----+----+----------------------------------------------------+
 *
 * RH - Redirect happened
 * RP - Redirected partially
 * MF - More fragments
 * The `check` portion of the header in fragment map use as length of not sended bytes 
 */

static __always_inline int ipv4_is_fragment(const struct iphdr *ip4)
{
	return !(ip4->frag_off & htons(0x4000));
}

static __always_inline int ipv4_is_first_fragment(const struct iphdr *ip4)
{
	return !(ip4->frag_off & htons(0x1FFF));
}

static __always_inline int ipv4_more_fragments(struct iphdr *ip4)
{
	return ip4->frag_off & htons(0x2000);
}

static __always_inline int ipv4_frag_offset(const struct iphdr *ip4)
{
    return (htons(ip4->frag_off) & 0x1FFF) * 8;
}

static __always_inline int ipv4_is_redirected(const struct iphdr *ip4)
{
    return ip4->frag_off & htons(REDIRECT_IP4_FLAG);
}

static __always_inline int ipv4_is_redirect_partially(const struct iphdr *ip4)
{
    return !ipv4_is_fragment(ip4);
}

static __always_inline __u16 ipv4_csum(void *data_start, int data_size,__u32 *csum) {
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    __u32 tmp = htonl(*csum);
    tmp = (tmp & 0xffff) + (tmp >> 16);
    if(htonl(tmp) > 0xffff)
       tmp = (tmp & 0xffff) + (tmp >> 16);
    return htons(~tmp);
}

static __always_inline int redirect_ip4_fragment(struct ebpf_context* ctx, struct __sk_buff* skb, __u16 if_index)
{
    struct Config* cfg_ = bpf_map_lookup_elem(&BPF_CFG_MAP, &ctx->cur_info.node_id);
    if(!cfg_) return TC_ACT_OK;

    struct iphdr* prev_data = 0;
    __u16 mtu = cfg_->settings.interface.mtu;
    __u16 offset = 0, frag_offset = 0;
    __u16 absent_data_size = 0;
    __u32 skb_size = skb->len - sizeof(struct ethhdr);
#pragma clang loop unroll(full)
    for(int i = 0; i < MAX_FRAGMENTS; i++) {
        struct fragment_data fd = {.id = ctx->cur_id, .offset = offset};
        struct iphdr* data = bpf_map_lookup_elem(&BPF_FRAG_DATA_MAP, &fd);
        if(!data) break;
        offset += htons(data->tot_len) - sizeof(struct iphdr);

        if(ipv4_is_redirected(data)) continue;
        if(ipv4_is_redirect_partially(data)) {
            absent_data_size = data->check;
            prev_data = data;
            frag_offset += ipv4_frag_offset(data);
            continue;
        }

        char* buf_pos = ctx->buffer;
        bpf_probe_read_kernel(buf_pos, sizeof(struct iphdr), data);
        buf_pos += sizeof(struct iphdr);
        if(prev_data) {
            absent_data_size &= MASK_MTU;
            bpf_probe_read_kernel(buf_pos, absent_data_size, prev_data + 1);
            buf_pos += absent_data_size;
            prev_data->frag_off |= htons(REDIRECT_IP4_FLAG);
            prev_data->check = 0;
        }
        if(data->check > 0) {
            __u16 newlen = 0;
            __u32 totlen = 0;
            __u16 packet_size = data->check + sizeof(struct iphdr) + absent_data_size;
            __u8 dofrag = packet_size > mtu;
            __u16 len_diff = 0;

            if(dofrag) {
                len_diff = packet_size - mtu;

                newlen = data->check + absent_data_size - len_diff;
                newlen &= MASK_MTU;
                totlen = newlen + sizeof(struct iphdr);
                bpf_probe_read_kernel(buf_pos, newlen, data+1);
                buf_pos += newlen;
            } else {
                data->check &= MASK_MTU;
                bpf_probe_read_kernel(buf_pos, data->check, data+1);
                newlen = data->check + absent_data_size;
                newlen &= MASK_MTU;
                totlen = newlen + sizeof(struct iphdr);
            }

            struct iphdr* ipbuf = (struct iphdr*)ctx->buffer;
            ipbuf->tot_len = htons(totlen);
            ipbuf->frag_off = dofrag ? htons(0x2000) : ipv4_more_fragments(ipbuf);
            ipbuf->frag_off |= htons(frag_offset/8);
            __u32 csum = 0;
            ipbuf->check = 0;
            ipbuf->check = ipv4_csum(ipbuf, sizeof(struct iphdr), &csum);
            frag_offset += newlen;
            data->frag_off = ipv4_more_fragments(data);
            data->frag_off |= htons(frag_offset/8);
            if(dofrag) {
                data->frag_off |= htons(PART_REDIRECT_IP4_FLAG);
                data->check = len_diff;
            } else { 
                data->frag_off |= htons(REDIRECT_IP4_FLAG);
                data->check = 0;
            }

            if(skb_size != totlen) {
                int diff = totlen - skb_size;
                bpf_skb_adjust_room(skb, diff, BPF_ADJ_ROOM_MAC, 0);
                skb_size = skb->len - sizeof(struct ethhdr);
            }
            bpf_skb_store_bytes(skb, sizeof(struct ethhdr), ctx->buffer, totlen, 0);
            bpf_clone_redirect(skb, if_index, 0);

            if(dofrag) {
                __u32 off = totlen - absent_data_size;
                char* ldata = (char*)data + off;
                bpf_probe_read_kernel(ctx->buffer, MTU, ldata);
                bpf_probe_read_kernel(data+1, MTU - sizeof(struct iphdr), ctx->buffer);

                absent_data_size = data->check;
                prev_data = data;
            } else {
                absent_data_size = 0;
                prev_data = 0;
            }
        }

        if(!ipv4_more_fragments(data) && !ipv4_is_redirected(data)) {
            buf_pos = ctx->buffer;
            bpf_probe_read_kernel(buf_pos, sizeof(struct iphdr), data);
            buf_pos += sizeof(struct iphdr);
            if(prev_data) {
                absent_data_size &= MASK_MTU;
                bpf_probe_read_kernel(buf_pos, absent_data_size, prev_data + 1);
                buf_pos += absent_data_size;
                prev_data->frag_off |= htons(REDIRECT_IP4_FLAG);
                prev_data->check = 0;
            }

            __u32 totlen = absent_data_size + sizeof(struct iphdr);
            struct iphdr* ipbuf = (struct iphdr*)ctx->buffer;
            ipbuf->frag_off = htons(frag_offset/8);
            ipbuf->tot_len = htons(totlen);
            __u32 csum = 0;
            ipbuf->check = 0;
            ipbuf->check = ipv4_csum(ipbuf, sizeof(struct iphdr), &csum);

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

static __always_inline int check_in_maps_ip4_fragment(struct ebpf_context* ctx, struct __sk_buff *skb, const struct iphdr* ip4)
{
    ctx->cur_frag.id = ip4->id;
    ctx->cur_frag.offset = ipv4_frag_offset(ip4);
    ctx->cur_id = ip4->id;
    ctx->payload_size = htons(ip4->tot_len) - sizeof(struct iphdr);
    struct fragment_info* info = bpf_map_lookup_elem(&BPF_FRAG_INFO_MAP, &ctx->cur_id);
    if(!info) {
        memset(&ctx->cur_info, 0, sizeof(ctx->cur_info));
        bpf_map_update_elem(&BPF_FRAG_INFO_MAP, &ctx->cur_id, &ctx->cur_info, BPF_ANY);
    } else {
        ctx->cur_info = *info;
    }

    bpf_probe_read_kernel(ctx->buffer, MTU, ip4);
    struct iphdr *ipbuf = (struct iphdr *)ctx->buffer;
    // clear redirect flag and set redirected size
    ipbuf->check = htons(ipbuf->tot_len) - sizeof(struct iphdr);
    ipbuf->frag_off &= htons(~(REDIRECT_IP4_FLAG|PART_REDIRECT_IP4_FLAG));
    bpf_map_update_elem(&BPF_FRAG_DATA_MAP, &ctx->cur_frag, ctx->buffer, BPF_ANY);
    if(ipv4_is_first_fragment(ip4) || !ipv4_frag_offset(ip4)) return TC_ACT_OK;
    if(!ctx->cur_info.checked) {
        return TC_ACT_SHOT;
    }

    ctx->state = IPv4_REDIRECT_STATE;
    ctx->is_fragment = 1;
    return TC_ACT_UNSPEC;
}

#endif/*BPF_IPV4_FRAGMENT_H*/
