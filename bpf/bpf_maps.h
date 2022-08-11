#ifndef BPF_MAPS_H
#define BPF_MAPS_H

#include "common/common.h"

/*
 *  external maps for cofigurations and logs
 */
struct bpf_map_def SEC("maps") BPF_CFG_MAP = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(int),
	.value_size	= sizeof(struct Config),
	.max_entries= 3
};

struct bpf_map_def SEC("maps") BPF_MONITOR_MAP = {
	.type		= BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size	= sizeof(int),
	.value_size	= sizeof(__u32),
	.max_entries= 128
};

/*
 *  developer maps
 */
#define MASK_MTU 0x7ff
#define LOG_BUFFER_SIZE 2048

#define FRAG_INFO_MAP_SIZE 1000
#define FRAG_DATA_MAP_SIZE FRAG_INFO_MAP_SIZE*(MAX_FRAGMENTS)

struct fragment_info
{
    __u8 checked;
    __u16 if_index;
    __u16 node_id;
};

struct fragment_data
{
    __s32 id;
    __u32 offset;
};

struct ebpf_context
{
    // for ipv6
    __u32 frag_off; // offset of ipv6 fragment header
    __u32 last_hdr_off; // offset of header before ipv6 header or ipv6 fragment header
    //for sip
    __u32 payload_size;
    // common data
    enum {
        DEFAULT_STATE = 0,
        IPv4_REDIRECT_STATE,
        IPv6_REDIRECT_STATE
    } state;
    __u32 is_fragment;
    struct fragment_data cur_frag;
    struct fragment_info cur_info;
    __s32 cur_id; // packet id;
    char buffer[4*MTU];
};

struct bpf_map_def SEC("maps") BPF_CONTEXT_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.key_size	= sizeof(__u32),
	.value_size	= sizeof(struct ebpf_context),
	.max_entries= FRAG_INFO_MAP_SIZE
};

//id -> fragment_info
struct bpf_map_def SEC("maps") BPF_FRAG_INFO_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.key_size	= sizeof(int),
	.value_size	= sizeof(struct fragment_info),
	.max_entries= FRAG_INFO_MAP_SIZE
};

struct bpf_map_def SEC("maps") BPF_FRAG_DATA_MAP = {
	.type		= BPF_MAP_TYPE_LRU_HASH,
	.key_size	= sizeof(struct fragment_data),
	.value_size	= MTU,
	.max_entries= FRAG_DATA_MAP_SIZE
};

#endif/*BPF_MAPS_H*/
