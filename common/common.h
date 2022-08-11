#ifndef COMMON_H
#define COMMON_H

#include <limits.h>

#define xstr(s) str(s)
#define str(s) #s

#define MAX_INTERFACES  2
#define PROG_SIZE   4

#define BPF_IPV4_FUNCTION ipv4lb
#define BPF_IPV4_FUNC_NAME xstr(BPF_IPV4_FUNCTION)
#define BPF_IPv4_PROG_NAME "skb/" BPF_IPV4_FUNC_NAME

#define BPF_IPV6_FUNCTION ipv6lb
#define BPF_IPV6_FUNC_NAME xstr(BPF_IPV6_FUNCTION)
#define BPF_IPv6_PROG_NAME "skb/" BPF_IPV6_FUNC_NAME

#define BPF_IPv4_RDR_FUNCTION ipv4_redirect
#define BPF_IPv4_RDR_FUNC_NAME xstr(BPF_IPv4_RDR_FUNCTION)
#define BPF_IPv4_RDR_PROG_NAME "skb/" BPF_IPv4_RDR_FUNC_NAME

#define BPF_IPv6_RDR_FUNCTION ipv6_redirect
#define BPF_IPv6_RDR_FUNC_NAME xstr(BPF_IPv6_RDR_FUNCTION)
#define BPF_IPv6_RDR_PROG_NAME "skb/" BPF_IPv6_RDR_FUNC_NAME 

static const char bpfipv4_str[] = BPF_IPV4_FUNC_NAME;
static const char bpfipv6_str[] = BPF_IPV6_FUNC_NAME;
static const char bpfipv4rdr_str[] = BPF_IPv4_RDR_FUNC_NAME;
static const char bpfipv6rdr_str[] = BPF_IPv6_RDR_FUNC_NAME;

#define BPF_CFG_MAP cfg
#define BPF_CFG_MAP_NAME xstr(BPF_CFG_MAP)
#define BPF_CONTEXT_MAP    ctx_map
#define BPF_CONTEXT_MAP_NAME xstr(BPF_CONTEXT_MAP)
#define BPF_MONITOR_MAP log_ring_map
#define BPF_MON_MAP_NAME xstr(BPF_MONITOR_MAP)
#define BPF_FRAG_DATA_MAP  frag_data
#define BPF_FRAG_DATA_MAP_NAME xstr(BPF_FRAG_DATA_MAP)
#define BPF_FRAG_INFO_MAP  frag_info
#define BPF_FRAG_INFO_MAP_NAME xstr(BPF_FRAG_INFO_MAP)
#define BPF_PROG_MAP       prog_map
#define BPF_PROG_MAP_NAME xstr(BPF_PROG_MAP)

#define MTU 1500
// 65535/1500 = 43,69 ~ 44
// therefor `USHRT_MAX/MTU + 1`
#define MAX_FRAGMENTS USHRT_MAX/MTU + 1

// key value is node_id,
// where 0 is current settings
struct Config
{
    enum {
        CLUSTER_SETTINGS,
        INTERFACE_SETTINGS
    } type;
    union {
        struct {
            unsigned int ifindex;
            unsigned short udp_range_min;
            unsigned short udp_range_max;
            unsigned short tcp_range_min;
            unsigned short tcp_range_max;
            unsigned short mtu;
        } interface;
        struct {
            unsigned int   is_unit_test;
            unsigned int   node_ids[MAX_INTERFACES];
        } cluster;
    } settings;
};

struct LogData {
    enum {
        LOG_STRING,
        LOG_BINARY
    } type;
    char data[];
};

#endif/*COMMON_H*/
