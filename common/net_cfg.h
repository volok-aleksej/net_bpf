#ifndef NET_CFG_H
#define NET_CFG_H

#include <confuse.h>

#define SECTION_INTERFACE_NAME "interface"
#define PARAM_NODE_ID_NAME "node_id"
#define PARAM_IFINDEX_ID_NAME "if_index"
#define PARAM_UDP_RANGE_NAME "udp_range"
#define PARAM_TCP_RANGE_NAME "tcp_range"
#define PARAM_UDP_PORT_NAME "cluster_udp_port"
#define DEFAULT_UDP_PORT    5060

static cfg_opt_t interface[] = {
    CFG_INT(PARAM_IFINDEX_ID_NAME, 0, CFGF_NODEFAULT),
    CFG_INT(PARAM_NODE_ID_NAME, 0, CFGF_NODEFAULT),
    CFG_INT_LIST(PARAM_UDP_RANGE_NAME, 0, CFGF_NODEFAULT),
    CFG_INT_LIST(PARAM_TCP_RANGE_NAME, 0, CFGF_NODEFAULT),
    CFG_END()
};
static cfg_opt_t opt[] = {
    CFG_SEC(SECTION_INTERFACE_NAME, interface, CFGF_MULTI | CFGF_TITLE),
    CFG_END()
};

#endif/*NET_CFG_H*/
