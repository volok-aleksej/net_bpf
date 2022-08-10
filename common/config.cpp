#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/ip.h>
#include <linux/ipv6.h>

#include "common.h"
#include "config.h"
#include "net_cfg.h"
#include "common/netlink_utils.h"
#include "bpf_helpers.h"

#define GRE_HEADER_SIZE 4
#define GRE_IPV4_MTU MTU-sizeof(struct iphdr)-GRE_HEADER_SIZE

int configure_bpf(int config_map_fd, const char* config_path, bool unit_test)
{
    cfg_t* m_cfg = cfg_init(opt, 0);
    switch(cfg_parse(m_cfg, config_path)) {
    case CFG_SUCCESS:
        break;
    case CFG_FILE_ERROR:
        printf("failed to open configuration file: %s (%s)\n",
            config_path, strerror(errno));
        return ENOENT;
    case CFG_PARSE_ERROR:
        printf("failed to parse configuration file: %s\n", config_path);
        return ENODATA;
    default:
        printf("got unexpected error on configuration file processing: %s\n", config_path);
        return 1;
    }

    Config cfg;
    memset(&cfg, 0, sizeof(cfg));
    int node_id = 0;
    cfg.type = Config::CLUSTER_SETTINGS;
    Config cfgi[MAX_INTERFACES];
    int node_ids[MAX_INTERFACES];
    for(int i = 0; i < cfg_size(m_cfg, SECTION_INTERFACE_NAME) && i < MAX_INTERFACES; i++) {
        cfg_t* intr = cfg_getnsec(m_cfg, SECTION_INTERFACE_NAME, i);
        node_ids[i] = cfg_getint(intr, PARAM_NODE_ID_NAME);
        cfg.settings.cluster.node_ids[i] = node_ids[i];
        if(cfg_size(intr, PARAM_UDP_RANGE_NAME) != 2 ||
           cfg_size(intr, PARAM_TCP_RANGE_NAME) != 2) {
            printf("incorrect range in interface %s: parameters have to be 2 {min, max}\n", intr->title);
            cfg_free(m_cfg);
            return EINVAL;
        }

        struct tunnel_info info;
        if(!unit_test && get_tunnel_info(cfg_getint(intr, PARAM_IFINDEX_ID_NAME), info) <= 0) {
            printf("incorrect index of interface %s: interface is not gre\n", intr->title);
            return EINVAL;
        }

        cfgi[i].type = Config::INTERFACE_SETTINGS;
        cfgi[i].settings.interface.ifindex = cfg_getint(intr, PARAM_IFINDEX_ID_NAME);
        cfgi[i].settings.interface.mtu = unit_test ? GRE_IPV4_MTU : info.mtu;
        cfgi[i].settings.interface.udp_range_min = cfg_getnint(intr, PARAM_UDP_RANGE_NAME, 0);
        cfgi[i].settings.interface.udp_range_max = cfg_getnint(intr, PARAM_UDP_RANGE_NAME, 1);
        cfgi[i].settings.interface.tcp_range_min = cfg_getnint(intr, PARAM_TCP_RANGE_NAME, 0);
        cfgi[i].settings.interface.tcp_range_max = cfg_getnint(intr, PARAM_TCP_RANGE_NAME, 1);
        if(cfgi[i].settings.interface.udp_range_min > cfgi[i].settings.interface.udp_range_max ||
           cfgi[i].settings.interface.tcp_range_min > cfgi[i].settings.interface.tcp_range_max) {
            printf("incorrect range in interface %s: minimal value > maximum value\n", intr->title);
            cfg_free(m_cfg);
            return EINVAL;
        }
        for(int j  = 0; j < i; j++) {
            if((cfgi[j].settings.interface.udp_range_min <= cfgi[i].settings.interface.udp_range_max &&
                cfgi[j].settings.interface.udp_range_min >= cfgi[i].settings.interface.udp_range_min) ||
               (cfgi[j].settings.interface.udp_range_max <= cfgi[i].settings.interface.udp_range_max &&
                cfgi[j].settings.interface.udp_range_max >= cfgi[i].settings.interface.udp_range_min)) {
                   printf("incorrect udp range in interface %s: ranges overlapped\n", intr->title);
                   cfg_free(m_cfg);
                   return EINVAL;
            }
            if((cfgi[j].settings.interface.tcp_range_min <= cfgi[i].settings.interface.tcp_range_max &&
                cfgi[j].settings.interface.tcp_range_min >= cfgi[i].settings.interface.tcp_range_min) ||
               (cfgi[j].settings.interface.tcp_range_max <= cfgi[i].settings.interface.tcp_range_max &&
                cfgi[j].settings.interface.tcp_range_max >= cfgi[i].settings.interface.tcp_range_min)) {
                   printf("incorrect tcp range in interface %s: ranges overlapped\n", intr->title);
                   cfg_free(m_cfg);
                   return EINVAL;
            }
        }
    }

    for(int i = 0; i < MAX_INTERFACES; i++) {
        bpf_map_update_elem(config_map_fd, &node_ids[i], &cfgi[i], 0);   
    }
    bpf_map_update_elem(config_map_fd, &node_id, &cfg, 0);
    cfg_free(m_cfg);
    return 0;
}
