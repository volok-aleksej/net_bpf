#ifndef NETLINK_UTILS_H
#define NETLINK_UTILS_H

#include <linux/types.h>

//return 0 if netlink inited
// return > 0 if error occured
uint32_t init_netlink();
void close_netlink();

//return 0 if filter removed
// return > 0 if error occured
uint32_t remove_netlink_filters(__u16 if_index);
//return 0 if filter added
// return > 0 if error occured
uint32_t add_netlink_filter(__u16 if_index, __u32 prog_id, char* prog_name, int prog_name_len);

// return 0 if not found ingress filter
// return < 0 if error occured
// return > 0(bpf_id) if found bpf ingress filter
int get_filter_id(__u16 if_index);

// return 0 if not found clsact qdisk
// return < 0 if error occured
// return 1 if found clsact qdisk
int getqdisk_id(__u16 if_index);

struct tunnel_info
{
    int family;
    int mtu;
};
// return 0 if it is not tunnel(gre) interface
// return < 0 if error occured
// return 1 if link of tunnel up
int get_tunnel_info(__u16 if_index, struct tunnel_info& info);

#endif/*NETLINK_UTILS_H*/
