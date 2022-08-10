#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <memory.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>

#include "common.h"
#include "netlink_utils.h"

static const char clsact_str[] = "clsact";
static const char gre_str[] = "gre";
static const char bpf_str[] = "bpf";
static int seq = 0;
static int sfd = 0;

static int create_socket()
{
    sfd=socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);
    int val = 32768;
    if(setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &val, 4)) return errno;
    val = 1048576;
    if(setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &val, 4)) return errno;
    val = 1;
    if(setsockopt(sfd, SOL_NETLINK, NETLINK_EXT_ACK, &val, 4)) return errno;
    sockaddr_nl addrnl = {0};
    addrnl.nl_family = AF_NETLINK;
    if(bind(sfd, (sockaddr*)&addrnl, sizeof(addrnl)))  return errno;
    return 0;
}

void close_netlink()
{
    if(sfd) close(sfd);
}

static char* get_netlink_response(int& datalen) {
	struct msghdr msgh = {0};
	struct iovec iov = {0};
    sockaddr_nl addrnl = {0};
    addrnl.nl_family = AF_NETLINK;
    msgh.msg_name = &addrnl;
    msgh.msg_namelen = sizeof(addrnl);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_flags = MSG_TRUNC;
    datalen = recvmsg(sfd, &msgh, MSG_PEEK | MSG_TRUNC);
    if(datalen <= 0) return 0;
    char* data = new char[datalen];
    if(recv(sfd, data, datalen, 0) <= 0) {
        delete[] data;
        return 0;
    }

    return data;
}

static int check_netlink_error(char* resp = 0)
{
    int datalen = 0, err;
    char* data = 0;
    bool shared = false;
    if(resp) {
        shared = true;
        data = resp;
    } else
        data = get_netlink_response(datalen);
    if(!data) return errno;

    struct nlmsghdr* hdr = (struct nlmsghdr*)data;
    if(hdr->nlmsg_type == NLMSG_DONE) err = 0;
    else if(hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr* msgerr = (struct nlmsgerr*)(hdr+1);
        err = msgerr->error;
        if(err < 0) printf("tc error: %d\n", err);
        struct nlattr* attr = (struct nlattr*)((char*)(&msgerr->msg) + msgerr->msg.nlmsg_len);
        while((char*)attr < data + hdr->nlmsg_len) {
            if(attr->nla_type == NLMSGERR_ATTR_MSG) {
                char* errstr = (char*)(attr+1);
                printf("%s\n", errstr);
            }
            attr = (struct nlattr*)((char*)attr + NLA_ALIGN(attr->nla_len));
        }
    } else {
        printf("WARN: not status message type\n");
        err = -EIO;
    }
    if(!shared)
        delete[] data;
    return err;
}

int getqdisk_id(__u16 if_index)
{
    struct {
        struct nlmsghdr hdr;
        struct tcmsg tc;
    } msg;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.nlmsg_len = sizeof(msg);
    msg.hdr.nlmsg_type = RTM_GETQDISC;
    msg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.hdr.nlmsg_seq = ++seq;
    msg.hdr.nlmsg_pid = getpid();
    msg.tc.tcm_family = AF_UNSPEC;
    msg.tc.tcm_ifindex = if_index;
    msg.tc.tcm_parent = 0;

    if(send(sfd, &msg, sizeof(msg), 0) < 0) return -errno;

    int datalen = 0;
    char *data = get_netlink_response(datalen), *databegin = data, *dataend = data + datalen;
    if(!data) return -errno;
    int ret = check_netlink_error();
    if(ret) return ret;

    while(data < dataend) {
        struct nlmsghdr* hdr = (struct nlmsghdr*)data;
        data += hdr->nlmsg_len;
        if(hdr->nlmsg_type != RTM_NEWQDISC) continue;

        struct tcmsg *tc = (struct tcmsg *)(hdr+1);
        if(tc->tcm_ifindex != if_index) continue;

        struct nlattr* attr = (struct nlattr*)(tc+1);
        while((char*)attr < data) {
            if(attr->nla_type == TCA_KIND) {
                char* kind = (char*)(attr+1);
                int kindlen = attr->nla_len - sizeof(struct nlattr);
                if(kindlen == sizeof(clsact_str) && strncmp(kind, clsact_str, kindlen) == 0) {
                    delete[] databegin;
                    return 1;
                }
            }
            attr = (struct nlattr*)((char*)attr + NLA_ALIGN(attr->nla_len));
        }
    }
    delete[] databegin;

    return 0;
}

uint32_t init_netlink()
{
    return create_socket();
}

uint32_t remove_netlink_filters(__u16 if_index)
{
    __u32 clsact_id = getqdisk_id(if_index);
    if(!clsact_id) {
            printf("Couldn't find clsact qdisc\n");
            return ENODEV;
    } else if(clsact_id < 0) {
        printf("socket error %d: %s\n", errno, strerror(errno));
        return -clsact_id;
    }

    struct {
        struct nlmsghdr hdr;
        struct tcmsg tc;
    } msg = {0};

    msg.hdr.nlmsg_len = sizeof(msg);
    msg.hdr.nlmsg_type = RTM_DELTFILTER;
    msg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.hdr.nlmsg_seq = ++seq;
    msg.hdr.nlmsg_pid = getpid();
    msg.tc.tcm_family = AF_UNSPEC;
    msg.tc.tcm_ifindex = if_index;
    msg.tc.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);

    if(send(sfd, &msg, sizeof(msg), 0) < 0) return errno;

    return -check_netlink_error();
}

uint32_t add_netlink_filter(__u16 if_index, __u32 prog_id, char* prog_name, int prog_name_len)
{
    __u32 clsact_id = getqdisk_id(if_index);
    if(!clsact_id) {
            printf("Couldn't find clsact qdisc\n");
            return ENODEV;
    } else if(clsact_id < 0) {
        printf("socket error %d: %s\n", clsact_id, strerror(clsact_id));
        return -clsact_id;
    }

    int packedlen = 0;
    struct {
        struct nlmsghdr hdr;
        struct tcmsg tc;
    } msg = {0};

    msg.hdr.nlmsg_type = RTM_NEWTFILTER;
    msg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    msg.hdr.nlmsg_seq = ++seq;
    msg.hdr.nlmsg_pid = getpid();
    msg.tc.tcm_family = AF_UNSPEC;
    msg.tc.tcm_ifindex = if_index;
    msg.tc.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
    msg.tc.tcm_info = TC_H_MAKE(0, htons(ETH_P_ALL));
    packedlen += sizeof(msg);
    struct nlattr nl_kind;
    nl_kind.nla_len = sizeof(struct nlattr) + sizeof(bpf_str);
    nl_kind.nla_type = TCA_KIND;
    packedlen += NLA_ALIGN(nl_kind.nla_len);

    __u32 bpf_flags = TCA_BPF_FLAG_ACT_DIRECT;
    int optionslen = 0;
    struct nlattr nl_bpf_fd;
    nl_bpf_fd.nla_len = sizeof(struct nlattr) + sizeof(int);
    nl_bpf_fd.nla_type = TCA_BPF_FD;
    optionslen += NLA_ALIGN(nl_bpf_fd.nla_len);
    struct nlattr nl_bpf_name;
    nl_bpf_name.nla_len = sizeof(struct nlattr) + prog_name_len;
    nl_bpf_name.nla_type = TCA_BPF_NAME;
    optionslen += NLA_ALIGN(nl_bpf_name.nla_len);
    struct nlattr nl_bpf_flags;
    nl_bpf_flags.nla_len = sizeof(struct nlattr) + sizeof(int);
    nl_bpf_flags.nla_type = TCA_BPF_FLAGS;
    optionslen += NLA_ALIGN(nl_bpf_flags.nla_len);

    struct nlattr nl_options;
    nl_options.nla_len = sizeof(struct nlattr) + optionslen;
    nl_options.nla_type = TCA_OPTIONS;
    packedlen += NLA_ALIGN(nl_options.nla_len);

    msg.hdr.nlmsg_len = packedlen;

    char *data = new char[packedlen], *datap = data;
    memset(data, 0, packedlen);
    memcpy(datap, &msg, sizeof(msg));
    datap += sizeof(msg);
    memcpy(datap, &nl_kind, sizeof(nl_kind));
    memcpy(datap + sizeof(nl_kind), bpf_str, sizeof(bpf_str));
    datap += NLA_ALIGN(nl_kind.nla_len);

    memcpy(datap, &nl_options, sizeof(nl_options));
    datap += sizeof(nl_options);
    memcpy(datap, &nl_bpf_fd, sizeof(nl_bpf_fd));
    memcpy(datap + sizeof(nl_bpf_fd), &prog_id, sizeof(prog_id));
    datap += NLA_ALIGN(nl_bpf_fd.nla_len);
    memcpy(datap, &nl_bpf_name, sizeof(nl_bpf_name));
    memcpy(datap + sizeof(nl_bpf_name), prog_name, prog_name_len);
    datap += NLA_ALIGN(nl_bpf_name.nla_len);
    memcpy(datap, &nl_bpf_flags, sizeof(nl_bpf_flags));
    memcpy(datap + sizeof(nl_bpf_flags), &bpf_flags, sizeof(bpf_flags));
    datap += NLA_ALIGN(nl_bpf_flags.nla_len);

    if(send(sfd, data, packedlen, 0) < 0) {
        delete[] data;
        return errno;
    }

    delete[] data;
    return -check_netlink_error();
}

int get_filter_id(__u16 if_index)
{
    __u32 clsact_id = getqdisk_id(if_index);
    if(!clsact_id) {
            printf("Couldn't find clsact qdisc\n");
            return -ENODEV;
    } else if(clsact_id < 0) {
        printf("socket error %d: %s\n", clsact_id, strerror(clsact_id));
        return clsact_id;
    }

    struct {
        struct nlmsghdr hdr;
        struct tcmsg tc;
    } msg = {0};

    msg.hdr.nlmsg_len = sizeof(msg);
    msg.hdr.nlmsg_type = RTM_GETTFILTER;
    msg.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.hdr.nlmsg_seq = ++seq;
    msg.hdr.nlmsg_pid = getpid();
    msg.tc.tcm_family = AF_UNSPEC;
    msg.tc.tcm_ifindex = if_index;
    msg.tc.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);

    if(send(sfd, &msg, sizeof(msg), 0) < 0) return -errno;

    int datalen = 0;
    char *data = get_netlink_response(datalen), *databegin = data, *dataend = data + datalen;
    if(!data) return -errno;
    struct nlmsghdr* hdr = (struct nlmsghdr*)data;
    int ret = 0;
    if(hdr->nlmsg_type == NLMSG_DONE || hdr->nlmsg_type == NLMSG_ERROR) ret = check_netlink_error(data);
    else ret = check_netlink_error();
    if(ret) return ret;

    while(data < dataend) {
        struct nlmsghdr* hdr = (struct nlmsghdr*)data;
        data += hdr->nlmsg_len;
        if(hdr->nlmsg_type != RTM_NEWTFILTER) continue;

        struct tcmsg *tc = (struct tcmsg *)(hdr+1);
        if(tc->tcm_ifindex != if_index) continue;

        struct nlattr* attr = (struct nlattr*)(tc+1);
        while((char*)attr < data) {
            if(attr->nla_type == TCA_KIND) {
                char* kind = (char*)(attr+1);
                int kindlen = attr->nla_len - sizeof(struct nlattr);
                if(kindlen != sizeof(bpf_str) || strncmp(kind, bpf_str, kindlen) != 0)
                    break;
            }
            if(attr->nla_type == TCA_OPTIONS) {
                struct nlattr* attr1 = attr+1;
                while((char*)attr1 < (char*)attr + NLA_ALIGN(attr->nla_len)) {
                    if(attr1->nla_type == TCA_BPF_ID) {
                        delete[] databegin;
                        return *(uint32_t*)(attr1 + 1);
                    }
                    attr1 = (struct nlattr*)((char*)attr1 + NLA_ALIGN(attr1->nla_len));
                }
            }
            attr = (struct nlattr*)((char*)attr + NLA_ALIGN(attr->nla_len));
        }
    }
    delete[] databegin;

    return 0;
}

int get_tunnel_info(__u16 if_index, struct tunnel_info& info)
{
    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg ifi;
    } msg = {0};

    msg.hdr.nlmsg_len = sizeof(msg);
    msg.hdr.nlmsg_type = RTM_GETLINK;
    msg.hdr.nlmsg_flags = NLM_F_REQUEST;
    msg.hdr.nlmsg_seq = ++seq;
    msg.hdr.nlmsg_pid = getpid();
    msg.ifi.ifi_family = AF_PACKET;
    msg.ifi.ifi_index = if_index;
    msg.ifi.ifi_type = ARPHRD_NETROM;

    if(send(sfd, &msg, sizeof(msg), 0) < 0) return -errno;

    int datalen = 0;
    char *data = get_netlink_response(datalen), *databegin = data, *dataend = data + datalen;
    if(!data) return -errno;
    struct nlmsghdr* hdr = (struct nlmsghdr*)data;
    int ret = 0;
    if(hdr->nlmsg_type == NLMSG_DONE || hdr->nlmsg_type == NLMSG_ERROR) ret = check_netlink_error(data);
    if(ret) return ret;

    bool find = false;
    while(data < dataend) {
        struct nlmsghdr* hdr = (struct nlmsghdr*)data;
        data += hdr->nlmsg_len;
        if(hdr->nlmsg_type != RTM_NEWLINK) continue;

        struct ifinfomsg *ifi = (struct ifinfomsg *)(hdr+1);
        if(ifi->ifi_index != if_index) continue;

        struct nlattr* attr = (struct nlattr*)(ifi+1);
        while((char*)attr < data) {
            if(attr->nla_type == IFLA_MTU) {
                int* mtu = (int*)(attr+1);
                info.mtu = *mtu;
            } else if(attr->nla_type == IFLA_LINKINFO) {
                struct nlattr* attr1 = attr+1;
                while((char*)attr1 < (char*)attr + NLA_ALIGN(attr->nla_len)) {
                    if(attr1->nla_type == IFLA_INFO_KIND) {
                        char* kind = (char*)(attr1+1);
                        int kindlen = attr1->nla_len - sizeof(struct nlattr);
                        if(kindlen != sizeof(gre_str) || strncmp(kind, gre_str, kindlen)) {
                            delete[] databegin;
                            return 0;
                        }
                        find = true;
                    } else if(attr1->nla_type == IFLA_INFO_DATA) {
                        struct nlattr* attr2 = attr1+1;
                        while((char*)attr2 < (char*)attr1 + NLA_ALIGN(attr1->nla_len)) {
                            if(attr2->nla_type == IFLA_GRE_LOCAL) {
                                int addrlen = attr2->nla_len - sizeof(struct nlattr);
                                if(addrlen == sizeof(struct in_addr))
                                    info.family = AF_INET;
                                else if(addrlen == sizeof(struct in6_addr))
                                    info.family = AF_INET6;
                                else {
                                    printf("unknown local address in interface\n");
                                    delete[] databegin;
                                    return 0;
                                }
                            }
                            attr2 = (struct nlattr*)((char*)attr2 + NLA_ALIGN(attr2->nla_len));
                        }
                    }
                    attr1 = (struct nlattr*)((char*)attr1 + NLA_ALIGN(attr1->nla_len));
                }
            }
            attr = (struct nlattr*)((char*)attr + NLA_ALIGN(attr->nla_len));
        }
    }
    delete[] databegin;

    return find ? 1 : 0;
}

