#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/limits.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "gtest/gtest.h"
#include "common/common.h"
#include "common/checksum.h"
#include "common/bpf_helpers.h"
#include "unit_test.h"

#define BUFFER_SIZE MTU+sizeof(struct ethhdr)
#define MAX_FRAGMENTED_SIZE MTU - (MTU-sizeof(struct ipv6hdr))%8 + sizeof(struct ethhdr)

static char buffer_in[MAX_FRAGMENTS][BUFFER_SIZE];
extern int ipv6_fd;

struct ipv6_fragment_hdr {
     struct ipv6_opt_hdr opt;
     __u16 frag_data;
     __s32 id;
};

int fill_ipv6_packet(int len, __u32& count, int port = 33440)
{
    struct{
        struct ethhdr ethhdr;
        struct ipv6hdr iphdr;
    } __attribute__((packed)) *pdata;

    char* data = 0;
    __s32 id = rand();
    struct udphdr* udph = 0;
    __u32 csum = 0; 
    int data_size = len + sizeof(struct udphdr);
    for(int i = 0; data_size && i < MAX_FRAGMENTS; i++) {
        memset(buffer_in[i], 0, BUFFER_SIZE);
        pdata = reinterpret_cast<decltype(pdata)>(buffer_in[i]);
        pdata->ethhdr.h_proto = htons(ETH_P_IPV6);
        pdata->iphdr.version = 6;
        pdata->iphdr.hop_limit = 255;
        if(data_size <= MTU - sizeof(struct ipv6hdr) && !i) {
            pdata->iphdr.nexthdr = IPPROTO_UDP;
            pdata->iphdr.payload_len = htons(data_size);
        } else {
            pdata->iphdr.nexthdr = IPPROTO_FRAGMENT;
            if(data_size <= MTU - sizeof(struct ipv6hdr) - sizeof(struct ipv6_fragment_hdr)) {
                pdata->iphdr.payload_len = htons(data_size + sizeof(struct ipv6_fragment_hdr));
            } else {
                uint16_t maxlen = MTU - sizeof(struct ipv6hdr);
                maxlen -= maxlen%8;
                pdata->iphdr.payload_len = htons(maxlen);
            }
        }
        inet_pton(AF_INET6, "2a00::101", &pdata->iphdr.saddr);
        inet_pton(AF_INET6, "2a00::100", &pdata->iphdr.daddr);
        data = (char*)(pdata+1);
        int data_len = htons(pdata->iphdr.payload_len); 
        if(pdata->iphdr.nexthdr == IPPROTO_FRAGMENT) {
            struct ipv6_fragment_hdr* ipfrag = (struct ipv6_fragment_hdr*)data;
            ipfrag->opt.nexthdr = IPPROTO_UDP;
            ipfrag->id = htonl(id);
            if(data_size <= MTU - sizeof(struct ipv6hdr) - sizeof(struct ipv6_fragment_hdr))
                ipfrag->frag_data = 0;
            else 
                ipfrag->frag_data = htons(0x1);
            ipfrag->frag_data |= htons(((len + sizeof(struct udphdr) - data_size)/8)<<3);
            data = (char*)(ipfrag + 1);
            data_len -= sizeof(struct ipv6_fragment_hdr);
        }
        if(!i) {
            udph = (struct udphdr*)data;
            udph->len = htons(len + sizeof(struct udphdr));
            udph->dest = htons(port);
            udph->source = htons(443);
            data = (char*)(udph+1);
            data_len -= sizeof(struct udphdr);
            data_size -= sizeof(struct udphdr);
            csum = net_checksum(sizeof(struct udphdr), (uint8_t*)udph, &csum);
        }
        for(int j = 0; j < data_len; j++) {
            data[j] = j&0xff;
        }
        csum = net_checksum(data_len, (uint8_t*)data, &csum);
        data_size -= data_len;
        count = i+1;
    }

    udph->check = htons(net_checksum_udp(len + sizeof(struct udphdr), &csum, (uint8_t*)&pdata->iphdr.saddr, 32));
    return htons(pdata->iphdr.payload_len) + sizeof(ethhdr) + sizeof(struct ipv6hdr);
}

int fill_ext_ipv6_packet(int len, __u32& count, int port = 33440)
{
    struct{
        struct ethhdr ethhdr;
        struct ipv6hdr iphdr;
    } __attribute__((packed)) *pdata;

    char* data = 0;
    __s32 id = rand();
    struct udphdr* udph = 0;
    __u32 csum = 0; 
    int data_size = len + sizeof(struct udphdr);
    for(int i = 0; data_size && i < MAX_FRAGMENTS; i++) {
        memset(buffer_in[i], 0, BUFFER_SIZE);
        int filled_size = 0;
        int payload_len = data_size;
        pdata = reinterpret_cast<decltype(pdata)>(buffer_in[i]);
        pdata->ethhdr.h_proto = htons(ETH_P_IPV6);
        pdata->iphdr.version = 6;
        pdata->iphdr.hop_limit = 255;
        pdata->iphdr.nexthdr = IPPROTO_HOPOPTS;
        inet_pton(AF_INET6, "2a00::101", &pdata->iphdr.saddr);
        inet_pton(AF_INET6, "2a00::100", &pdata->iphdr.daddr);
        filled_size += sizeof(struct ipv6hdr);
        struct ipv6_opt_hdr* hopbyhop = (struct ipv6_opt_hdr*)(pdata+1);
        struct ipv6_opt_hdr* opt_hdr = hopbyhop + 1;
        opt_hdr->hdrlen = 4;
        filled_size += 8;
        payload_len += 8;
        if(data_size <= MTU - filled_size && !i) {
            hopbyhop->nexthdr = IPPROTO_UDP;
            pdata->iphdr.payload_len = htons(payload_len);
        } else {
            hopbyhop->nexthdr = IPPROTO_FRAGMENT;
            if(data_size <= MTU - filled_size - sizeof(struct ipv6_fragment_hdr)) {
                pdata->iphdr.payload_len = htons(payload_len + sizeof(struct ipv6_fragment_hdr));
            } else {
                uint16_t maxlen = MTU - sizeof(struct ipv6hdr);
                maxlen -= maxlen%8;
                pdata->iphdr.payload_len = htons(maxlen);
            }
        }
        data = (char*)(pdata+1) + 8;
        int data_len = htons(pdata->iphdr.payload_len) - 8; 
        if(hopbyhop->nexthdr == IPPROTO_FRAGMENT) {
            struct ipv6_fragment_hdr* ipfrag = (struct ipv6_fragment_hdr*)data;
            ipfrag->opt.nexthdr = IPPROTO_UDP;
            ipfrag->id = htonl(id);
            if(data_size <= MTU - sizeof(struct ipv6hdr) - sizeof(struct ipv6_fragment_hdr))
                ipfrag->frag_data = 0;
            else 
                ipfrag->frag_data = htons(0x1);
            ipfrag->frag_data |= htons(((len + sizeof(struct udphdr) - data_size)/8)<<3);
            data = (char*)(ipfrag + 1);
            data_len -= sizeof(struct ipv6_fragment_hdr);
        }
        if(!i) {
            udph = (struct udphdr*)data;
            udph->len = htons(len + sizeof(struct udphdr));
            udph->dest = htons(port);
            udph->source = htons(443);
            data = (char*)(udph+1);
            data_len -= sizeof(struct udphdr);
            data_size -= sizeof(struct udphdr);
            csum = net_checksum(sizeof(struct udphdr), (uint8_t*)udph, &csum);
        }
        for(int j = 0; j < data_len; j++) {
            data[j] = j&0xff;
        }
        csum = net_checksum(data_len, (uint8_t*)data, &csum);
        data_size -= data_len;
        count = i+1;
    }

    udph->check = htons(net_checksum_udp(len + sizeof(struct udphdr), &csum, (uint8_t*)&pdata->iphdr.saddr, 32));
    return htons(pdata->iphdr.payload_len) + sizeof(ethhdr) + sizeof(struct ipv6hdr);
}

TEST(IPv6_Tests, SingleTest) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv6_packet(1400, count);
    GTEST_ASSERT_EQ(count, 1);
    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}

TEST(IPv6_Tests, FragmentTest) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv6_packet(1442, count);
    GTEST_ASSERT_EQ(count, 1);
    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);

    len = fill_ext_ipv6_packet(1435, count);
    GTEST_ASSERT_EQ(count, 1);
    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);

}

TEST(IPv6_Tests, Fragment1Test) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv6_packet(1455, count);
    GTEST_ASSERT_EQ(count, 2);

    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);

    len = fill_ext_ipv6_packet(1455, count);
    GTEST_ASSERT_EQ(count, 2);

    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}

TEST(IPv6_Tests, Fragment2Test) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv6_packet(1455, count);
    GTEST_ASSERT_EQ(count, 2);

    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_SHOT);
    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);

    len = fill_ext_ipv6_packet(1455, count);
    GTEST_ASSERT_EQ(count, 2);

    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_SHOT);
    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], MAX_FRAGMENTED_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}

TEST(IPv6_Tests, Fragment3Test) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv6_packet(1440, count);
    GTEST_ASSERT_EQ(count, 1);

    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);

    len = fill_ext_ipv6_packet(1432, count);
    GTEST_ASSERT_EQ(count, 1);

    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}
