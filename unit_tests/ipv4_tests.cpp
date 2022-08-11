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

static char buffer_in[MAX_FRAGMENTS][BUFFER_SIZE];

int fill_ipv4_packet(int len, __u32& count, int port = 33440, char* buf = 0)
{
    struct{
        struct ethhdr ethhdr;
        struct iphdr iphdr;
    } __attribute__((packed)) *pdata;

    char* data = 0;
    __s16 id = rand();
    struct udphdr* udph = 0;
    __u32 csum = 0; 
    int data_size = len + sizeof(struct udphdr);
    for(int i = 0; data_size && i < MAX_FRAGMENTS; i++) {
        pdata = reinterpret_cast<decltype(pdata)>(buffer_in[i]);
        pdata->ethhdr.h_proto = htons(ETH_P_IP);
        pdata->iphdr.version = 4;
        pdata->iphdr.ihl = 5;
        pdata->iphdr.ttl = 255;
        pdata->iphdr.check = 0;
        if(data_size <= MTU - sizeof(struct iphdr)) {
            pdata->iphdr.frag_off = 0;
            pdata->iphdr.tot_len = htons(data_size + sizeof(struct iphdr));
        } else {
            pdata->iphdr.frag_off = htons(0x2000);
            pdata->iphdr.tot_len = htons(MTU);
        }
        pdata->iphdr.frag_off |= htons((len + sizeof(struct udphdr) - data_size)/8);
        pdata->iphdr.id = htons(id);
        pdata->iphdr.protocol = IPPROTO_UDP;
        pdata->iphdr.tos = 0;
        pdata->iphdr.saddr = htonl(inet_addr("192.168.0.107"));
        pdata->iphdr.daddr = htonl(inet_addr("192.168.0.101"));
        pdata->iphdr.check = net_checksum_ip(sizeof(struct iphdr), (uint8_t*)&pdata->iphdr);

        data = (char*)(pdata+1);
        int data_len = htons(pdata->iphdr.tot_len) - sizeof(struct iphdr); 
        if(!i) {
            udph = (struct udphdr*)(pdata+1);
            udph->len = htons(len + sizeof(struct udphdr));
            udph->check = 0;
            udph->dest = htons(port);
            udph->source = htons(443);
            data = (char*)(udph+1);
            data_len = htons(pdata->iphdr.tot_len) - sizeof(struct iphdr) - sizeof(struct udphdr);
            csum = net_checksum(sizeof(struct udphdr), (uint8_t*)udph, &csum);
        }
        for(int j = 0; j < data_len; j++) {
            if(!buf) {
                data[j] = j&0xff;
            } else {
                data[j] = *buf;
                buf += 1;
            }
        }
        csum = net_checksum(data_len, (uint8_t*)data, &csum);
        data_size -= htons(pdata->iphdr.tot_len)- sizeof(struct iphdr);
        count = i+1;
    }
    udph->check = htons(net_checksum_udp(htons(udph->len), &csum, (uint8_t*)&pdata->iphdr.saddr, 8));
    return htons(pdata->iphdr.tot_len) + sizeof(ethhdr);
}

TEST(IPv4_Tests, SingleTest) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv4_packet(1400, count);
    GTEST_ASSERT_EQ(count, 1);
    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}

TEST(IPv4_Tests, FragmentTest) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv4_packet(1500, count);
    GTEST_ASSERT_EQ(count, 2);
    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
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
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}

TEST(IPv4_Tests, FragmentTest1) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv4_packet(1472, count);
    GTEST_ASSERT_EQ(count, 1);
    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}

TEST(IPv4_Tests, UnorderingTest) {
    __u32 duration, retval;
    __u32 count;
    int len = fill_ipv4_packet(1500, count);
    GTEST_ASSERT_EQ(count, 2);
    __u32 err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[1], len, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_SHOT);
    err = bpf_prog_test_run(ipv4_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv6_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_UNSPEC);
    err = bpf_prog_test_run(ipv4_rdr_fd, 1, buffer_in[0], BUFFER_SIZE, 0, 0, &retval, &duration);
    GTEST_ASSERT_EQ(err, 0);
    GTEST_ASSERT_EQ(retval, TC_ACT_REDIRECT);
}
