#include <stdint.h>
#include <netinet/in.h>
#include "checksum.h"

uint32_t net_checksum_add(int len, uint8_t *buf)
{
    uint32_t sum = 0;
    int i;

    for (i = 0; i < len; i++) {
	if (i & 1)
	    sum += (uint32_t)buf[i];
	else
	    sum += (uint32_t)buf[i] << 8;
    }
    return sum;
}

uint16_t net_checksum_finish(uint32_t sum)
{
    while (sum>>16)
	sum = (sum & 0xFFFF)+(sum >> 16);
    return ~sum;
}

uint32_t net_checksum(uint16_t length, uint8_t *buf, uint32_t *csum)
{
    *csum += net_checksum_add(length, buf);
    return *csum;
}

uint16_t net_checksum_udp(uint16_t length, uint32_t *csum, uint8_t *addrs, uint16_t addrslen)
{
    *csum += net_checksum_add(addrslen, addrs);            // src + dst address
    *csum += IPPROTO_UDP + length;                  // protocol & length
    return net_checksum_finish(*csum);
}

uint16_t net_checksum_ip(uint16_t length, uint8_t *buf)
{
    uint32_t sum = 0;
    sum += net_checksum_add(length, buf);
    return net_checksum_finish(sum);
}
