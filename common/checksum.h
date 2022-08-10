#ifndef CHECKSUM_H
#define CHECKSUM_H

uint16_t net_checksum_udp(uint16_t length, uint32_t *csum, uint8_t *addrs, uint16_t addrslen);
uint16_t net_checksum_ip(uint16_t length, uint8_t *buf);
uint32_t net_checksum(uint16_t length, uint8_t *buf, uint32_t *csum);

#endif/*CHECKSUM_H*/
