/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "debug.h"

#define IP_ADDR_LEN 4

#define IPFMT  "%u.%u.%u.%u"
#define MACFMT "%02X:%02X:%02X:%02X:%02X:%02X"


static uint16_t ip_chksum(uint16_t initcksum, uint8_t *ptr, int len)
{
    unsigned int cksum;
    int idx;
    int odd;

    cksum = (unsigned int) initcksum;

    odd = len & 1;
    len -= odd;

    for (idx = 0; idx < len; idx += 2) {
        cksum += ((unsigned long) ptr[idx] << 8) + ((unsigned long) ptr[idx+1]);
    }

    if (odd) {      /* buffer is odd length */
        cksum += ((unsigned long) ptr[idx] << 8);
    }

    /*
     * Fold in the carries
     */

    while (cksum >> 16) {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }

    return cksum;
}

static uint16_t tcp_chksum(uint16_t initcksum, uint8_t *tcphead, int tcplen , uint32_t *srcaddr, uint32_t *destaddr)
{
    uint8_t pseudoheader[12];
    uint16_t calccksum;

    memcpy(&pseudoheader[0],srcaddr,IP_ADDR_LEN);
    memcpy(&pseudoheader[4],destaddr,IP_ADDR_LEN);
    pseudoheader[8] = 0; /* 填充零 */
    pseudoheader[9] = IPPROTO_TCP;
    pseudoheader[10] = (tcplen >> 8) & 0xFF;
    pseudoheader[11] = (tcplen & 0xFF);

    calccksum = ip_chksum(0,pseudoheader,sizeof(pseudoheader));
    calccksum = ip_chksum(calccksum,tcphead,tcplen);
    calccksum = ~calccksum;
    return calccksum;
}

void __dump_ip_addr(uint32_t addr, char *prefix)
{
	unsigned char *p = (uint8_t *)&addr;
	D_NOP(p);
	D("%s"IPFMT"\n", prefix, p[0], p[1], p[2], p[3]);
}

void __dump_mac_addr(uint8_t *mac, char *prefix)
{
	D("%s"MACFMT"\n", prefix,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void __dump_ether(struct ether_header *eh)
{
	__dump_mac_addr(eh->ether_shost, "Src MAC: ");
	__dump_mac_addr(eh->ether_dhost, "Dst MAC: ");
}

void __dump_iphdr(struct iphdr *iph)
{
	__dump_ip_addr(iph->saddr, "Src IP: ");
	__dump_ip_addr(iph->daddr, "Dst IP: ");
}

void __dump_tcphdr(struct tcphdr *tcph)
{
	D("Protocol: TCP\n");
	D("Src port: %u\n", ntohs(tcph->source));
	D("Dst port: %u\n", ntohs(tcph->dest));
}

void __dump_udphdr(struct udphdr *udph)
{
	D("Protocol: UDP\n");
	D("Src port: %u\n", ntohs(udph->source));
	D("Dst port: %u\n", ntohs(udph->dest));
}

void __ip_update_chksum(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ~ip_chksum(0, (uint8_t *)iph, __iphdr_len(iph));
	iph->check = htons(iph->check);
}

void __tcp_update_chksum(struct tcphdr *tcph, struct iphdr *iph)
{
	tcph->check = 0;
	tcph->check = tcp_chksum(0, (uint8_t *)tcph,
			__iphdr_totlen(iph) - __iphdr_len(iph),
			&iph->saddr, &iph->daddr);
	tcph->check = htons(tcph->check);
}

int ipaddr_dnat(struct iphdr *iph, uint32_t target_da)
{
	__dump_ip_addr(iph->daddr, "ip dnat from: ");
	__dump_ip_addr(target_da,  "          to: ");
	iph->daddr = target_da;
	return 1;
}

int ipaddr_snat(struct iphdr *iph, uint32_t target_sa)
{
	__dump_ip_addr(iph->saddr, "ip snat from: ");
	__dump_ip_addr(target_sa,  "          to: ");
	iph->saddr = target_sa;
	return 1;
}

int macaddr_dnat(struct ether_header *eh, uint8_t *target_da)
{
	__dump_mac_addr(eh->ether_dhost, "mac dnat from: ");
	__dump_mac_addr(target_da,       "           to: ");
	memcpy(eh->ether_dhost, target_da, ETH_ALEN);
	__dump_mac_addr(eh->ether_dhost, "          now: ");
	return 1;
}

int macaddr_snat(struct ether_header *eh, uint8_t *target_sa)
{
	__dump_mac_addr(eh->ether_shost, "mac snat from: ");
	__dump_mac_addr(target_sa,       "           to: ");
	memcpy(eh->ether_shost, target_sa, ETH_ALEN);
	__dump_mac_addr(eh->ether_shost, "          now: ");
	return 1;
}

