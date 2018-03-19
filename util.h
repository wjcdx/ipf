/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#ifndef _IPF_UTIL_H_
#define _IPF_UTIL_H_

#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static inline int __iphdr_len(struct iphdr *iph)
{
	return (iph->ihl << 2);
}

static inline int __iphdr_totlen(struct iphdr *iph)
{
	return ntohs(iph->tot_len);
}

static inline struct tcphdr *__tcphdr(struct iphdr *iph)
{
	return (struct tcphdr *)((uint8_t *)iph + __iphdr_len(iph));
}

static inline int __is_tcp_syn_fin(struct tcphdr *tcph)
{
	return tcph->syn || tcph->fin || (tcph->ack && !tcph->psh);
}

static inline struct udphdr *__udphdr(struct iphdr *iph)
{
	return (struct udphdr *)((uint8_t *)iph + __iphdr_len(iph));
}

void __dump_ip_addr(uint32_t addr, char *prefix);
void __dump_mac_addr(uint8_t *mac, char *prefix);
void __dump_ether(struct ether_header *eh);
void __dump_iphdr(struct iphdr *iph);
void __dump_tcphdr(struct tcphdr *tcph);
void __dump_udphdr(struct udphdr *udph);

void __ip_update_chksum(struct iphdr *iph);
void __tcp_update_chksum(struct tcphdr *tcph, struct iphdr *iph);

int ipaddr_dnat(struct iphdr *iph, uint32_t target_da);
int ipaddr_snat(struct iphdr *iph, uint32_t target_sa);
int macaddr_dnat(struct ether_header *eh, uint8_t *target_da);
int macaddr_snat(struct ether_header *eh, uint8_t *target_sa);

#endif /* _IPF_UTIL_H_ */



