/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IPF_CONNTRACK_H_
#define _IPF_CONNTRACK_H_

#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "list.h"

enum {
	IPF_CT_DIR_ORIG = 0,
	IPF_CT_DIR_REPL = 1,
	IPF_CT_DIR_NUM,
};

struct ipf_ct_peer {
	uint16_t port;            /* In network order endian */
	uint8_t  protocol;
	uint32_t ip;
	uint8_t  mac[6];
};

enum {
	IPF_CT_STATE_NEW = 0,
	IPF_CT_STATE_LEARNT,
};

struct ipf_ct_tuple {
	struct ipf_ct_peer src;
	struct ipf_ct_peer dst;
	int state;
	int hash;
};

struct ipf_conn {
	struct list_head list;
	struct ipf_ct_tuple tuples[IPF_CT_DIR_NUM];
};

struct ipf_skb {
	struct list_head list;

	uint8_t *frame;
	uint32_t len;
	uint8_t	 protocol; // protocol of transport 
	
	struct ether_header *eh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int dir;
};

void ipf_ct_invert_tuple(struct ipf_ct_tuple *inverse, struct ipf_ct_tuple *orig);
void ipf_ct_tuple_get(struct ipf_ct_tuple *tuple, struct ipf_skb *skb);
int ipf_ct_conn_established(struct ipf_conn *conn);
struct ipf_conn *ipf_conn_find(struct ipf_ct_tuple *tuple, int dir);
struct ipf_conn *ipf_ct_conn_new(void);

struct ipf_skb *ipf_skb_alloc(unsigned int size);
void ipf_setup_skb(struct ipf_skb *skb);

#endif /* _IPF_CONNTRACK_H_ */

