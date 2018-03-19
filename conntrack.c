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
#include <stdlib.h>

#include "conntrack.h"
#include "util.h"
#include "debug.h"


static struct list_head g_ipf_conn_head = LIST_HEAD_INIT(g_ipf_conn_head);

int ipf_ct_conn_established(struct ipf_conn *conn)
{
	return (conn->tuples[IPF_CT_DIR_ORIG].state == IPF_CT_STATE_LEARNT
		&& conn->tuples[IPF_CT_DIR_REPL].state == IPF_CT_STATE_LEARNT);
}

static uint32_t ipf_ct_tuple_hash(struct ipf_ct_tuple *tuple)
{
	uint32_t hash = 0;
	int i = 0;

	for (i = 0; i < sizeof(tuple->src); i++) {
		hash += *(((uint8_t *)&tuple->src) + i);
	}
	
	for (i = 0; i < sizeof(tuple->dst); i++) {
		hash += *(((uint8_t *)&tuple->dst) + i);
	}

	return hash;
}

void __ipf_ct_tuple_dump_hex(struct ipf_ct_tuple *tuple, char *prefix)
{
	int i = 0;
	D("%s src: ", prefix);
	for (i = 0; i < sizeof(tuple->src); i++) {
		D("%02x ", *(((uint8_t *)&tuple->src) + i));
	}
	D("dst: ");
	for (i = 0; i < sizeof(tuple->src); i++) {
		D("%02x ", *(((uint8_t *)&tuple->dst) + i));
	}
	D("\n");
}

static void __ipf_ct_peer_dump(struct ipf_ct_peer *peer, char *prefix)
{
	D("  %s\n", prefix);
	__dump_mac_addr(peer->mac, "    mac: ");
	__dump_ip_addr(peer->ip,   "    ip : ");
	D("    protocol: %02x, port: %d\n", peer->protocol, ntohs(peer->port));
}

void __ipf_ct_tuple_dump(struct ipf_ct_tuple *tuple, char *prefix)
{
	D("%s\n  hash: %08x\n", prefix, tuple->hash);
	__ipf_ct_peer_dump(&tuple->src, "src:");
	__ipf_ct_peer_dump(&tuple->dst, "dst:");
}

void ipf_ct_tuple_get(struct ipf_ct_tuple *tuple, struct ipf_skb *skb)
{
	struct ether_header *eh = skb->eh;
	struct iphdr *iph = skb->iph;

	memset(tuple, 0, sizeof(*tuple));
	memcpy(tuple->src.mac, eh->ether_shost, ETH_ALEN);
	memcpy(tuple->dst.mac, eh->ether_dhost, ETH_ALEN);
	
	tuple->src.ip = iph->saddr;
	tuple->dst.ip = iph->daddr;
	tuple->src.protocol = iph->protocol;
	tuple->dst.protocol = iph->protocol;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = skb->tcph;
		tuple->src.port = tcph->source;
		tuple->dst.port = tcph->dest;
	}
	else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = skb->udph;
		tuple->src.port = udph->source;
		tuple->dst.port = udph->dest;
	}
	tuple->hash = ipf_ct_tuple_hash(tuple);
	__ipf_ct_tuple_dump(tuple,     "got tuple:");
	__ipf_ct_tuple_dump_hex(tuple, "got tuple:");
}

void ipf_ct_invert_tuple(struct ipf_ct_tuple *inverse, struct ipf_ct_tuple *orig)
{
	memcpy(&inverse->src, &orig->dst, sizeof(inverse->src));
	memcpy(&inverse->dst, &orig->src, sizeof(inverse->dst));
	inverse->hash = ipf_ct_tuple_hash(inverse);
	__ipf_ct_tuple_dump(inverse,     "inv tuple:");
	__ipf_ct_tuple_dump_hex(inverse, "inv tuple:");
}

static inline int __ipf_ct_tuple_equals(struct ipf_ct_tuple *lhs,
		struct ipf_ct_tuple *rhs)
{
	D("hash equals: %08x ?= %08x\n", lhs->hash, rhs->hash);
	if (lhs->hash != rhs->hash) {
		return 0;
	}

	__ipf_ct_tuple_dump_hex(lhs, "lhs: ");
	__ipf_ct_tuple_dump_hex(rhs, "rhs: ");
	if (memcmp(&lhs->src, &rhs->src, sizeof(lhs->src)) != 0
	 || memcmp(&lhs->dst, &rhs->dst, sizeof(lhs->dst)) != 0) {
		D("tuple equals: NO\n");
		return 0;
	}

	D("tuple equals: YES\n");
	return 1;
}

struct ipf_conn *ipf_conn_find(struct ipf_ct_tuple *tuple, int dir)
{
	struct ipf_conn *c = NULL;
	struct list_head *pos = NULL;

	list_for_each(pos, &g_ipf_conn_head) {
		c = list_entry(pos, struct ipf_conn, list);
		if (__ipf_ct_tuple_equals(tuple, &c->tuples[dir])) {
			return c;
		}
	}

	return NULL;
}

struct ipf_conn *ipf_ct_conn_new(void)
{
	struct ipf_conn *conn = NULL;

	conn = (struct ipf_conn *)malloc(sizeof(struct ipf_conn));
	memset(conn, 0, sizeof(struct ipf_conn));

	list_add_tail(&conn->list, &g_ipf_conn_head);
	return conn;
}

struct ipf_skb *ipf_skb_alloc(unsigned int size)
{
	struct ipf_skb *skb = NULL;
	int len = 0;

	len = size + sizeof(struct ipf_skb);
	skb = (struct ipf_skb *)malloc(len);
	if (!skb) {
		return NULL;
	}
	memset(skb, 0, len);
	skb->frame = (((uint8_t *)skb) + sizeof(struct ipf_skb));

	return skb;
}

void ipf_setup_skb(struct ipf_skb *skb)
{
	uint8_t *frame = skb->frame;

	skb->eh = (struct ether_header *)frame;
	skb->iph = (struct iphdr *)(frame + sizeof(struct ether_header));
	skb->protocol = skb->iph->protocol;
	// set transport layer to the same position
	skb->tcph = __tcphdr(skb->iph);
	skb->udph = __udphdr(skb->iph);
}

