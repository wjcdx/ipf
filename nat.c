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

#include "nat.h"
#include "util.h"
#include "debug.h"


uint32_t __text_search(uint8_t *text, uint32_t offset, uint32_t len,
		uint8_t *target, uint32_t target_len)
{
	int i = 0;

	for (i = offset; i < len; i++) {
		if (len - i < target_len) {
			return -1;
		}
		if (memcmp(text + i, target, target_len) == 0) {
			return i;
		}
	}
	return -1;
}

int ipaddr_repl(struct iphdr *iph, uint32_t dst, uint32_t src)
{
	uint32_t pos = -12;
	int totlen = __iphdr_totlen(iph);
	while ((pos = __text_search((uint8_t *)iph, pos + 12,
			totlen, (uint8_t *)"192.168.1.90", 12)) != -1) {
		D("192.168.1.90 found.\n");
		memcpy(((uint8_t *)iph) + pos, "192.168.6.64", 12);
	}
	return 1;
}

void ipf_learn(struct ipf_conn *conn,
		struct ipf_ct_tuple *tuple, int dir)
{
	struct ipf_ct_tuple *t = NULL;

	t = &conn->tuples[dir];
	if (t->state == IPF_CT_STATE_LEARNT) {
		return;
	}

	memcpy(t, tuple, sizeof(*t));
	t->state = IPF_CT_STATE_LEARNT;
}

int ipf_nat(struct ipf_skb *skb, struct ipf_conn *conn)
{
	struct ipf_ct_tuple target;
	struct ether_header *eh = skb->eh;
	struct iphdr *iph = skb->iph;

	memset(&target, 0, sizeof(target));
	// nat(ds) = invert(target(us))
	ipf_ct_invert_tuple(&target, &conn->tuples[!skb->dir]);

	ipaddr_snat(iph, target.src.ip);
	ipaddr_dnat(iph, target.dst.ip);
	__ip_update_chksum(iph);
	// replace ip address in layer7 packet contents
	// TODO: do not care about layer7 alg yet
	//ipaddr_repl(iph, target.dst.ip, rule->m.daddr);
	if (iph->protocol == IPPROTO_TCP) {
		__tcp_update_chksum(skb->tcph, iph);
	}
	macaddr_snat(eh, target.src.mac);
	macaddr_dnat(eh, target.dst.mac);
	return 1;
}

