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

#include "DNAT.h"
#include "util.h"
#include "debug.h"


static int ipf_ds_match(struct ipf_skb *skb, struct ipf_rule *rule)
{
	struct iphdr *iph = skb->iph;
	__dump_ip_addr(iph->daddr,           "ds check: ");
	__dump_ip_addr(rule->m.daddr,        "       =? ");
	if (iph->daddr != rule->m.daddr) {
		return 0;
	}

	if (iph->protocol != rule->m.protocol) {
		return 0;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = skb->tcph;
		if (tcph->dest != rule->m.port) {
			return 0;
		}
	}
	else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = skb->udph;
		if (udph->dest != rule->m.port) {
			return 0;
		}
	}

	return 1;
}

int ipf_rule_match(struct ipf_skb *skb, struct ipf_rule *rule)
{
	return ipf_ds_match(skb, rule);
}

// There's only DNAT target just now.
int ipf_rule_jump_target(struct ipf_skb *skb, struct ipf_rule *rule)
{
	struct ether_header *eh = skb->eh;
	struct iphdr *iph = skb->iph;

	//ipaddr_snat(iph, rule->t.to_saddr);
	ipaddr_dnat(iph, rule->t.to_daddr);
	__ip_update_chksum(iph);
	// replace ip address in layer7 packet contents
	// TODO: do not care about layer7 alg yet
	//ipaddr_repl(iph, target.dst.ip, rule->m.daddr);
	if (iph->protocol == IPPROTO_TCP) {
		__tcp_update_chksum(skb->tcph, iph);
	}
	macaddr_snat(eh, rule->t.to_shost);
	macaddr_dnat(eh, rule->t.to_dhost);
	return 1;
}

