/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include "config.h"
#include "conntrack.h"
#include "nat.h"
#include "DNAT.h"
#include "list.h"
#include "util.h"
#include "debug.h"

int g_raw_sockfd = -1;

#define IPF_MAX_FRAME_SIZE 2000
struct list_head       g_ipf_skb_head = LIST_HEAD_INIT(g_ipf_skb_head);
static pthread_mutex_t g_ipf_skb_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t       g_ipf_forwarding_thread = 0;

struct ipf_rule g_ipf_rule;
int g_ipf_send_ifindex[IPF_CT_DIR_NUM] = { 0 };


/* man 7 packet:
* When  you  send packets, it is enough to specify: sll_family, sll_addr,
* sll_halen, sll_ifindex, and sll_protocol.  The other fields should be 0.
* sll_hatype and sll_pkttype are set on received packets for your information.
*/
int ipf_forward_frame(struct ipf_skb *skb)
{
	struct sockaddr_ll dst_addr = { 0 };

	dst_addr.sll_family = AF_PACKET;
	dst_addr.sll_protocol = ETH_P_IP;
	dst_addr.sll_ifindex = g_ipf_send_ifindex[skb->dir];
	dst_addr.sll_halen = 6;
	dst_addr.sll_addr[0] = 0x00;
	dst_addr.sll_addr[1] = 0x01;
	dst_addr.sll_addr[2] = 0x02;
	dst_addr.sll_addr[3] = 0x03;
	dst_addr.sll_addr[4] = 0x04;
	dst_addr.sll_addr[5] = 0x05;

	ssize_t n = sendto(g_raw_sockfd, skb->frame, skb->len, 0, (const struct sockaddr *)&dst_addr,
			sizeof(dst_addr));
	D_NOP(n);
	D("send: %u\n", (unsigned int)n);
	return 0;
}

void handle_ether_frame(struct ipf_skb *skb, struct ipf_rule *rule)
{
	struct ipf_conn *conn = NULL;
	struct ipf_ct_tuple tuple, reply;

	if (!ipf_rule_match(skb, rule)) {
		D("rule mismatched...\n");
		// check if it's reply direction
		ipf_ct_tuple_get(&tuple, skb);
		conn = ipf_conn_find(&tuple, IPF_CT_DIR_REPL);
		if (!conn) {
			D("not reply, do nothing.\n");
			return;
		}
		skb->dir = IPF_CT_DIR_REPL;
		D("reply direction...\n");
	}
	else {
		D("rule matched...\n");
		ipf_ct_tuple_get(&tuple, skb);
		conn = ipf_conn_find(&tuple, IPF_CT_DIR_ORIG);
		skb->dir = IPF_CT_DIR_ORIG;
		if (!conn) {
			D("new conn...\n");
			conn = ipf_ct_conn_new();
		}
	}

	if (ipf_ct_conn_established(conn)) {
		D("conn established, nat & forward.\n");
		ipf_nat(skb, conn);
		ipf_forward_frame(skb);
		return;
	}

	D("conn learn...\n");
	ipf_learn(conn, &tuple, skb->dir);
	// nat using pre-configured rule
	ipf_rule_jump_target(skb, rule);
	D("conn learn reply...\n");
	ipf_ct_tuple_get(&tuple, skb);
	ipf_ct_invert_tuple(&reply, &tuple);
	ipf_learn(conn, &reply, !skb->dir);

	D("forward...\n");
	ipf_forward_frame(skb);
}

int ipf_rule_parse(struct ipf_rule *rule, int argc, char *argv[])
{
	int c = 0, s = 0;
	struct in_addr dst;
	static struct option long_options[] = {
		{"dport",          required_argument, 0,  0 },
		{"to-destination", required_argument, 0,  1 },
		{0,                0,                 0,  0 }
	};

	memset(rule, 0, sizeof(struct ipf_rule));
	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "d:p:j:", long_options, &option_index);
		if (c == -1)
			break;
		
		switch (c) {
		case 0:
			rule->m.port = htons(atoi(optarg));
			D("rule->m.port: %d\n", ntohs(rule->m.port));
			break;
		case 1:
			s = inet_pton(AF_INET, optarg, &dst);
			if (s != 1)
				goto err;
			rule->t.to_daddr = dst.s_addr;
			D("rule->t.to_daddr: %s\n", inet_ntoa(dst));
			break;
		case 'd':
			s = inet_pton(AF_INET, optarg, &dst);
			if (s != 1)
				goto err;
			rule->m.daddr = dst.s_addr;
			D("rule->m.daddr: %s\n", inet_ntoa(dst));
			break;
		case 'p':
			if (strncasecmp(optarg, "tcp", 3) == 0) {
				rule->m.protocol = IPPROTO_TCP;
			}
			else if (strncasecmp(optarg, "udp", 3) == 0) {
				rule->m.protocol = IPPROTO_UDP;
			}
			else {
				E("protocol only accepts tcp or udp.\n");
				goto err;
			}
			D("rule->m.protocol: %d\n", rule->m.protocol);
			break;
		case 'j':
			if (strcmp(optarg, "DNAT") != 0) {
				E("target only accepts DNAT.\n");
				goto err;
			}
			D("target: %s\n", optarg);
			break;
		case '?':
		default:
			goto err;
			break;
		}
	}

	if (!rule->m.daddr || !rule->t.to_daddr) {
		goto err;
	}

	return 1;
err:
	E("options wrong.\nmatching options:\n"
	  "-d: original destination ip address, which belongs to localhost\n"
	  "-p: transport layer protocol in ip header: tcp|udp\n"
	  " --dport: transport layer destination port\n"
	  "target options:\n"
	  "-j DNAT: only support destination network address translate\n"
	  " --to-destination: DNAT to the ip address, which is a neighbor\n");
	return 0;
}

int ipf_rule_fill_orig(struct ipf_rule *rule, uint32_t daddr)
{
	int s, ifn;
	struct ifreq  ifreqs[16];
	struct ifconf ifc;
	struct ifreq *ifr;
	uint32_t addr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
	{
		E("create socket failed.\n");
		return -1;
	}

	ifc.ifc_len = sizeof(ifreqs);
	ifc.ifc_buf = (caddr_t)ifreqs;
	if (ioctl(s, SIOCGIFCONF, (char *)&ifc)) {
		E("ioctl SIOCGIFCONF failed.\n");
		goto err;
	}

	ifn = ifc.ifc_len / sizeof(struct ifreq);
	while (ifn-- > 0)
	{
		ifr = &ifreqs[ifn];
		D("ifname: %s\n", ifr->ifr_name);

		if (ioctl(s, SIOCGIFADDR, ifr)) {
			E("ioctl SIOCGIFADDR failed.\n");
			goto err;
		}

		addr = ((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr;
		if (addr != daddr) {
			continue;
		}

		if (ioctl(s, SIOCGIFINDEX, ifr)) {
			E("ioctl SIOGIFINDEX fialed.\n");
			goto err;
		}
		g_ipf_send_ifindex[!IPF_CT_DIR_ORIG] = ifr->ifr_ifindex;
		D("reply send ifindex: %d\n", g_ipf_send_ifindex[!IPF_CT_DIR_ORIG]);
		break;
	}

	return 0;

err:
	close(s);
	return -1;
}

int __ipf_is_neigh_of(uint32_t target_ip, char *ifname, uint8_t *target_hwaddr)
{
	struct arpreq req;
        struct sockaddr_in *sin = NULL;
        int ret = 0;
        int s;

	I("find neigh of: %s\n", ifname);
        memset(&req, 0, sizeof(struct arpreq));
        sin = (struct sockaddr_in *)&req.arp_pa;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = target_ip;
        strncpy(req.arp_dev, ifname, IF_NAMESIZE);

        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s == -1)
        {
                E("create socket failed.\n");
                return 0;
        }

        ret = ioctl(s, SIOCGARP, &req);
        if (ret < 0)
        {
                E("ioctl SIOCGARP failed.\n");
		goto err;
        }

	memcpy(target_hwaddr, req.arp_ha.sa_data, ETH_ALEN);
	return 1;
err:
        close(s);
        return 0;
}

int ipf_rule_fill_repl(struct ipf_rule *rule, uint32_t to_daddr)
{
	struct ifreq  ifreqs[16];
	struct ifconf ifc;
	struct ifreq *ifr;
	int s;
	int ifn;
	char cmd[1024] = {0};
	struct in_addr addr;

	addr.s_addr = to_daddr;
	sprintf(cmd, "ping -c 3 -W 1 %s", inet_ntoa(addr));
	system(cmd);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
	{
		E("create socket failed.\n");
		return -1;
	}

	ifc.ifc_len = sizeof(ifreqs);
	ifc.ifc_buf = (caddr_t)ifreqs;
	if (ioctl(s, SIOCGIFCONF, (char *)&ifc)) {
		E("ioctl SIOCGIFCONF failed.\n");
		goto err;
	}

	ifn = ifc.ifc_len / sizeof(struct ifreq);
	while (ifn-- > 0)
	{
		ifr = &ifreqs[ifn];
		D("ifname: %s\n", ifr->ifr_name);

		if (!__ipf_is_neigh_of(to_daddr, ifr->ifr_name, rule->t.to_dhost)) {
			continue;
		}
		__dump_mac_addr(rule->t.to_dhost, "to_dhost: ");

		if (ioctl(s, SIOCGIFHWADDR, ifr)) {
			E("ioctl SIOGIFHWADDR fialed.\n");
			goto err;
		}
		memcpy(rule->t.to_shost, ifr->ifr_hwaddr.sa_data, ETH_ALEN);
		__dump_mac_addr(rule->t.to_shost, "to_shost: ");

		if (ioctl(s, SIOCGIFINDEX, ifr)) {
			E("ioctl SIOGIFINDEX fialed.\n");
			goto err;
		}
		g_ipf_send_ifindex[!IPF_CT_DIR_REPL] = ifr->ifr_ifindex;
		D("orig send ifindex: %d\n", g_ipf_send_ifindex[!IPF_CT_DIR_REPL]);
		break;
	}

	return 0;

err:
	close(s);
	return -1;
}

// ip & port provided in network byte order
void __ipf_block_tcp_port(uint32_t ip, uint16_t port)
{
	char cmd[1024] = {0};
	sprintf(cmd, "iptables -D INPUT -p tcp -j DROP");
	system(cmd);
	sprintf(cmd, "iptables -I INPUT -p tcp -j DROP");
	system(cmd);
	D("Block TCP port: %s\n", cmd);
	//D("Should block TCP RST packets to avoid been interrupted, with:\ncmd: %s\n", cmd);
}

int ipf_rule_prepare(struct ipf_rule *rule)
{
	if (rule->m.protocol == IPPROTO_TCP) {
		__ipf_block_tcp_port(rule->m.daddr, rule->m.port);
	}

	// fill needed information
	ipf_rule_fill_orig(rule, rule->m.daddr);
	ipf_rule_fill_repl(rule, rule->t.to_daddr);

	if (!g_ipf_send_ifindex[IPF_CT_DIR_ORIG]
	  || !g_ipf_send_ifindex[IPF_CT_DIR_REPL]) {
		E("find forwarding interface failed.\n");
		return 0;
	}
	return 1;
}

void __ipf_skb_queue(struct ipf_skb *skb)
{
	pthread_mutex_lock(&g_ipf_skb_list_lock);
	list_add_tail(&skb->list, &g_ipf_skb_head);
	pthread_mutex_unlock(&g_ipf_skb_list_lock);
}

struct ipf_skb *__ipf_skb_dequeue(void)
{
	struct ipf_skb *skb = NULL;

	pthread_mutex_lock(&g_ipf_skb_list_lock);
	if (list_empty(&g_ipf_skb_head)) {
		goto out;
	}
	skb = list_first_entry(&g_ipf_skb_head, struct ipf_skb, list);
	list_del(&skb->list);
out:
	pthread_mutex_unlock(&g_ipf_skb_list_lock);
	return skb;
}

void *__ipf_forward(void *arg)
{
	struct ipf_skb *skb = NULL;

	while (1) {
		skb = __ipf_skb_dequeue();
		if (!skb) {
			usleep(1); // sleep 1us
			continue;
		}
		ipf_setup_skb(skb);
		handle_ether_frame(skb, &g_ipf_rule);
		free(skb);
	}
}

int main(int argc, char *argv[])
{
	if (!ipf_rule_parse(&g_ipf_rule, argc, argv)) {
		E("parse forward rule failed.\n");
		return 1;
	}

	if (!ipf_rule_prepare(&g_ipf_rule)) {
		E("prepare forward rule failed.\n");
		return 1;
	}

	I("prepare forward rule success.\n");

	if (pthread_create(&g_ipf_forwarding_thread, NULL,
			__ipf_forward, NULL) != 0) {
		E("create forwarding thread failed.\n");
		return 1;
	}

	g_raw_sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (g_raw_sockfd == -1)
	{
		E("socket error!\n");
		return 1;
	}

	I("create capture socket success.\n");

	while (1)
	{
		struct ipf_skb *skb = ipf_skb_alloc(IPF_MAX_FRAME_SIZE);
		if (!skb) {
			E("memory not enough...\n");
			usleep(10000);
			continue;
		}

		ssize_t n = recv(g_raw_sockfd, skb->frame, IPF_MAX_FRAME_SIZE, 0);
		if (n == -1)
		{
			E("recv error!\n");
			free(skb);
			break;
		}
		else if (n == 0) {
			free(skb);
			continue;
		}

		skb->len = (uint32_t)n;
		__ipf_skb_queue(skb);
	}

	close(g_raw_sockfd);
	return 0;
}

