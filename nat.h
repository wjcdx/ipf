/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IPF_NAT_H_
#define _IPF_NAT_H_

#include "conntrack.h"

void ipf_learn(struct ipf_conn *conn,
		struct ipf_ct_tuple *tuple, int dir);
int ipf_nat(struct ipf_skb *skb, struct ipf_conn *conn);

#endif /* _IPF_NAT_H_ */

