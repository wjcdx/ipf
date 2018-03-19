/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IPF_DNAT_H_
#define _IPF_DNAT_H_

#include "config.h"
#include "conntrack.h"

int ipf_rule_match(struct ipf_skb *skb, struct ipf_rule *rule);
int ipf_rule_jump_target(struct ipf_skb *skb, struct ipf_rule *rule);

#endif /* _IPF_DNAT_H_ */

