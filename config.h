/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IPF_CONFIG_H_
#define _IPF_CONFIG_H_

struct ipf_match {
#define IPF_MATCH_DADDR     0x1
#define IPF_MATCH_PROTOCOL  0x2
#define IPF_MATCH_PORT      0x4
	uint32_t flag;
	uint32_t daddr;      //configured
	uint8_t  protocol;   //configured
	uint16_t port;       //configured  /* In network byte order */
};

struct ipf_target {
	uint32_t to_daddr;  //configured
	uint32_t to_saddr;       // get from system
	uint8_t  to_shost[6];    // get from system
	uint8_t  to_dhost[6];    // get from system
};

struct ipf_rule {
	struct ipf_match  m;
	struct ipf_target t;
};

#endif /* _IPF_CONFIG_H_ */

