/*
 * (C) 2018 Wang Jianchang <wjcdx@qq.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _IPF_DEBUG_H_
#define _IPF_DEBUG_H_

#ifdef DEBUG
#define D(fmt, args...) printf(fmt, ##args)
#define I(fmt, args...) printf(fmt, ##args)
#define E(fmt, args...) printf("ERROR: "fmt, ##args)
#define D_NOP(v)
#else
#define D(fmt, args...)
#define I(fmt, args...) printf(fmt, ##args)
#define E(fmt, args...) printf("ERROR: "fmt, ##args)
#define D_NOP(v) ((void)v)
#endif

#endif /* _IPF_DEBUG_H_ */

