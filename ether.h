/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2021, Linus Lüssing
 */

#ifndef __ETHER_H__
#define __ETHER_H__

#include <stdio.h>
#include "main.h"

extern struct pling_config pling_config;

static inline int eth_str2bin(const char *src, unsigned char *dst)
{
	unsigned int d[ETH_ALEN];

	if (sscanf(src, "%x:%x:%x:%x:%x:%x%*c",
		   &d[0], &d[1], &d[2], &d[3], &d[4], &d[5]) != 6)
		return -EINVAL;

	for (int i = 0; i < ETH_ALEN; i++)
		dst[i] = (unsigned char)d[i];

	return 0;
}

static inline void eth_bin2str(const unsigned char *src, char *dst)
{
	sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned int)src[0],
		(unsigned int)src[1],
		(unsigned int)src[2],
		(unsigned int)src[3],
		(unsigned int)src[4],
		(unsigned int)src[5]);
}

static inline int eth_is_zero(unsigned char *ethaddr)
{
	const static unsigned char ethzeroaddr[ETH_ALEN] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	return !memcmp(ethaddr, ethzeroaddr, ETH_ALEN);
}

static inline int eth_is_own(unsigned char *ethaddr)
{
	return !memcmp(ethaddr, pling_config.ifaddr, ETH_ALEN);
}

static inline int eth_is_multicast(unsigned char *ethaddr)
{
	return ethaddr[0] & 0x01;
}

static inline void eth_copy(unsigned char *dst, const unsigned char *src)
{
	memcpy(dst, src, ETH_ALEN);
}

#endif /* __ETHER_H__ */
