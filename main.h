/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2021, Linus Lüssing
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#include "list.h"

struct pling_config {
	unsigned long count;
	unsigned long size;
	unsigned long interval;	/* in milliseconds */
	int listen;
	const char *ifname;
	int ifindex;
	unsigned char ifaddr[ETH_ALEN];
	struct list_head hosts;
	unsigned char replyto[ETH_ALEN];
};

struct pling_host {
	unsigned char host[ETH_ALEN];
	struct list_head node;
};

#endif /* __MAIN_H__ */
