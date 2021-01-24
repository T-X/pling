/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2021, Linus Lüssing
 */

#ifndef __TIMES_H__
#define __TIMES_H__

static inline struct timespec timespec_sum(const struct timespec aug,
					   const struct timespec add)
{
	struct timespec res = aug;

	res.tv_sec += add.tv_sec;
	res.tv_nsec += add.tv_nsec;

	if (res.tv_nsec >= 1000000000L) {
		res.tv_sec++;
		res.tv_nsec -= 1000000000L;
	}

	return res;
}

static inline int64_t timespec_diffus(const struct timespec before,
				      const struct timespec after)
{
	int64_t diff_us = (int64_t)after.tv_sec - (int64_t)before.tv_sec;

	diff_us *= 1000 * 1000;
	diff_us += ((int64_t)after.tv_nsec - (int64_t)before.tv_nsec) / 1000;

	return diff_us;
}

#endif /* __TIMES_H__ */
