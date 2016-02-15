/*
 * Copyright(C) 2015 ALi Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __CA_SHA_SYSFS_H__
#define __CA_SHA_SYSFS_H__

#include "ali_sha.h"

#ifdef CONFIG_SYSFS
int ca_sha_sysfs_create(struct ali_sha_dev *psha);
void ca_sha_sysfs_remove(struct ali_sha_dev *psha);
#else
inline int ca_sha_sysfs_create(struct ali_sha_dev *psha) { return -ENOSYS; };
inline void ca_sha_sysfs_remove(struct ali_sha_dev *psha) { return; };
#endif

#endif
