/*
 * DeScrambler Core driver
 * Copyright(C) 2014 ALi Corporation. All rights reserved.
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
#ifndef __CA_DSC_SYSFS_H__
#define __CA_DSC_SYSFS_H__

#include "ca_dsc_priv.h"

#ifdef CONFIG_SYSFS
int ca_dsc_sysfs_create(struct ca_dsc_dev *dsc);
void ca_dsc_sysfs_remove(struct ca_dsc_dev *dsc);
#else
inline int ca_dsc_sysfs_create(struct ca_dsc_dev *dsc) { return -ENOSYS; };
inline void ca_dsc_sysfs_remove(struct ca_dsc_dev *dsc) { return; };
#endif

#endif
