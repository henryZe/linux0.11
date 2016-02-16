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

#ifndef __CA_DSC_DBGFS_H__
#define __CA_DSC_DBGFS_H__

#include "ca_dsc_priv.h"

#ifdef CONFIG_DEBUG_FS
void ca_dsc_dbgfs_create(struct ca_dsc_dev *dsc);
void ca_dsc_dbgfs_remove(struct ca_dsc_dev *dsc);
int ca_dsc_dbgfs_add_session(struct ca_dsc_session *sess);
int ca_dsc_dbgfs_del_session(struct ca_dsc_session *sess);
#else
inline void ca_dsc_dbgfs_create(struct ca_dsc_dev *dsc) {};
inline void ca_dsc_dbgfs_remove(struct ca_dsc_dev *dsc) {};
inline int ca_dsc_dbgfs_add_session(struct ca_dsc_session *sess)
{
	return -ENOSYS;
}
inline int ca_dsc_dbgfs_del_session(struct ca_dsc_session *sess)
{
	return -ENOSYS;
}
#endif

#endif
