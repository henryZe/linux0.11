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

#ifndef _CA_DSC_SBM_H_
#define _CA_DSC_SBM_H_

#include "ca_dsc_priv.h"
#include "ali_sbm_client.h"

struct ca_dsc_session;

int open_sbm(struct ca_dsc_session *s);
int close_sbm(struct ca_dsc_session *s);
int write_sbm(struct ca_dsc_session *s, char *buf, size_t count,
	struct see_sbm_entry *sbm_entry);
int query_sbm_entry(struct ca_dsc_session *s,
	struct see_sbm_entry *sbm_entry);

#endif /*_CA_DSC_SBM_H_*/
