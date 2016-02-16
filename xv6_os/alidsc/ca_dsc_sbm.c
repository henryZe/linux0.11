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
#include <linux/slab.h>
#include "ca_dsc_priv.h"
#include "ca_dsc_rpc.h"
#include "ca_dsc_sbm.h"

int open_sbm(struct ca_dsc_session *s)
{
	int rc;

	s->sbm.buf_size = DSC_SBM_NR_NODES * 2 * 4;
	s->sbm.buf_start = kmalloc(s->sbm.buf_size, GFP_KERNEL);
	if (!s->sbm.buf_start)
		return -ENOMEM;

	/*s->sbm.buf_start = (UINT32)(s->sbm.buf_start)&0x1FFFFFFF;*/
	memset(s->sbm.buf_start, 0, s->sbm.buf_size);
	s->sbm.priv_data = (void *)s;
	rc = see_sbm_create(&s->sbm);
	if (rc) {
		dev_dbg(s->dsc->dev, "create sbm error!\n");
		return rc;
	}

	dev_dbg(s->dsc->dev, "create_sbm:id[%d],addr[%p],size[%x]\n",
		s->sbm.id, s->sbm.buf_start, s->sbm.buf_size);

	return ali_dsc_create_sbm_task(s->dsc, s->sbm.id);
}

int close_sbm(struct ca_dsc_session *s)
{
	int ret;
	int sbm_id = s->sbm.id;

	ret = see_sbm_destroy(&s->sbm);
	if (ret) {
		dev_dbg(s->dsc->dev, "delete sbm error!\n");
		return ret;
	}

	kfree(s->sbm.buf_start);
	return ali_dsc_delete_sbm_task(s->dsc, sbm_id);
}

int write_sbm(struct ca_dsc_session *s, char *buf, size_t count,
	struct see_sbm_entry *sbm_entry)
{
	int rc;

	rc = see_enqueue_sbm_entry(&s->sbm, buf, count, sbm_entry);
	if (rc) {
		dev_dbg(s->dsc->dev, "add sbm entry error!\n");
		return rc;
	}

	return 0;
}

/*
	0: finish
	1: query failed or not finish
*/
int query_sbm_entry(struct ca_dsc_session *s,
	struct see_sbm_entry *sbm_entry)
{
	/* Not enqueue SBM yet*/
	if (!sbm_entry->entry)
		return 1;

	return see_query_sbm_entry(&s->sbm, sbm_entry);
}

