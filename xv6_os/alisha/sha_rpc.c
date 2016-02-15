/*
 * Security Hashing Algorithm driver
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/semaphore.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>

#include "ali_sha.h"
#include <ali_rpcng.h>

static int ali_umemcpy(void *dest, const void *src, __u32 n)
{
	int ret = 0;
	int sflag = access_ok(VERIFY_READ, (void __user *)src, n);
	int dflag = access_ok(VERIFY_WRITE, (void __user *)dest, n);

	if (segment_eq(get_fs(), USER_DS)) {
		if (sflag && !dflag)
			ret = copy_from_user(dest, (void __user *)src, n);
		else if (dflag && !sflag)
			ret = copy_to_user(dest, src, n);
		else if (!sflag && !dflag)
			memcpy(dest, src, n);
		else
			return -1;
	} else {
		memcpy(dest, src, n);
	}

	return ret;
}

int see_sha_sbm_open(SHA_DEV *pShaDev, int sbm_id)
{
	Param p1;
	Param p2;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pShaDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_INT32,
		sizeof(int), (void *)&sbm_id);

	return RpcCallCompletion(RPC_sha_sbm_open,
			&p1, &p2, NULL);
}

int ali_sha_ioctl(SHA_DEV *pShaDev, __u32 cmd, __u32 param)
{
	Param p1;
	Param p2;
	Param p3;
	SHA_INIT_PARAM sha_param;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pShaDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&cmd);
	RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&param);

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(IO_INIT_CMD):
		ali_umemcpy(&sha_param, (void *)param,
			sizeof(sha_param));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Sha_init_param_rpc,
			sizeof(Sha_init_param_rpc), (void *)&sha_param);
		break;

	default:
		pr_info("sha rpc error: invalid cmd %d\n", cmd);
		return RET_FAILURE;
	}

	return RpcCallCompletion(RPC_sha_ioctl, &p1, &p2, &p3, NULL);
}

int ali_sbm_release_task(int sbm_id)
{
	Param p1;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_INT32,
		sizeof(int), (void *)&sbm_id);

	return RpcCallCompletion(RPC_sha_delete_sbm_task,
		&p1, NULL);
}

int ali_sha_digest(SHA_DEV *pShaDev,
	__u8 *input, __u8 *output, u32 data_len)
{
	int ret = -1;
	Sha_hash_rpc hash_out;
	Param p1;
	Param p2;
	Param p3;
	Param p4;

	memset((void *)&hash_out, 0x00, sizeof(hash_out));

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pShaDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&input);
	RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_Sha_hash_rpc,
		sizeof(Sha_hash_rpc), (void *)&hash_out);
	RPC_PARAM_UPDATE(p4, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&data_len);

	ret = RpcCallCompletion(RPC_sha_digest,
		&p1, &p2, &p3, &p4, NULL);

	memcpy(output, hash_out.hash, sizeof(hash_out));

	return ret;
}

void ali_m36_sha_see_init(void)
{
	RpcCallCompletion(RPC_dsc_api_attach, NULL);
}

__u32 ali_sha_get_free_sub_device_id(void)
{
	__u8 sub_mode = SHA;

	RPC_PARAM_CREATE(p1, PARAM_IN, PARAM_UCHAR,
		sizeof(__u8), &sub_mode);

	return RpcCallCompletion(RPC_dsc_get_free_sub_device_id,
		&p1, NULL);
}

int ali_sha_set_sub_device_id_idle(__u32 device_id)
{
	__u8 sub_mode = SHA;
	Param p1;
	Param p2;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UCHAR,
		sizeof(__u8), (void *)&sub_mode);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&device_id);

	return RpcCallCompletion(RPC_dsc_set_sub_device_id_idle,
		&p1, &p2, NULL);
}


