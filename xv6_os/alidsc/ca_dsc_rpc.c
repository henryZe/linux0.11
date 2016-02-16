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
#include <ali_cache.h>
#include "ca_dsc_priv.h"
#include <ali_rpcng.h>

#undef UC
#define UC(x) ((void *)(((UINT32)(x)&0xBFFFFFFF)|0xa0000000))

int ali_dsc_umemcpy(void *dest, const void *src, __u32 n)
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

int ali_des_ioctl(struct ca_dsc_dev *dsc,
	DES_DEV *pDesDev, __u32 cmd, __u32 param)
{
	struct see_client *clnt = dsc->clnt;
	KEY_PARAM *key_param = (KEY_PARAM *)param;
	struct dsc_clr_key *dsc_key = (struct dsc_clr_key *)dsc->dsc_key;
	DES_INIT_PARAM des_param;
	PID_PARAM pid_param;
	IV_OTHER_PARAM other_param;
	Param p1;
	Param p2;
	Param p3;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pDesDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&cmd);
	RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&param);

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(IO_INIT_CMD):
		ali_dsc_umemcpy(&des_param, (void *)param,
			sizeof(DES_INIT_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Des_init_param_rpc,
			sizeof(Des_init_param_rpc), (void *)&des_param);
	break;

	case DSC_IO_CMD(IO_CREAT_CRYPT_STREAM_CMD):
	case DSC_IO_CMD(IO_KEY_INFO_UPDATE_CMD): {
		if (key_param->pid_list && key_param->pid_len) {
			ali_dsc_umemcpy((dsc_key->pid_ptr), key_param->pid_list,
				sizeof(__u16)*(key_param->pid_len));
			key_param->pid_list = UC(dsc_key->pid_ptr);
		}

		if (key_param->p_des_key_info) {
			ali_dsc_umemcpy((dsc_key->key_ptr),
				key_param->p_des_key_info,
				2*key_param->key_length/8);
			key_param->p_des_key_info = UC(dsc_key->key_ptr);
		}

		if (key_param->p_des_iv_info) {
			ali_dsc_umemcpy((dsc_key->iv_ptr),
				key_param->p_des_iv_info,
				2*DES_BLOCK_LEN);
			key_param->p_des_iv_info = UC(dsc_key->iv_ptr);
		}

		if (key_param->init_vector) {
			ali_dsc_umemcpy((dsc_key->iv_ptr),
				key_param->init_vector,
				DES_BLOCK_LEN);
			key_param->init_vector = UC(dsc_key->iv_ptr);
		}

		RPC_PARAM_UPDATE(p3, PARAM_INOUT, PARAM_Key_param_rpc,
			sizeof(Key_param_rpc), (void *)key_param);
		break;
	}

	case DSC_IO_CMD(IO_ADD_DEL_PID): {
		memcpy(&pid_param, (void *)param, sizeof(PID_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_Pid_param_rpc,
			sizeof(dsc_Pid_param_rpc), (void *)&pid_param);
		break;
	}

	case DSC_IO_CMD(IO_PARAM_INFO_UPDATE): {
		memcpy(&other_param, (void *)param, sizeof(IV_OTHER_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_Other_param_rpc,
			sizeof(dsc_Other_param_rpc), (void *)&other_param);
		break;
	}

	case DSC_IO_CMD(IO_DELETE_CRYPT_STREAM_CMD):
		break;

	case DSC_IO_CMD(IO_CONTINUOUS_RENEW):
		break;

	default:
	    dev_dbg(dsc->dev, "Dsc rpc invalid cmd=%d\n", cmd);
		break;
	}

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_des_ioctl, &p1, &p2, &p3, NULL);
}

int ali_aes_ioctl(struct ca_dsc_dev *dsc,
	AES_DEV *pAesDev, __u32 cmd, __u32 param)
{
	struct see_client *clnt = dsc->clnt;
	KEY_PARAM *key_param = (KEY_PARAM *)param;
	struct dsc_clr_key *dsc_key = (struct dsc_clr_key *)dsc->dsc_key;
	AES_INIT_PARAM aes_param;
	PID_PARAM pid_param;
	IV_OTHER_PARAM other_param;
	Param p1;
	Param p2;
	Param p3;
	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pAesDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&cmd);
	RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&param);

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(IO_INIT_CMD):
		memcpy(&aes_param, (void *)param, sizeof(AES_INIT_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Aes_init_param_rpc,
			sizeof(Aes_init_param_rpc), (void *)&aes_param);
	break;

	case DSC_IO_CMD(IO_CREAT_CRYPT_STREAM_CMD):
	case DSC_IO_CMD(IO_KEY_INFO_UPDATE_CMD): {
		if (key_param->pid_list && key_param->pid_len) {
			memcpy((dsc_key->pid_ptr), key_param->pid_list,
				sizeof(__u16)*(key_param->pid_len));
			key_param->pid_list = UC(dsc_key->pid_ptr);
		}

		if (key_param->p_aes_key_info) {
			memcpy((dsc_key->key_ptr), key_param->p_aes_key_info,
				2*key_param->key_length/8);
			key_param->p_aes_key_info =
				UC(dsc_key->key_ptr);
		}

		if (key_param->p_aes_iv_info) {
			memcpy((dsc_key->iv_ptr), key_param->p_aes_iv_info,
				2*AES_BLOCK_LEN);
			key_param->p_aes_iv_info = UC(dsc_key->iv_ptr);
		}

		if (key_param->init_vector) {
			memcpy((dsc_key->iv_ptr), key_param->init_vector,
				AES_BLOCK_LEN);
			key_param->init_vector = UC(dsc_key->iv_ptr);
		}

		if (key_param->ctr_counter) {
			memcpy((dsc_key->ctr_ptr), key_param->ctr_counter,
				AES_BLOCK_LEN);
			key_param->ctr_counter = UC(dsc_key->ctr_ptr);
		}

		RPC_PARAM_UPDATE(p3, PARAM_INOUT, PARAM_Key_param_rpc,
			sizeof(Key_param_rpc), (void *)key_param);
		break;
	}

	case DSC_IO_CMD(IO_ADD_DEL_PID): {
		memcpy(&pid_param, (void *)param, sizeof(PID_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_Pid_param_rpc,
			sizeof(dsc_Pid_param_rpc), (void *)&pid_param);
		break;
	}

	case DSC_IO_CMD(IO_PARAM_INFO_UPDATE): {
		memcpy(&other_param, (void *)param, sizeof(IV_OTHER_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_Other_param_rpc,
			sizeof(dsc_Other_param_rpc), (void *)&other_param);
		break;
	}

	case DSC_IO_CMD(IO_DELETE_CRYPT_STREAM_CMD):
		break;

	case DSC_IO_CMD(IO_CONTINUOUS_RENEW):
		break;

	default:
		dev_dbg(dsc->dev, "Dsc rpc invalid cmd=%d\n", cmd);
		break;
	}

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_aes_ioctl, &p1, &p2, &p3, NULL);
}

int ali_dsc_ioctl(struct ca_dsc_dev *dsc,
	DSC_DEV *pDscDev, __u32 cmd, __u32 param)
{
	struct see_client *clnt = dsc->clnt;
	DSC_PVR_KEY_PARAM *pvr_key = (DSC_PVR_KEY_PARAM *)param;
	Param p1;
	Param p2;
	Param p3;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pDscDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&cmd);
	RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&param);

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(IO_PARSE_DMX_ID_GET_CMD):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_UINT32,
			sizeof(__u32), (void *)param);
		break;
	case DSC_IO_CMD(IO_PARSE_DMX_ID_SET_CMD):
		break;
	case DSC_IO_CMD(IO_DSC_GET_DES_HANDLE):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_UINT32,
			sizeof(__u32), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_GET_AES_HANDLE):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_UINT32,
			sizeof(__u32), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_GET_CSA_HANDLE):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_UINT32,
			sizeof(__u32), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_GET_SHA_HANDLE):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_UINT32,
			sizeof(__u32), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_SET_PVR_KEY_PARAM):
		if (pvr_key->input_addr) {
			ali_dsc_umemcpy(dsc->dsc_key,
			(const void *)pvr_key->input_addr,
			pvr_key->valid_key_num*pvr_key->pvr_key_length/8);
			pvr_key->input_addr = (__u32)UC(dsc->dsc_key);
		} else {
			return RET_FAILURE;
		}
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_pvr_key_param_rpc,
			sizeof(Dsc_pvr_key_param_rpc), (void *)pvr_key);
		break;
	case DSC_IO_CMD(IO_DSC_SET_ENCRYPT_PRIORITY):
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_deen_parity_rpc,
			sizeof(Dsc_deen_parity_rpc), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_GET_DRIVER_VERSION):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_Dsc_drv_ver_rpc,
			sizeof(Dsc_drv_ver_rpc), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_VER_CHECK):
		RPC_PARAM_UPDATE(p3, PARAM_OUT, PARAM_Dsc_ver_chk_param_rpc,
			sizeof(Dsc_ver_chk_param_rpc), (void *)param);
		break;
	case DSC_IO_CMD(IO_DSC_SET_PVR_KEY_IDLE):
	case DSC_IO_CMD(IO_DSC_SET_CLR_CMDQ_EN):
	case DSC_IO_CMD(IO_DSC_DELETE_HANDLE_CMD):
		break;
	case DSC_IO_CMD(IO_DSC_FIXED_DECRYPTION):
	case DSC_IO_CMD(IO_DSC_SYS_UK_FW):
	default:
		return ALI_DSC_ERROR_OPERATION_NOT_SUPPORTED;
	}

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_ioctl, &p1, &p2, &p3, NULL);
}

__u16 ali_dsc_get_free_stream_id(struct ca_dsc_dev *dsc,
	enum DMA_MODE dma_mode)
{
	struct see_client *clnt = dsc->clnt;

	RPC_PARAM_CREATE(p1, PARAM_IN, PARAM_ENUM,
		sizeof(enum DMA_MODE), &dma_mode);
	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_get_free_stream_id, &p1, NULL);
}

__u32 ali_dsc_get_free_sub_device_id(struct ca_dsc_dev *dsc,
	__u8 sub_mode)
{
	struct see_client *clnt = dsc->clnt;

	RPC_PARAM_CREATE(p1, PARAM_IN, PARAM_UCHAR,
		sizeof(__u8), &sub_mode);
	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_get_free_sub_device_id, &p1, NULL);
}

int ali_dsc_set_sub_device_id_idle(struct ca_dsc_dev *dsc,
	__u8 sub_mode, __u32 device_id)
{
	Param p1;
	Param p2;
	struct see_client *clnt = dsc->clnt;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UCHAR,
		sizeof(__u8), (void *)&sub_mode);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&device_id);

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_set_sub_device_id_idle, &p1, &p2, NULL);
}

int ali_dsc_set_stream_id_idle(struct ca_dsc_dev *dsc,
	__u32 pos)
{
	struct see_client *clnt = dsc->clnt;

	RPC_PARAM_CREATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), &pos);
	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_set_stream_id_idle, &p1, NULL);
}

int ali_csa_ioctl(struct ca_dsc_dev *dsc,
	CSA_DEV *pCsaDev, __u32 cmd, __u32 param)
{
	struct see_client *clnt = dsc->clnt;
	KEY_PARAM *key_param = (KEY_PARAM *)param;
	struct dsc_clr_key *dsc_key = (struct dsc_clr_key *)dsc->dsc_key;
	CSA_INIT_PARAM csa_param;
	PID_PARAM pid_param;
	IV_OTHER_PARAM other_param;
	Param p1;
	Param p2;
	Param p3;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&pCsaDev);
	RPC_PARAM_UPDATE(p2, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&cmd);
	RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&param);

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(IO_INIT_CMD):
		ali_dsc_umemcpy(&csa_param, (void *)param,
			sizeof(csa_param));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Csa_init_param_rpc,
			sizeof(Csa_init_param_rpc), (void *)&csa_param);
		break;

	case DSC_IO_CMD(IO_CREAT_CRYPT_STREAM_CMD):
	case DSC_IO_CMD(IO_KEY_INFO_UPDATE_CMD): {
		if (key_param->pid_list && key_param->pid_len) {
			ali_dsc_umemcpy((dsc_key->pid_ptr), key_param->pid_list,
				sizeof(__u16)*(key_param->pid_len));
			key_param->pid_list = UC(dsc_key->pid_ptr);
		}

		if (key_param->p_csa_key_info) {
			ali_dsc_umemcpy((dsc_key->key_ptr),
				key_param->p_csa_key_info,
				2*key_param->key_length/8);
			key_param->p_csa_key_info =
				UC(dsc_key->key_ptr);
		}

		RPC_PARAM_UPDATE(p3, PARAM_INOUT, PARAM_Key_param_rpc,
			sizeof(Key_param_rpc), (void *)key_param);
		break;
	}

	case DSC_IO_CMD(IO_ADD_DEL_PID): {
		memcpy(&pid_param, (void *)param, sizeof(PID_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_Pid_param_rpc,
			sizeof(dsc_Pid_param_rpc), (void *)&pid_param);
		break;
	}

	case DSC_IO_CMD(IO_PARAM_INFO_UPDATE): {
		memcpy(&other_param, (void *)param, sizeof(IV_OTHER_PARAM));
		RPC_PARAM_UPDATE(p3, PARAM_IN, PARAM_Dsc_Other_param_rpc,
			sizeof(dsc_Other_param_rpc), (void *)&other_param);
		break;
	}

	case DSC_IO_CMD(IO_DELETE_CRYPT_STREAM_CMD):
		break;

	default:
	    dev_dbg(dsc->dev, "Dsc rpc invalid cmd=%d\n", cmd);
		break;
	}

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_csa_ioctl, &p1, &p2, &p3, NULL);
}

void ali_m36_dsc_see_init(struct ca_dsc_dev *dsc)
{
	struct see_client *clnt = dsc->clnt;

	__rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_api_attach, NULL);
}

void ali_m36_dsc_see_uninit(struct ca_dsc_dev *dsc)
{
	struct see_client *clnt = dsc->clnt;
	__rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_api_detach, NULL);
}

int ali_dsc_create_sbm_task(struct ca_dsc_dev *dsc,
	UINT32 sbm_id)
{
	struct see_client *clnt = dsc->clnt;
	Param p1;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&sbm_id);

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_create_sbm_task, &p1, NULL);
}

int ali_dsc_delete_sbm_task(struct ca_dsc_dev *dsc,
	UINT32 sbm_id)
{
	struct see_client *clnt = dsc->clnt;
	Param p1;

	RPC_PARAM_UPDATE(p1, PARAM_IN, PARAM_UINT32,
		sizeof(__u32), (void *)&sbm_id);

	return __rpc_service_call_completion(clnt,
		ALIRPC_RPC_dsc_delete_sbm_task, &p1, NULL);
}


