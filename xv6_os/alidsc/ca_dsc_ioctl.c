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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/splice.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/file.h>

#include <ca_dsc.h>
#include "ca_dsc_ioctl.h"
#include "ca_dsc_ioctl_legacy.h"
#include "ca_dsc_priv.h"
#include "ca_dsc_rpc.h"
#include "../ali_kl_fd_framework/ca_kl_fd_dispatch.h"

#define INVALID_CA_FORMAT(format) ( \
	(format) != CA_FORMAT_RAW && \
	(format) != CA_FORMAT_TS188 && \
	(format) != CA_FORMAT_TS188_LTSID && \
	(format) != CA_FORMAT_TS200)

#define INVALID_ALGO(algo) ((algo) != CA_ALGO_AES && \
	(algo) != CA_ALGO_DES && \
	(algo) != CA_ALGO_TDES && \
	(algo) != CA_ALGO_CSA1 && \
	(algo) != CA_ALGO_CSA2 && \
	(algo) != CA_ALGO_CSA3)

#define INVALID_RESIDUE_MODE(mode) ( \
	(mode) != CA_RESIDUE_CLEAR && \
	(mode) != CA_RESIDUE_AS_ATSC && \
	(mode) != CA_RESIDUE_HW_CTS)

#define INVALID_WORK_MODE(mode) ( \
	(mode) != CA_MODE_ECB && \
	(mode) != CA_MODE_CBC && \
	(mode) != CA_MODE_CFB && \
	(mode) != CA_MODE_CTR && \
	(mode) != CA_MODE_OFB)

#define NEED_IV(mode) ( \
	(mode) == CA_MODE_CBC || \
	(mode) == CA_MODE_CFB || \
	(mode) == CA_MODE_OFB || \
	(mode) == CA_MODE_CTR)

#define INVALID_PARITY(parity) ( \
	((parity) != CA_PARITY_ODD) && \
	((parity) != CA_PARITY_EVEN) && \
	((parity) != CA_PARITY_AUTO))

#define INVALID_TSC(tsc) ( \
	((tsc) != DSC_TSC_CLEAR_EVEN) && \
	((tsc) != DSC_TSC_CLEAR_ODD) && \
	((tsc) != DSC_TSC_CIPHER_EVEN) && \
	((tsc) != DSC_TSC_CIPHER_ODD))

/*#define INVALID_IV_PARITY(parity) ( \
	(parity) != CA_IV_PARITY_ODD && \
	(parity) != CA_IV_PARITY_EVEN && \
	(parity) != CA_IV_PARITY_ODD_EVEN && \
	(parity) != CA_IV_PARITY_NONE)*/

#define INVALID_CRYPT_MODE(crypt) ( \
	(crypt) != CA_ENCRYPT && (crypt) != CA_DECRYPT)

#define INVALID_AES_KEY_SIZE(size) ( \
	(size) != 16 && (size) != 24 && (size) != 32)
#define INVALID_DES_KEY_SIZE(size) ( \
	(size) != 8)
#define INVALID_TDES_KEY_SIZE(size) ( \
	(size) != 16 && (size) != 24)
#define INVALID_CSA1_KEY_SIZE(size) ( \
	(size) != 8)
#define INVALID_CSA2_KEY_SIZE(size) ( \
	(size) != 8)
#define INVALID_CSA3_KEY_SIZE(size) ( \
	(size) != 16)

static const int g_switch_parity[] = {
	[CA_PARITY_AUTO] = AUTO_PARITY_MODE0,
	[CA_PARITY_ODD] = ODD_PARITY_MODE,
	[CA_PARITY_EVEN] = EVEN_PARITY_MODE,
};

static const int g_switch_residue[] = {
	[CA_RESIDUE_CLEAR] = RESIDUE_BLOCK_IS_NO_HANDLE,
	[CA_RESIDUE_AS_ATSC] = RESIDUE_BLOCK_IS_AS_ATSC,
	[CA_RESIDUE_HW_CTS] = RESIDUE_BLOCK_IS_HW_CTS,
};

static const int g_switch_chaining[] = {
	[CA_MODE_ECB] = WORK_MODE_IS_ECB,
	[CA_MODE_CBC] = WORK_MODE_IS_CBC,
	[CA_MODE_OFB] = WORK_MODE_IS_OFB,
	[CA_MODE_CFB] = WORK_MODE_IS_CFB,
	[CA_MODE_CTR] = WORK_MODE_IS_CTR,
	[CA_MODE_CTR8] = WORK_MODE_IS_CTR,
};

static const int g_switch_otp_sel[] = {
	[CA_OTP_KEY_6] = OTP_KEY_FROM_68,
	[CA_OTP_KEY_7] = OTP_KEY_FROM_6C,
	[CA_OTP_KEY_FP] = OTP_KEY_FROM_FP,
};

static int dsc_fetch_streamId(struct ca_dsc_session *s)
{
	int ret = (-EIO);

	/*Get free stream ID*/
	s->stream_id = ali_dsc_get_free_stream_id(s->dsc, s->dma_mode);
	if (ALI_INVALID_CRYPTO_STREAM_ID == s->stream_id) {
		dev_dbg(s->dsc->dev, "Get free stream ID error!\n");
		goto LOCAL_CLEAR;
	}

	dev_dbg(s->dsc->dev, "stream_id[%x]\n", s->stream_id);

	s->stream_id_flag = 1;
	return 0;

LOCAL_CLEAR:
	if (ALI_INVALID_CRYPTO_STREAM_ID != s->stream_id) {
		ali_dsc_set_stream_id_idle(s->dsc, s->stream_id);
		s->stream_id = ALI_INVALID_CRYPTO_STREAM_ID;
	}

	return ret;
}

static int dsc_fetch_subdevice(struct ca_dsc_session *s)
{
	int ret = (-EIO);
	struct ca_dsc_dev *dsc = NULL;

	dsc = s->dsc;
	/*Get Sub device ID*/
	s->sub_dev_id = ali_dsc_get_free_sub_device_id(s->dsc, s->sub_module);
	if (ALI_INVALID_DSC_SUB_DEV_ID == s->sub_dev_id ||
		s->sub_dev_id >= VIRTUAL_DEV_NUM) {
		dev_dbg(s->dsc->dev, "SubID[%x] err!\n", s->sub_dev_id);
		goto LOCAL_CLEAR;
	}

	/*Get Sub device Handler*/
	switch (s->sub_module) {
	case AES:
		s->sub_dev_see_hdl = (__u32)dsc->see_aes_id[s->sub_dev_id];
		break;
	case DES:
	case TDES:
		s->sub_dev_see_hdl = (__u32)dsc->see_des_id[s->sub_dev_id];
		break;
	case CSA:
		s->sub_dev_see_hdl = (__u32)dsc->see_csa_id[s->sub_dev_id];
		break;
	case SHA:
		s->sub_dev_see_hdl = (__u32)dsc->see_sha_id[s->sub_dev_id];
		break;
	default:
		dev_dbg(s->dsc->dev, "invalid algo mode!!\n");
		goto LOCAL_CLEAR;
	}

	dev_dbg(s->dsc->dev, "SubM[%x],DmaM[%x],SubID[%x],SeeHdl[%x]\n",
	s->sub_module, s->dma_mode, s->sub_dev_id, s->sub_dev_see_hdl);

	return 0;

LOCAL_CLEAR:
	if (ALI_INVALID_DSC_SUB_DEV_ID != s->sub_dev_id) {
		ali_dsc_set_sub_device_id_idle(s->dsc,
			s->sub_module, s->sub_dev_id);
		s->sub_dev_id = ALI_INVALID_DSC_SUB_DEV_ID;
	}
	return ret;
}

static int dsc_free_streamid(struct ca_dsc_session *s)
{
	struct ca_dsc_dev *dsc = NULL;
	dsc = s->dsc;

	if (ALI_INVALID_CRYPTO_STREAM_ID != s->stream_id) {
		ali_dsc_set_stream_id_idle(s->dsc, s->stream_id);
		s->stream_id = ALI_INVALID_CRYPTO_STREAM_ID;
	}

	return 0;
}

int dsc_release_internel_resource(struct ca_dsc_session *s)
{
	struct ca_dsc_dev *dsc = NULL;
	dsc = s->dsc;

	if (ALI_INVALID_CRYPTO_STREAM_ID != s->stream_id) {
		ali_dsc_set_stream_id_idle(s->dsc, s->stream_id);
		s->stream_id = ALI_INVALID_CRYPTO_STREAM_ID;
	}
	if (ALI_INVALID_DSC_SUB_DEV_ID != s->sub_dev_id) {
		ali_dsc_set_sub_device_id_idle(s->dsc,
			s->sub_module, s->sub_dev_id);
		s->sub_dev_id = ALI_INVALID_DSC_SUB_DEV_ID;
	}

	return 0;
}

static int dsc_create_aes_stream(struct ca_dsc_session *s,
	AES_INIT_PARAM *paes_init, KEY_PARAM *pkeyparam)
{
	int ret = 0;
	unsigned char see_ts_fmt[] = {
		[CA_FORMAT_RAW] = 0,
		[CA_FORMAT_TS188] = 0,
		[CA_FORMAT_TS188_LTSID] = 2,
		[CA_FORMAT_TS200] = 1,
	};

	paes_init->ts_format = see_ts_fmt[s->format];
	paes_init->continuous = s->ts_chaining;
	paes_init->sc_mode = s->sc_mode;

	ret = ali_aes_ioctl(s->dsc, (AES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_INIT_CMD),
			(__u32)paes_init);
	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "Err AES INIT-%x\n", ret);
		ret = -EIO;
	}

	ret = ali_aes_ioctl(s->dsc, (AES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_CREAT_CRYPT_STREAM_CMD),
			(__u32)pkeyparam);
	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "ERR AES CREATE_STREAM-%x\n", ret);
		ret = -EIO;
	}

	if (pkeyparam->handle == ALI_INVALID_CRYPTO_STREAM_HANDLE) {
		dev_dbg(s->dsc->dev, "get invalid handle!\n");
		ret = -EIO;
	}

	return ret;
}

static int dsc_create_des_stream(struct ca_dsc_session *s,
	DES_INIT_PARAM *pdes_init, KEY_PARAM *pkeyparam)
{
	int ret = 0;
	unsigned char see_ts_fmt[] = {
		[CA_FORMAT_RAW] = 0,
		[CA_FORMAT_TS188] = 0,
		[CA_FORMAT_TS188_LTSID] = 2,
		[CA_FORMAT_TS200] = 1,
	};

	pdes_init->ts_format = see_ts_fmt[s->format];
	pdes_init->continuous = s->ts_chaining;
	pdes_init->sc_mode = s->sc_mode;

	ret = ali_des_ioctl(s->dsc, (DES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_INIT_CMD), (__u32)pdes_init);
	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "Err DES INIT-%x\n", ret);
		ret = -EIO;
	}

	ret = ali_des_ioctl(s->dsc, (DES_DEV *)s->sub_dev_see_hdl,
		DSC_IO_CMD(IO_CREAT_CRYPT_STREAM_CMD),
		(__u32)pkeyparam);
	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "ERR DES CREATE_STREAM-%x\n", ret);
		ret = -EIO;
	}

	if (pkeyparam->handle == ALI_INVALID_CRYPTO_STREAM_HANDLE) {
		dev_dbg(s->dsc->dev, "get invalid handle!\n");
		ret = -EIO;
	}

	return ret;
}

static int dsc_create_csa_stream(struct ca_dsc_session *s,
	CSA_INIT_PARAM *pcsa_init, KEY_PARAM *pkeyparam)
{
	int ret = 0;
	unsigned char see_ts_fmt[] = {
		[CA_FORMAT_RAW] = 0,
		[CA_FORMAT_TS188] = 0,
		[CA_FORMAT_TS188_LTSID] = 2,
		[CA_FORMAT_TS200] = 1,
	};

	pcsa_init->ts_format = see_ts_fmt[s->format];

	ret = ali_csa_ioctl(s->dsc, (CSA_DEV *)s->sub_dev_see_hdl,
		DSC_IO_CMD(IO_INIT_CMD), (__u32)pcsa_init);
	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "Err CSA INIT-%x\n", ret);
		ret = -EIO;
	}

	ret = ali_csa_ioctl(s->dsc, (CSA_DEV *)s->sub_dev_see_hdl,
		DSC_IO_CMD(IO_CREAT_CRYPT_STREAM_CMD),
		(__u32)pkeyparam);
	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "ERR CSA CREATE_STREAM-%x\n", ret);
		ret = -EIO;
	}

	if (pkeyparam->handle == ALI_INVALID_CRYPTO_STREAM_HANDLE) {
		dev_dbg(s->dsc->dev, "get invalid handler!\n");
		ret = -EIO;
	}

	return ret;
}

static int dsc_create_clearkey_stream(struct ca_dsc_session *s,
	struct ali_inst_key *key)
{
	int ret = 0;
	int key_size;
	AES_INIT_PARAM aes_init;
	DES_INIT_PARAM des_init;
	CSA_INIT_PARAM csa_init;
	KEY_PARAM key_param;
	AES_KEY_PARAM aes_key_info;
	DES_KEY_PARAM des_key_info;
	CSA_KEY_PARAM csa_key_info;
	AES_IV_INFO aes_iv_info;
	DES_IV_INFO des_iv_info;
	unsigned short pid[CA_PID_MAX] = {0};
	int pid_size = 0;

	/*Translate pid_list to pid_array as SEE requires*/
	if (s->dma_mode == PURE_DATA_MODE) {
		pid[0] = 0x1234;
		pid_size = 1;
	} else {
		struct dsc_pid *ppid;

		list_for_each_entry(ppid, &key->pid_list, pid_node) {
			pid[pid_size] = ppid->pid;
			pid_size++;
		}

		if (pid_size != key->pid_size) {
			dev_dbg(s->dsc->dev,
				"key_size diff, somewhere wrong!!\n");
			return -EFAULT;
		}
	}

	if (key->key_type != DSC_INST_CLEAR_KEY) {
		dev_dbg(s->dsc->dev, "Invalid keytype[%x]\n", key->key_type);
		return -EINVAL;
	}

	/*Set AES Clear Key*/
	key_size = key->key_size * 8;
	if (s->sub_module == AES) {
		memset(&aes_init, 0, sizeof(aes_init));
		aes_init.key_from = KEY_FROM_SRAM;
		aes_init.key_mode = (key_size/64 - 1);
		aes_init.dma_mode = s->dma_mode;
		aes_init.stream_id = s->stream_id;
		aes_init.parity_mode = g_switch_parity[s->parity];
		aes_init.residue_mode = g_switch_residue[s->residue_mode];
		aes_init.work_mode = g_switch_chaining[s->chaining_mode];

		memset(&key_param, 0, sizeof(KEY_PARAM));
		memset(&aes_key_info, 0, sizeof(AES_KEY_PARAM));
		if (key_size == 128) {
			memcpy(aes_key_info.aes_128bit_key.odd_key,
				key->key_odd, 16);
			memcpy(aes_key_info.aes_128bit_key.even_key,
				key->key_even, 16);
		} else if (key_size == 192) {
			memcpy(aes_key_info.aes_192bit_key.odd_key,
				key->key_odd, 24);
			memcpy(aes_key_info.aes_192bit_key.even_key,
				key->key_even, 24);
		} else {
			memcpy(aes_key_info.aes_256bit_key.odd_key,
				key->key_odd, 32);
			memcpy(aes_key_info.aes_256bit_key.even_key,
				key->key_even, 32);
		}

		if (NEED_IV(s->chaining_mode)) {
			memcpy(aes_iv_info.odd_iv, key->iv_odd, 16);
			memcpy(aes_iv_info.even_iv, key->iv_even, 16);

			key_param.p_aes_iv_info = &aes_iv_info;
		}

		if (CA_MODE_CTR == s->chaining_mode) {
			key_param.ctr_counter = key->iv_even;
			aes_init.residue_mode = RESIDUE_BLOCK_IS_RESERVED;
		}

		key_param.p_aes_key_info = &aes_key_info;
		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = NULL;
		key_param.key_length = key_size;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.stream_id = s->stream_id;
		key_param.pos = 0;
		key_param.key_from = KEY_FROM_SRAM;
		ret = dsc_create_aes_stream(s, &aes_init, &key_param);

	} else if (s->sub_module == DES || s->sub_module == TDES) {
		memset(&des_init, 0, sizeof(des_init));
		des_init.key_from = KEY_FROM_SRAM;
		des_init.key_mode = (key_size/64 - 1);
		des_init.dma_mode = s->dma_mode;
		des_init.stream_id = s->stream_id;
		des_init.sub_module = s->sub_module;
		des_init.parity_mode = g_switch_parity[s->parity];
		des_init.residue_mode = g_switch_residue[s->residue_mode];
		des_init.work_mode = g_switch_chaining[s->chaining_mode];

		memset(&key_param, 0, sizeof(KEY_PARAM));
		memset(&des_key_info, 0, sizeof(DES_KEY_PARAM));
		if (key_size == 128) {
			memcpy(des_key_info.des_128bits_key.OddKey,
				key->key_odd, 16);
			memcpy(des_key_info.des_128bits_key.EvenKey,
				key->key_even, 16);
		} else if (key_size == 192) {
			memcpy(des_key_info.des_192bits_key.OddKey,
				key->key_odd, 24);
			memcpy(des_key_info.des_192bits_key.EvenKey,
				key->key_even, 24);
		} else {
			memcpy(des_key_info.des_64bits_key.OddKey,
				key->key_odd, 8);
			memcpy(des_key_info.des_64bits_key.EvenKey,
				key->key_even, 8);
		}

		if (NEED_IV(s->chaining_mode)) {
			memcpy(des_iv_info.odd_iv, key->iv_odd, 8);
			memcpy(des_iv_info.even_iv, key->iv_even, 8);

			key_param.p_des_iv_info = &des_iv_info;
		}

		key_param.p_des_key_info = &des_key_info;
		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = NULL;
		key_param.key_length = key_size;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.stream_id = s->stream_id;
		key_param.pos = 0;
		key_param.key_from = KEY_FROM_SRAM;
		ret = dsc_create_des_stream(s, &des_init, &key_param);

	} else if (s->sub_module == CSA) {
		/*only support most 128 when CSA3*/
		key_size = (s->csa_version == CSA3) ? 128 : 64;
		memset(&csa_init, 0, sizeof(csa_init));
		csa_init.version = s->csa_version;
		csa_init.dma_mode = s->dma_mode;
		csa_init.stream_id = s->stream_id;
		csa_init.key_from = KEY_FROM_SRAM;
		csa_init.parity_mode = AUTO_PARITY_MODE0;

		memset(&key_param, 0, sizeof(KEY_PARAM));
		memset(&csa_key_info, 0, sizeof(CSA_KEY_PARAM));
		if (s->csa_version == CSA3) {
			memcpy(csa_key_info.csa3_key.OddKey,
				key->key_odd, 16);
			memcpy(csa_key_info.csa3_key.EvenKey,
				key->key_even, 16);
		} else {
			memcpy(csa_key_info.csa_key.OddKey,
				key->key_odd, 8);
			memcpy(csa_key_info.csa_key.EvenKey,
				key->key_even, 8);
		}

		key_param.p_csa_key_info = &csa_key_info;
		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = NULL;
		key_param.ctr_counter = NULL;
		key_param.key_length = key_size;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.stream_id = s->stream_id;
		key_param.pos = 0;
		key_param.key_from = KEY_FROM_SRAM;
		ret = dsc_create_csa_stream(s, &csa_init, &key_param);
	} else
		ret = -EPERM;

	if (ret)
		dev_dbg(s->dsc->dev, "create stream err!\n");

	key->key_handle = key_param.handle;
	return ret;
}

static int dsc_create_kl_stream(struct ca_dsc_session *s,
	struct ali_inst_key *key)
{
	int ret;
	int key_size = 0;
	AES_INIT_PARAM aes_init;
	DES_INIT_PARAM des_init;
	CSA_INIT_PARAM csa_init;
	KEY_PARAM key_param;
	AES_IV_INFO aes_iv_info;
	DES_IV_INFO des_iv_info;
	unsigned short pid[CA_PID_MAX] = { 0 };
	int pid_size = 0;

	/*Translate pid_list to pid_array as SEE requires*/
	if (s->dma_mode == PURE_DATA_MODE) {
		pid[0] = 0x1234;
		pid_size = 1;
	} else {
		struct dsc_pid *ppid;

		list_for_each_entry(ppid, &key->pid_list, pid_node) {
			pid[pid_size] = ppid->pid;
			pid_size++;
		}

		if (pid_size != key->pid_size) {
			dev_dbg(s->dsc->dev,
				"key_size diff, somewhere wrong!!\n");
			return -EFAULT;
		}
	}

	if (key->key_type != DSC_INST_KL_KEY) {
		dev_dbg(s->dsc->dev, "invalid keytype[%x]\n", key->key_type);
		return -EINVAL;
	}

	/*check key cell available*/
	if (!key->cell) {
		dev_dbg(s->dsc->dev, "ERR: pls fetch key cell first\n");
		return ret;
	}

	/*Set KL Key*/
	if (AES == s->sub_module) {
		key_size = 128; /*KL only support most 128 when AES*/
		memset(&aes_init, 0, sizeof(aes_init));
		aes_init.key_from = KEY_FROM_CRYPTO;
		aes_init.key_mode = (key_size/64 - 1);
		aes_init.dma_mode = s->dma_mode;
		aes_init.stream_id = s->stream_id;
		aes_init.parity_mode = g_switch_parity[s->parity];
		aes_init.residue_mode = g_switch_residue[s->residue_mode];
		aes_init.work_mode = g_switch_chaining[s->chaining_mode];

		memset(&key_param, 0, sizeof(KEY_PARAM));
		if (NEED_IV(s->chaining_mode)) {
			memcpy(aes_iv_info.odd_iv, key->iv_odd, 16);
			memcpy(aes_iv_info.even_iv, key->iv_even, 16);

			key_param.p_aes_iv_info = &aes_iv_info;
		}

		if (WORK_MODE_IS_CTR == aes_init.work_mode) {
			key_param.ctr_counter = key->iv_even;
			aes_init.residue_mode = RESIDUE_BLOCK_IS_RESERVED;
		}

		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = NULL;
		key_param.key_length = key_size;
		key_param.stream_id = s->stream_id;
		key_param.pos = key->cell->pos;
		key_param.kl_sel = key->cell->kl_sel;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.key_from = KEY_FROM_CRYPTO;
		ret = dsc_create_aes_stream(s, &aes_init, &key_param);

	} else if (s->sub_module == DES || s->sub_module == TDES) {
		/*KL only support most 64 when DES && 128 when TDES*/
		key_size = (s->sub_module == DES) ? 64 : 128;
		memset(&des_init, 0, sizeof(des_init));
		des_init.key_from = KEY_FROM_CRYPTO;
		des_init.key_mode = (key_size/64 - 1);
		des_init.dma_mode = s->dma_mode;
		des_init.stream_id = s->stream_id;
		des_init.sub_module = s->sub_module;
		des_init.parity_mode = g_switch_parity[s->parity];
		des_init.residue_mode = g_switch_residue[s->residue_mode];
		des_init.work_mode = g_switch_chaining[s->chaining_mode];

		memset(&key_param, 0, sizeof(KEY_PARAM));
		if (NEED_IV(s->chaining_mode)) {
			memcpy(des_iv_info.odd_iv, key->iv_odd, 8);
			memcpy(des_iv_info.even_iv, key->iv_even, 8);

			key_param.p_des_iv_info = &des_iv_info;
		}

		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = NULL;
		key_param.key_length = key_size;
		key_param.stream_id = s->stream_id;
		key_param.pos = key->cell->pos;
		key_param.kl_sel = key->cell->kl_sel;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.key_from = KEY_FROM_CRYPTO;
		ret = dsc_create_des_stream(s, &des_init, &key_param);

	} else if (s->sub_module == CSA) {
		/*KL only support most 128 when CSA3*/
		key_size = (s->csa_version == CSA3) ? 128 : 64;
		memset(&csa_init, 0, sizeof(csa_init));
		csa_init.version = s->csa_version;
		csa_init.dma_mode = s->dma_mode;
		csa_init.stream_id = s->stream_id;
		csa_init.key_from = KEY_FROM_CRYPTO;
		csa_init.parity_mode = AUTO_PARITY_MODE0;

		memset(&key_param, 0, sizeof(KEY_PARAM));
		key_param.p_csa_key_info = NULL;
		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = NULL;
		key_param.ctr_counter = NULL;
		key_param.key_length = key_size;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.stream_id = s->stream_id;
		key_param.pos = key->cell->pos;
		key_param.kl_sel = key->cell->kl_sel;
		key_param.key_from = KEY_FROM_CRYPTO;
		ret = dsc_create_csa_stream(s, &csa_init, &key_param);
	} else
		ret = -EPERM;

	if (ret)
		dev_dbg(s->dsc->dev, "create stream err!\n");

	key->key_handle = key_param.handle;
	return ret;
}

static int dsc_create_otp_stream(struct ca_dsc_session *s,
	struct ali_inst_key *key)
{
	int ret = -1;
	int key_size = 0;
	AES_INIT_PARAM aes_init;
	DES_INIT_PARAM des_init;
	KEY_PARAM key_param;
	AES_IV_INFO aes_iv_info;
	DES_IV_INFO des_iv_info;
	unsigned short pid[1] = {0x1234};
	int pid_size = 1;

	if (key->key_type != DSC_INST_OTP_KEY) {
		dev_dbg(s->dsc->dev, "Invalid Key Type[%x]\n", key->key_type);
		return -EINVAL;
	}

	/*Set OTP Key*/
	if (AES == s->sub_module) {
		key_size = 128;
		memset(&aes_init, 0, sizeof(aes_init));
		aes_init.key_from = KEY_FROM_OTP;
		aes_init.key_mode = (key_size/64 - 1);
		aes_init.dma_mode = s->dma_mode;
		aes_init.stream_id = s->stream_id;
		aes_init.residue_mode = g_switch_residue[s->residue_mode];
		aes_init.work_mode = g_switch_chaining[s->chaining_mode];
		aes_init.parity_mode = g_switch_otp_sel[key->otp_key_select];

		memset(&key_param, 0, sizeof(KEY_PARAM));
		if (NEED_IV(s->chaining_mode))
			memcpy(aes_iv_info.even_iv, key->iv_even, 16);

		if (WORK_MODE_IS_CTR == aes_init.work_mode) {
			key_param.ctr_counter = key->iv_even;
			aes_init.residue_mode = RESIDUE_BLOCK_IS_RESERVED;
		}

		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = (unsigned char *)&aes_iv_info;
		key_param.key_length = key_size;
		key_param.stream_id = s->stream_id;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.key_from = KEY_FROM_OTP;
		ret = dsc_create_aes_stream(s, &aes_init, &key_param);

	} else if (TDES == s->sub_module) {
		key_size = 128;
		memset(&des_init, 0, sizeof(des_init));
		des_init.key_from = KEY_FROM_OTP;
		des_init.key_mode = (key_size/64 - 1);
		des_init.dma_mode = s->dma_mode;
		des_init.stream_id = s->stream_id;
		des_init.sub_module = TDES;
		des_init.parity_mode = g_switch_otp_sel[key->otp_key_select];
		des_init.residue_mode = g_switch_residue[s->residue_mode];
		des_init.work_mode = g_switch_chaining[s->chaining_mode];

		memset(&key_param, 0, sizeof(KEY_PARAM));
		if (NEED_IV(s->chaining_mode))
			memcpy(des_iv_info.even_iv, key->iv_even, 8);

		key_param.handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;
		key_param.init_vector = (unsigned char *)&des_iv_info;
		key_param.key_length = key_size;
		key_param.stream_id = s->stream_id;
		key_param.pid_list = pid;
		key_param.pid_len = pid_size;
		key_param.key_from = KEY_FROM_OTP;
		ret = dsc_create_des_stream(s, &des_init, &key_param);
	} else
		ret = -EPERM;

	if (ret)
		dev_dbg(s->dsc->dev, "create stream err!\n");

	key->key_handle = key_param.handle;
	return ret;
}

int dsc_delete_crypto_stream(struct ca_dsc_session *s,
	int key_handle)
{
	int ret = -1;
	struct ca_dsc_dev *dsc = s->dsc;

	if (ALI_INVALID_CRYPTO_STREAM_HANDLE == key_handle)
		return 0;

	ret = ali_dsc_ioctl(s->dsc, (DSC_DEV *)dsc->see_dsc_id,
		DSC_IO_CMD(IO_DSC_DELETE_HANDLE_CMD), key_handle);

	if (ret != RET_SUCCESS) {
		dev_dbg(s->dsc->dev, "Delete crypt stream error, key[%d]!\n",
			key_handle);
		ret = -EIO;
	}

	return ret;
}

static int inst_key_is_pid_exist(struct ali_inst_key *inst_key,
	unsigned short pid, unsigned char ltsid)
{
	struct dsc_pid *ppid;

	list_for_each_entry(ppid, &inst_key->pid_list, pid_node) {

		/*this pid already exist*/
		if (inst_key->s->format == CA_FORMAT_TS188)
			if (ppid->pid == pid)
				return 1;

		/*this pid+ltsid already exist*/
		if (inst_key->s->format == CA_FORMAT_TS200)
			if (ppid->pid == pid &&
				ppid->ltsid == ltsid)
				return 1;
	}

	return 0;
}

static int inst_key_add_pid(struct ali_inst_key *inst_key,
	unsigned short pid, unsigned char ltsid, unsigned char tsc)
{
	struct dsc_pid *ppid = NULL;

	if (inst_key->pid_size == CA_PID_MAX)
		return -ENOBUFS; /*Full ...*/

	if (inst_key_is_pid_exist(inst_key, pid, ltsid))
		return -EPERM; /*already exist*/

	/*not exist, add it.*/
	ppid = kmalloc(sizeof(struct dsc_pid),
		GFP_KERNEL);
	if (!ppid)
		return -ENOMEM;

	ppid->pid = pid;
	ppid->ltsid = ltsid;
	ppid->tsc = tsc;

	list_add_tail(&ppid->pid_node, &inst_key->pid_list);
	inst_key->pid_size++;

	return 0;
}

static int inst_key_del_pid(struct ali_inst_key *inst_key,
	unsigned short pid, unsigned char ltsid)
{
	struct dsc_pid *ppid, *_ppid;

	list_for_each_entry_safe(ppid, _ppid,
		&inst_key->pid_list, pid_node) {

		if (ppid->pid == pid &&
			ppid->ltsid == ltsid) {

			list_del(&ppid->pid_node);
			inst_key->pid_size--;
			kfree(ppid);
		}
	}

	return 0;
}

static struct ali_inst_key *inst_key_find_by_handle(
	struct ca_dsc_session *s, int key_id)
{
	struct ali_inst_key *key;
	int found = 0;

	list_for_each_entry(key, &s->key_list, key_node) {
		if (key->key_id == key_id) {
			found = 1;
			break;
		}
	}

	if (!found) {
		dev_dbg(s->dsc->dev, "key[%d] not found\n", key_id);
		return NULL;
	}

	return key;
}

static struct ali_inst_key *inst_key_new(void *key,
	int key_type, struct ca_dsc_session *s)
{
	int ret;
	struct ali_inst_key *p_inst_key = NULL;
	struct ca_create_clear_key *clear_key;
	struct ca_create_kl_key *kl_key;
	struct ca_create_otp_key *otp_key;

	/*new s key*/
	p_inst_key = kmalloc(sizeof(struct ali_inst_key),
		GFP_KERNEL);
	if (!p_inst_key)
		return NULL;

	memset(p_inst_key, 0, sizeof(struct ali_inst_key));

	if (DSC_INST_CLEAR_KEY == key_type) {
		clear_key = (struct ca_create_clear_key *)key;

		p_inst_key->even_locate = 0;
		p_inst_key->odd_locate = 0;
		p_inst_key->key_size = clear_key->key_size;
		p_inst_key->key_type = DSC_INST_CLEAR_KEY;
		if (clear_key->valid_mask & CA_VALID_KEY_EVEN) {
			memcpy(p_inst_key->key_even,
				clear_key->key_even, CA_KEY_SIZE_MAX);
			p_inst_key->no_even = 0;
		}
		if (clear_key->valid_mask & CA_VALID_KEY_ODD) {
			memcpy(p_inst_key->key_odd,
				clear_key->key_odd, CA_KEY_SIZE_MAX);
			p_inst_key->no_odd = 0;
		}

		if (clear_key->valid_mask & CA_VALID_IV_EVEN)
			memcpy(p_inst_key->iv_even,
				clear_key->iv_even, CA_IV_SIZE_MAX);
		if (clear_key->valid_mask & CA_VALID_IV_ODD)
			memcpy(p_inst_key->iv_odd,
				clear_key->iv_odd, CA_IV_SIZE_MAX);
	} else if (DSC_INST_KL_KEY == key_type) {
		kl_key = (struct ca_create_kl_key *)key;

		p_inst_key->even_locate = 1;
		p_inst_key->odd_locate = 1;
		p_inst_key->key_type = key_type;
		p_inst_key->kl_fd = kl_key->kl_fd;
		ret = fetch_key_cell_by_fd(kl_key->kl_fd, &p_inst_key->cell);
		if (ret || !p_inst_key->cell) {
			dev_dbg(s->dsc->dev,
				"fetch key cell by fd error: %d\n", ret);
			kfree(p_inst_key);
			return NULL;
		} else {
			get_key_cell(p_inst_key->cell);
		}

		if (kl_key->valid_mask & CA_VALID_IV_EVEN)
			memcpy(p_inst_key->iv_even,
				kl_key->iv_even, CA_IV_SIZE_MAX);
		if (kl_key->valid_mask & CA_VALID_IV_ODD)
			memcpy(p_inst_key->iv_odd,
				kl_key->iv_odd, CA_IV_SIZE_MAX);
	} else if (DSC_INST_OTP_KEY == key_type) {
		otp_key = (struct ca_create_otp_key *)key;

		p_inst_key->otp_key_select = otp_key->otp_key_select;
		p_inst_key->key_type = DSC_INST_OTP_KEY;

		memcpy(p_inst_key->iv_even,
			otp_key->iv_even, CA_IV_SIZE_MAX);
	}

	p_inst_key->key_id = ida_simple_get(&s->key_ida, 1, 0, GFP_KERNEL);
	p_inst_key->key_handle = ALI_INVALID_CRYPTO_STREAM_HANDLE;

	INIT_LIST_HEAD(&p_inst_key->pid_list);
	p_inst_key->pid_size = 0;

	p_inst_key->s = s;
	return p_inst_key;
}

void inst_key_delete(struct ali_inst_key *inst_key)
{
	struct dsc_pid *ppid, *_ppid;
	struct ca_dsc_session *s;

	if (inst_key == NULL)
		return;

	s = inst_key->s;

	/*clean the pid_list*/
	list_for_each_entry_safe(ppid, _ppid,
		&inst_key->pid_list, pid_node) {
		list_del(&ppid->pid_node);
		kfree(ppid);
	}

	if (inst_key->cell)
		put_key_cell(inst_key->cell);

	ida_simple_remove(&s->key_ida, inst_key->key_id);

	kfree(inst_key);
}

static int ca_keep_consistent(struct ca_dsc_session *s)
{
	int ret;

	ret = s->engine.ops->is_busy(&s->engine);
	while (ret == -EBUSY) {
		if (schedule_timeout_interruptible(DSC_SCHE_DELAY)) {
			ret = -ERESTARTSYS;
			return ret;
		}

		ret = s->engine.ops->is_busy(&s->engine);
	}

	return 0;
}

static int ca_clear_key_sc(struct ca_dsc_session *s,
	struct ca_create_clear_key *clear_key)
{
	int ret = -EINVAL;
	enum WORK_SUB_MODULE sub_module = DSC_INVALID_SUB_MODULE;

	if (!clear_key || !s) {
		dev_dbg(s->dsc->dev, "argument NULL\n");
		return -EINVAL;
	}

	/*before this, ca format should be set first*/
	if (s->dma_mode == DSC_INVALID_DMA_MODE) {
		dev_dbg(s->dsc->dev, "CA format should be set first<CA_SET_FORMAT>!!\n");
		return -EPERM;
	}

	if (INVALID_ALGO(clear_key->algo)) {
		dev_dbg(s->dsc->dev, "Invalid algo\n");
		return -EINVAL;
	}

	if (INVALID_PARITY(clear_key->parity)) {
		dev_dbg(s->dsc->dev, "Invalid parity\n");
		return -EINVAL;
	}

	if (INVALID_CRYPT_MODE(clear_key->crypt_mode)) {
		dev_dbg(s->dsc->dev, "Invalid crypt_mode\n");
		return -EINVAL;
	}

	if (INVALID_WORK_MODE(clear_key->chaining_mode)) {
		dev_dbg(s->dsc->dev, "Invalid chaining_mode\n");
		return -EINVAL;
	}

	if (INVALID_RESIDUE_MODE(clear_key->residue_mode)) {
		dev_dbg(s->dsc->dev, "Invalid residue_mode\n");
		return -EINVAL;
	}

	/*more than one key*/
	if (!list_empty(&s->key_list)) {

		/*only one key allowed in pure data mode*/
		if (s->dma_mode == PURE_DATA_MODE) {
			dev_dbg(s->dsc->dev, "one key allow in RAW session!!\n");
			return -EPERM;
		}
	}

	switch (clear_key->algo) {
	case CA_ALGO_AES:
		sub_module = AES;
		break;
	case CA_ALGO_DES:
		sub_module = DES;
		break;
	case CA_ALGO_TDES:
		sub_module = TDES;
		break;
	case CA_ALGO_CSA1:
	case CA_ALGO_CSA2:
	case CA_ALGO_CSA3:
		sub_module = CSA;
		break;
	default:
		break;
	}

	/* new algo not allow*/
	if (s->sub_module != DSC_INVALID_SUB_MODULE &&
		s->sub_dev_id != ALI_INVALID_DSC_SUB_DEV_ID &&
		s->sub_module != sub_module) {
		dev_dbg(s->dsc->dev, "Not allow to change algo within session\n");
		return -EPERM;
	}

	s->sub_module = sub_module;

	if (s->sub_module == AES) {
		if (INVALID_AES_KEY_SIZE(clear_key->key_size)) {
			dev_dbg(s->dsc->dev, "Invalid Key size for AES[%d]\n",
				clear_key->key_size);
			return ret;
		}
	}

	if (s->sub_module == DES) {
		if (INVALID_DES_KEY_SIZE(clear_key->key_size))	{
			dev_dbg(s->dsc->dev, "Invalid Key Length for DES[%d]\n",
				clear_key->key_size);
			return ret;
		}
	}

	if (s->sub_module == TDES) {
		if (INVALID_TDES_KEY_SIZE(clear_key->key_size)) {
			dev_dbg(s->dsc->dev, "Invalid Key Length for TDES[%d]\n",
				clear_key->key_size);
			return ret;
		}
	}

	if (s->sub_module == CSA) {
		if (s->dma_mode == PURE_DATA_MODE) {
			dev_dbg(s->dsc->dev, "CSA is not support RAW data!\n");
			return ret;
		}

		if (clear_key->crypt_mode == CA_ENCRYPT) {
			dev_dbg(s->dsc->dev, "CSA is not support encryption!!\n");
			return ret;
		}

		if (clear_key->algo == CA_ALGO_CSA1) {
			s->csa_version = CSA1;
			if (INVALID_CSA1_KEY_SIZE(clear_key->key_size)) {
				dev_dbg(s->dsc->dev, "Invalid Key Length for CSA1[%d]\n",
					clear_key->key_size);
				return ret;
			}
		}

		if (clear_key->algo == CA_ALGO_CSA2) {
			s->csa_version = CSA2;
			if (INVALID_CSA2_KEY_SIZE(clear_key->key_size)) {
				dev_dbg(s->dsc->dev, "Invalid Key Length for CSA2[%d]\n",
					clear_key->key_size);
				return ret;
			}
		}

		if (clear_key->algo == CA_ALGO_CSA3) {
			s->csa_version = CSA3;
			if (INVALID_CSA3_KEY_SIZE(clear_key->key_size)) {
				dev_dbg(s->dsc->dev, "Invalid Key Length for CSA3[%d]\n",
					clear_key->key_size);
				return ret;
			}
		}
	}

	s->algo = clear_key->algo;
	s->crypt_mode = clear_key->crypt_mode;
	s->chaining_mode = clear_key->chaining_mode;
	s->residue_mode = clear_key->residue_mode;
	s->parity = clear_key->parity;

	return 0;
}

static int ca_clear_key_set(struct ca_dsc_session *s,
	struct ca_create_clear_key *clear_key)
{
	int ret;
	struct ali_inst_key *p_inst_key = NULL;

	ret = ca_clear_key_sc(s, clear_key);
	if (ret < 0)
		return ret;

	/*Fetch streamId && Sub-device ID*/
	if (s->stream_id_flag != 1) {
		ret = dsc_fetch_streamId(s);
		if (ret < 0) {
			dev_dbg(s->dsc->dev, "dsc fetch stream ID failed!\n");
			return ret;
		}
	}

	if (ALI_INVALID_DSC_SUB_DEV_ID == s->sub_dev_id) {
		ret = dsc_fetch_subdevice(s);
		if (ret < 0) {
			dev_dbg(s->dsc->dev, "dsc fetch sub-device ID failed!\n");
			return ret;
		}
	}

	/*create a new session key*/
	p_inst_key = inst_key_new((void *)clear_key,
		DSC_INST_CLEAR_KEY, s);
	if (p_inst_key == NULL)
		return -ENOMEM;

	ret = dsc_create_clearkey_stream(s, p_inst_key);
	if (ret < 0) {
		dev_dbg(s->dsc->dev, "create stream failed[%08x]\n", ret);
		inst_key_delete(p_inst_key);
		return -EIO;
	}

	/*Insert into the key_list*/
	list_add(&p_inst_key->key_node, &s->key_list);

	return p_inst_key->key_id;
}

static int ca_format_set(struct ca_dsc_session *s,
	int ca_format)
{
	int format;
	unsigned char ts_chaining;
	unsigned char sc_mode;

	if (!s)
		return -EINVAL;

	if (s->fmt_flag) {
		dev_dbg(s->dsc->dev, "cannot set twice!\n");
		return -EPERM;
	}

	format = ca_format & CA_FORMAT_MASK;
	ts_chaining = (ca_format & CA_FORMAT_TS_CHAINING) ? 1 : 0;
	sc_mode = (ca_format & CA_FORMAT_CLEAR_UNTOUCHED) ? 1 : 0;

	if (INVALID_CA_FORMAT(format)) {
		dev_dbg(s->dsc->dev,
			"Invalid ca_format[%x]!\n", ca_format);
		return -EINVAL;
	}

	if ((format == CA_FORMAT_RAW) && ts_chaining) {
		dev_dbg(s->dsc->dev,
			"Raw format not support chaining!\n");
		return -EINVAL;
	}

	if (format == CA_FORMAT_RAW) {
		s->dma_mode = PURE_DATA_MODE;
		s->pkt_size = PAGE_SIZE;
	} else {
		s->dma_mode = TS_MODE;

		if (format == CA_FORMAT_TS188 ||
			format == CA_FORMAT_TS188_LTSID)
			s->pkt_size = 188;
		else if (format == CA_FORMAT_TS200)
			s->pkt_size = 200;
	}

	s->format = format;
	s->ts_chaining = ts_chaining;
	s->sc_mode = sc_mode;
	s->fmt_flag = 1;

	if (s->ts_chaining)
		s->opt = CA_SET_CORK;
	else
		s->opt = CA_SET_UNCORK;

	return 0;
}

static int ca_opt_set(struct ca_dsc_session *s,
	int ca_opt)
{
	int ret = 0;

	if (!s)
		return -EINVAL;

	if (!s->ts_chaining) {
		dev_dbg(s->dsc->dev,
			"session not in chaining mode\n");
		return -EPERM;
	}

	if (ca_opt != CA_SET_CORK && ca_opt != CA_SET_UNCORK) {
		dev_dbg(s->dsc->dev, "Invalid ca_opt!\n");
		return -EINVAL;
	}

	if (ca_opt == CA_SET_UNCORK)
		ca_dsc_se_queue_last(&s->engine);

	ret = ca_keep_consistent(s);
	if (ret) {
		dev_dbg(s->dsc->dev,
			"cannot set opt now!\n");
		return ret;
	}

	if (ca_opt == CA_SET_UNCORK &&
		s->sub_dev_see_hdl) {
		if (s->sub_module == AES) {
			ret = ali_aes_ioctl(s->dsc,
					(AES_DEV *)s->sub_dev_see_hdl,
					DSC_IO_CMD(IO_CONTINUOUS_RENEW),
					0);
			if (ret != RET_SUCCESS) {
				dev_dbg(s->dsc->dev,
					"ERR AES IO_CONTINUOUS_RENEW-%x\n",
					ret);
				ret = -EIO;
			}
		} else if (s->sub_module == DES || s->sub_module == TDES) {
			ret = ali_des_ioctl(s->dsc,
					(DES_DEV *)s->sub_dev_see_hdl,
					DSC_IO_CMD(IO_CONTINUOUS_RENEW),
					0);
			if (ret != RET_SUCCESS) {
				dev_dbg(s->dsc->dev,
					"ERR DES IO_CONTINUOUS_RENEW-%x\n",
					ret);
				ret = -EIO;
			}
		} else {
			dev_dbg(s->dsc->dev,
				"CSA not support IO_CONTINUOUS_RENEW\n");
			return -EPERM;
		}
	}

	s->opt = ca_opt;

	return ret;
}

static int ca_kl_key_sc(struct ca_dsc_session *s,
	struct ca_create_kl_key *kl_key)
{
	enum WORK_SUB_MODULE sub_module = DSC_INVALID_SUB_MODULE;

	if (!kl_key || !s)
		return -EINVAL;

	/*before this, ca format should be set first*/
	if (DSC_INVALID_DMA_MODE == s->dma_mode) {
		dev_dbg(s->dsc->dev, "CA format should be set first<CA_SET_FORMAT>!!\n");
		return -EPERM;
	}

	if (INVALID_ALGO(kl_key->algo)) {
		dev_dbg(s->dsc->dev, "Invalid algo\n");
		return -EINVAL;
	}

	if (INVALID_PARITY(kl_key->parity)) {
		dev_dbg(s->dsc->dev, "Invalid parity\n");
		return -EINVAL;
	}

	if (INVALID_CRYPT_MODE(kl_key->crypt_mode)) {
		dev_dbg(s->dsc->dev, "Invalid crypt_mode\n");
		return -EINVAL;
	}

	if (INVALID_WORK_MODE(kl_key->chaining_mode)) {
		dev_dbg(s->dsc->dev, "Invalid chaining_mode\n");
		return -EINVAL;
	}

	if (INVALID_RESIDUE_MODE(kl_key->residue_mode)) {
		dev_dbg(s->dsc->dev, "Invalid residue_mode\n");
		return -EINVAL;
	}

	/*more than one key*/
	if (!list_empty(&s->key_list)) {

		/*only one key allowed in pure data mode*/
		if (s->dma_mode == PURE_DATA_MODE) {
			dev_dbg(s->dsc->dev, "one key allow in RAW session!!\n");
			return -EPERM;
		}
	}

	if (kl_key->kl_fd <= 0) {
		dev_dbg(s->dsc->dev, "Invalid kl_fd[%d]\n", kl_key->kl_fd);
		return -EINVAL;
	}

	switch (kl_key->algo) {
	case CA_ALGO_AES:
		sub_module = AES;
		break;

	case CA_ALGO_DES:
		sub_module = DES;
		break;
	case CA_ALGO_TDES:
		sub_module = TDES;
		break;
	case CA_ALGO_CSA1:
	case CA_ALGO_CSA2:
	case CA_ALGO_CSA3:
		sub_module = CSA;
		break;
	default:
		break;
	}

	/*a new algo not allow*/
	if (s->sub_module != DSC_INVALID_SUB_MODULE &&
		s->sub_dev_id != ALI_INVALID_DSC_SUB_DEV_ID &&
		s->sub_module != sub_module){
		dev_dbg(s->dsc->dev, "Not allow to change algo within session\n");
		return -EPERM;
	}

	s->sub_module = sub_module;

	if (s->sub_module == CSA) {
		if (PURE_DATA_MODE == s->dma_mode) {
			dev_dbg(s->dsc->dev, "CSA is not support RAW data!\n");
			return -EINVAL;
		}

		if (CA_ENCRYPT == kl_key->crypt_mode) {
			dev_dbg(s->dsc->dev, "CSA is not support encryption!!\n");
			return -EINVAL;
		}

		if (CA_ALGO_CSA1 == kl_key->algo)
			s->csa_version = CSA1;
		else if (CA_ALGO_CSA2 == kl_key->algo)
			s->csa_version = CSA2;
		else if (CA_ALGO_CSA3 == kl_key->algo)
			s->csa_version = CSA3;
	}

	s->algo = kl_key->algo;
	s->crypt_mode = kl_key->crypt_mode;
	s->chaining_mode = kl_key->chaining_mode;
	s->residue_mode = kl_key->residue_mode;
	s->parity = kl_key->parity;

	return 0;
}

static int ca_kl_key_set(struct ca_dsc_session *s,
	struct ca_create_kl_key *kl_key)
{
	int ret;
	struct ali_inst_key *p_inst_key = NULL;

	ret = ca_kl_key_sc(s, kl_key);
	if (ret < 0)
		return ret;

	/*Fetch stream ID*/
	if (s->stream_id_flag != 1) {
		ret = dsc_fetch_streamId(s);
		if (ret < 0) {
			dev_dbg(s->dsc->dev, "dsc fetch streamID failed!\n");
			return ret;
		}
	} else {
		dev_dbg(s->dsc->dev, "sid[%d],flag[%d]\n",
			s->stream_id, s->stream_id_flag);
	}

	if (ALI_INVALID_DSC_SUB_DEV_ID == s->sub_dev_id) {
		ret = dsc_fetch_subdevice(s);
		if (ret < 0) {
			dev_dbg(s->dsc->dev, "dsc fetch sub-device ID failed!\n");
			return ret;
		}
	}

	/*Malloc a new session key*/
	p_inst_key = inst_key_new((void *)kl_key,
		DSC_INST_KL_KEY, s);
	if (NULL == p_inst_key) {
		dev_dbg(s->dsc->dev, "kmalloc error!\n");
		return -ENOMEM;
	}

	ret = dsc_create_kl_stream(s, p_inst_key);
	if (ret < 0) {
		dev_dbg(s->dsc->dev, "dsc create stream failed![%x]\n", ret);
		inst_key_delete(p_inst_key);
		return ret;
	}

	/*Insert into the key_list*/
	list_add(&p_inst_key->key_node, &s->key_list);

	return p_inst_key->key_id;
}

static int ca_otp_key_sc(struct ca_dsc_session *s,
	struct ca_create_otp_key *otp_key)
{
	enum WORK_SUB_MODULE sub_module = DSC_INVALID_SUB_MODULE;

	if (NULL == otp_key || NULL == s) {
		dev_dbg(s->dsc->dev, "argument NULL\n");
		return -EINVAL;
	}

	/*before this, ca format should be set first*/
	if (s->dma_mode != PURE_DATA_MODE) {
		dev_dbg(s->dsc->dev, "OTP KEY only supports Raw data!!\n");
		return -EPERM;
	}

	/*only one key allowed for OTP key session*/
	if (!list_empty(&s->key_list)) {
		dev_dbg(s->dsc->dev, "one key allow in otp session!!\n");
		return -EPERM;
	}

	if (otp_key->algo != CA_ALGO_AES &&
		otp_key->algo != CA_ALGO_TDES) {
		dev_dbg(s->dsc->dev, "Invalid algo[%x]\n", otp_key->algo);
		return -EINVAL;
	}

	if (otp_key->otp_key_select != CA_OTP_KEY_6 &&
		otp_key->otp_key_select != CA_OTP_KEY_7 &&
		otp_key->otp_key_select != CA_OTP_KEY_FP) {
		dev_dbg(s->dsc->dev, "Invalid key_sel[%x]\n", otp_key->algo);
		return -EINVAL;
	}

	if (otp_key->algo == CA_ALGO_TDES &&
		otp_key->otp_key_select == CA_OTP_KEY_FP) {
		dev_dbg(s->dsc->dev, "FP KEY cannot support TDES\n");
		return -EPERM;
	}

	if (INVALID_CRYPT_MODE(otp_key->crypt_mode)) {
		dev_dbg(s->dsc->dev, "Invalid crypt_mode\n");
		return -EINVAL;
	} else {
		s->crypt_mode = otp_key->crypt_mode;
	}

	switch (otp_key->algo) {
	case CA_ALGO_AES:
		sub_module = AES;
		break;

	case CA_ALGO_TDES:
		sub_module = TDES;
		break;
	default:
		break;
	}

	if (DSC_INVALID_SUB_MODULE == sub_module) {
		dev_dbg(s->dsc->dev, "Invalid algo\n");
		return -EINVAL;
	}


	dsc_free_streamid(s);

	s->sub_module = sub_module;

	if (INVALID_WORK_MODE(otp_key->chaining_mode)) {
		dev_dbg(s->dsc->dev, "Invalid chaining_mode\n");
		return -EINVAL;
	}

	if (INVALID_RESIDUE_MODE(otp_key->residue_mode)) {
		dev_dbg(s->dsc->dev, "Invalid residue_mode\n");
		return -EINVAL;
	}

	return 0;
}

static int ca_otp_key_set(struct ca_dsc_session *s,
	struct ca_create_otp_key *otp_key)
{
	int ret;
	struct ali_inst_key *p_inst_key = NULL;

	ret = ca_otp_key_sc(s, otp_key);
	if (ret < 0)
		return ret;

	if (ALI_INVALID_DSC_SUB_DEV_ID == s->sub_dev_id) {
		ret = dsc_fetch_subdevice(s);
		if (ret < 0) {
			dev_dbg(s->dsc->dev, "dsc fetch sub-device ID failed!\n");
			return ret;
		}
	}

	/*Malloc a new s key*/
	p_inst_key = inst_key_new((void *)otp_key,
		DSC_INST_OTP_KEY, s);
	if (NULL == p_inst_key) {
		dev_dbg(s->dsc->dev, "kmalloc error!\n");
		return -ENOMEM;
	}

	/*Create pure data stream*/
	ret = dsc_create_otp_stream(s, p_inst_key);
	if (ret < 0) {
		dev_dbg(s->dsc->dev, "%s,[%x]\n", __func__, ret);
		inst_key_delete(p_inst_key);
		return -EIO;
	}

	/*Insert into the key_list*/
	list_add(&p_inst_key->key_node, &s->key_list);

	return p_inst_key->key_id;
}

static int ca_pid_sc(struct ca_dsc_session *s,
	struct ca_pid *pid_info, struct ali_inst_key **target_key, int sc_type)
{
	struct ali_inst_key *key, *tmpkey;

	if (NULL == s || NULL == pid_info || NULL == target_key) {
		dev_dbg(s->dsc->dev, "argument NULL\n");
		return -EINVAL;
	}

	if (PURE_DATA_MODE == s->dma_mode) {
		dev_dbg(s->dsc->dev, "Raw data format, could not set/del PID!\n");
		return -EACCES;
	}

	key = inst_key_find_by_handle(s, pid_info->key_handle);
	if (!key)
		return -EINVAL;

	if (INVALID_TSC(pid_info->tsc_flag)) {
		dev_dbg(s->dsc->dev, "tsc_flag invalid\n");
		return -EINVAL;
	}

	if (1 == sc_type) {
		/* check whether one session with different tsc_flag */
		if (s->tsc_flag != DSC_INVALID_TSC_FLAG) {
			if (pid_info->tsc_flag != s->tsc_flag) {
				dev_dbg(s->dsc->dev, "one session one tsc_flag!\n");
				return -EPERM;
			}
		} else {
			s->tsc_flag = pid_info->tsc_flag;
		}

		/*In case PID full when setting PID*/
		if ((key->pid_size + 1) > CA_PID_MAX) {
			dev_dbg(s->dsc->dev, "key[%d] PID Full!!\n",
			    pid_info->key_handle);
			return -EINVAL;
		}

		/*In case same PID already associated with keyID, e.g.
		keyID1 ~ PID 1/2/3
		KeyID2 ~ PID 2/4/5
		   --> Pid 2 is not allowed, as the same streamID and
		   same PID in different keypos.
		   The HW doesnot know how to fetch.
		*/
		list_for_each_entry(tmpkey, &s->key_list, key_node) {

			if (inst_key_is_pid_exist(tmpkey, pid_info->pid,
					pid_info->ltsid)) {
				dev_dbg(s->dsc->dev,
					"pid[%d:%d] exists in key[%d]!\n",
					pid_info->ltsid, pid_info->pid,
					tmpkey->key_id);
				return -EINVAL;
			}
		}
	}

	*target_key = key;
	return 0;
}

static int ca_pid_add(struct ca_dsc_session *s,
	struct ca_pid *pid_info)
{
	int ret = 0;
	struct ali_inst_key *key = NULL;
	PID_PARAM pid_param;

	ret = ca_pid_sc(s, pid_info, &key, 1);
	if (ret < 0)
		return ret;

	memset(&pid_param, 0, sizeof(PID_PARAM));
	pid_param.handle = key->key_handle;
	pid_param.pid = pid_info->pid;
	pid_param.ltsid = pid_info->ltsid;
	pid_param.tsc_flag = pid_info->tsc_flag;
	pid_param.operate = 1;

	if (s->sub_module == AES) {
		ret = ali_aes_ioctl(s->dsc, (AES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_ADD_DEL_PID), (__u32)&pid_param);
	} else if (s->sub_module == DES || s->sub_module == TDES) {
		ret = ali_des_ioctl(s->dsc, (DES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_ADD_DEL_PID), (__u32)&pid_param);
	} else if (s->sub_module == CSA) {
		ret = ali_csa_ioctl(s->dsc, (CSA_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_ADD_DEL_PID), (__u32)&pid_param);
	}

	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "IO_ADD_DEL_PID failed, ret:%d\n", ret);
		return -EIO;
	}

	/*add it if lower add successfully*/
	ret = inst_key_add_pid(key, pid_info->pid,
			pid_info->ltsid, pid_info->tsc_flag);
	if (ret) {
		dev_dbg(s->dsc->dev, "Add pid failed!\n");
		return ret;
	}

	return 0;
}

/****************
	key_id: key_handle & 0x0000FFFF
	update key type: (key_handle & 0x01000000) >> 24
		0: update clear key
		1: update kl key
	key type: (key_handle & 0x10000000) >> 28
		0: single key type (clear or kl)
		1: mix key type (clear and kl)
	kl_fd: (key_handle & 0x00FF0000) >> 16
*/
static int ca_mix_key_update(struct ca_dsc_session *s,
	void *p, struct ali_inst_key *key, int type)
{
	struct ca_update_params *up_pm = NULL;
	struct ca_update_clear_key *up_clr = NULL;
	int up_key_type;
	int ret;

	if (s->dma_mode == PURE_DATA_MODE) {
		dev_dbg(s->dsc->dev, "None TS mode not support Mix Key!\n");
		return -EKEYREJECTED;
	}

	if (type == 0) {
		up_clr = (struct ca_update_clear_key *)p;
		if ((up_clr->key_handle >> 24) & 0x01) {
			dev_dbg(s->dsc->dev, "Not require to update Host Key...\n");
			return -EINVAL;
		}

		goto succ_out;
	}

	up_pm = (struct ca_update_params *)p;
	up_key_type = (up_pm->key_handle >> 24) & 0x01;
	if (up_key_type == 0)
		goto succ_out;

	/* update KL key info*/
	if (key->kl_fd != ((up_pm->key_handle >> 16) & 0xFF)) {

		if (key->cell)
			put_key_cell(key->cell);

		key->cell = NULL;
		key->kl_fd = (up_pm->key_handle >> 16) & 0xFF;
		ret = fetch_key_cell_by_fd(key->kl_fd, &key->cell);
		if (ret || !key->cell) {
			dev_dbg(s->dsc->dev, "ERR:fetch key cell,%d\n", ret);
			return ret;
		} else {
			get_key_cell(key->cell);
		}
	}

	/*check key cell available*/
	if (!key->cell) {
		dev_dbg(s->dsc->dev, "ERR: pls fetch key cell first\n");
		return -EFAULT;
	}

	if (key->cell->ck_parity == CA_PARITY_EVEN) {
		/*Even key is at KL, not update Host Even Key*/
		key->even_locate = 1;
		key->no_even = 1;
	} else if (key->cell->ck_parity == CA_PARITY_ODD) {
		/*Odd key is at KL, not update Host Odd Key*/
		key->odd_locate = 1;
		key->no_odd = 1;
	} else if (key->cell->ck_parity == CA_PARITY_AUTO) {
		key->even_locate = 1;
		key->no_even = 1;
		key->odd_locate = 1;
		key->no_odd = 1;
	}

succ_out:
	key->key_type = DSC_INST_MIX_KEY;

	return 0;
}

static int ca_pid_del(struct ca_dsc_session *s, struct ca_pid *pid_info)
{
	int ret = 0;
	struct ali_inst_key *key;
	PID_PARAM pid_param;

	ret = ca_pid_sc(s, pid_info, &key, 0);
	if (ret < 0)
		return ret;

	/*del pid*/
	inst_key_del_pid(key, pid_info->pid, pid_info->ltsid);

	memset(&pid_param, 0, sizeof(PID_PARAM));
	pid_param.handle = key->key_handle;
	pid_param.pid = pid_info->pid;
	pid_param.ltsid = pid_info->ltsid;
	pid_param.operate = 2;

	if (s->sub_module == AES) {
		ret = ali_aes_ioctl(s->dsc, (AES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_ADD_DEL_PID), (__u32)&pid_param);
	} else if (s->sub_module == DES || s->sub_module == TDES) {
		ret = ali_des_ioctl(s->dsc, (DES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_ADD_DEL_PID), (__u32)&pid_param);
	} else if (s->sub_module == CSA) {
		ret = ali_csa_ioctl(s->dsc, (CSA_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_ADD_DEL_PID), (__u32)&pid_param);
	}

	if (RET_SUCCESS != ret) {
		dev_dbg(s->dsc->dev, "IO_ADD_DEL_PID failed, ret:%d\n", ret);
		ret = (-EIO);
	}

	return ret;
}

static int ca_clear_key_update_sc(struct ca_dsc_session *s,
	struct ca_update_clear_key *update_clear_key,
	struct ali_inst_key **inst_key)
{
	struct ali_inst_key *key = NULL;

	if (NULL == update_clear_key || NULL == s) {
		dev_dbg(s->dsc->dev, "argument NULL\n");
		return -EINVAL;
	}

	key = inst_key_find_by_handle(s, update_clear_key->key_handle);
	if (!key)
		return -EINVAL;

	*inst_key = key;
	return 0;
}

static int ca_clear_key_update(struct ca_dsc_session *s,
	struct ca_update_clear_key *update_clear_key)
{
	int ret;
	struct ali_inst_key *key;
	int key_size;
	KEY_PARAM key_param;
	AES_KEY_PARAM aes_key_info;
	DES_KEY_PARAM des_key_info;
	CSA_KEY_PARAM csa_key_info;

	ret = ca_clear_key_update_sc(s, update_clear_key, &key);
	if (ret < 0)
		return ret;

	if (CA_VALID_KEY_ODD & update_clear_key->valid_mask) {
		memcpy(key->key_odd,
			update_clear_key->key_odd,
			CA_KEY_SIZE_MAX);
		key->no_odd = 0; /*update the odd key*/
		key->odd_locate = 0; /*odd key is host key*/
	}
	if (CA_VALID_KEY_EVEN & update_clear_key->valid_mask) {
		memcpy(key->key_even,
			update_clear_key->key_even,
			CA_KEY_SIZE_MAX);
		key->no_even = 0; /*update the even key*/
		key->even_locate = 0; /*even key is host key*/
	}

	if ((key->key_type == DSC_INST_KL_KEY ||
		key->key_type == DSC_INST_MIX_KEY) &&
		(update_clear_key->key_handle & (1 << 28))) {

		ret = ca_mix_key_update(s, (void *)update_clear_key, key, 0);
		if (ret != 0)
			return ret;
	}

	/*update Clear Key*/
	key_size = key->key_size * 8;
	memset(&key_param, 0, sizeof(KEY_PARAM));
	key_param.handle = key->key_handle;
	key_param.key_length = key_size;
	key_param.no_even = key->no_even;
	key_param.no_odd = key->no_odd;
	key_param.even_key_locate = key->even_locate;
	key_param.odd_key_locate = key->odd_locate;
	if (key->key_type == DSC_INST_CLEAR_KEY)
		key_param.key_from = KEY_FROM_SRAM;
	else if (key->key_type == DSC_INST_KL_KEY)
		key_param.key_from = KEY_FROM_CRYPTO;
	else if (key->key_type == DSC_INST_MIX_KEY)
		key_param.key_from = KEY_FROM_MIX;

	if (s->sub_module == AES) {
		memset(&aes_key_info, 0, sizeof(AES_KEY_PARAM));
		if (key_size == 128) {
			memcpy(aes_key_info.aes_128bit_key.odd_key,
				key->key_odd, 16);
			memcpy(aes_key_info.aes_128bit_key.even_key,
				key->key_even, 16);
		} else if (key_size == 192) {
			memcpy(aes_key_info.aes_192bit_key.odd_key,
				key->key_odd, 24);
			memcpy(aes_key_info.aes_192bit_key.even_key,
				key->key_even, 24);
		} else {
			memcpy(aes_key_info.aes_256bit_key.odd_key,
				key->key_odd, 32);
			memcpy(aes_key_info.aes_256bit_key.even_key,
				key->key_even, 32);
		}

		key_param.p_aes_key_info = &aes_key_info;

		/*Now, Exec the IO_KEY_INFO_UPDATE_CMD*/
		ret = ali_aes_ioctl(s->dsc, (AES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_KEY_INFO_UPDATE_CMD), (__u32)&key_param);
		if (RET_SUCCESS != ret) {
			dev_dbg(s->dsc->dev, "aes up failed, ret:%d\n", ret);
			ret = -EIO;
		}
	} else if (s->sub_module == DES || s->sub_module == TDES) {
		memset(&des_key_info, 0, sizeof(DES_KEY_PARAM));
		if (key_size == 128) {
			memcpy(des_key_info.des_128bits_key.OddKey,
				key->key_odd, 16);
			memcpy(des_key_info.des_128bits_key.EvenKey,
				key->key_even, 16);
		} else if (key_size == 192) {
			memcpy(des_key_info.des_192bits_key.OddKey,
				key->key_odd, 24);
			memcpy(des_key_info.des_192bits_key.EvenKey,
				key->key_even, 24);
		} else {
			memcpy(des_key_info.des_64bits_key.OddKey,
				key->key_odd, 8);
			memcpy(des_key_info.des_64bits_key.EvenKey,
				key->key_even, 8);
		}

		key_param.p_des_key_info = &des_key_info;

		/*Now, Exec the IO_KEY_INFO_UPDATE_CMD*/
		ret = ali_des_ioctl(s->dsc, (DES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_KEY_INFO_UPDATE_CMD),
			(__u32)&key_param);
		if (RET_SUCCESS != ret) {
			dev_dbg(s->dsc->dev, "des up failed, ret:%d\n", ret);
			ret = -EIO;
		}
	} else if (s->sub_module == CSA) {
		/*only support most 128 when CSA3*/
		key_size = (s->csa_version == CSA3) ? 128 : 64;

		memset(&csa_key_info, 0, sizeof(CSA_KEY_PARAM));
		if (s->csa_version == CSA3) {
			memcpy(csa_key_info.csa3_key.OddKey,
				key->key_odd, 16);
			memcpy(csa_key_info.csa3_key.EvenKey,
				key->key_even, 16);
		} else {
			memcpy(csa_key_info.csa_key.OddKey,
				key->key_odd, 8);
			memcpy(csa_key_info.csa_key.EvenKey,
				key->key_even, 8);
		}

		key_param.p_csa_key_info = &csa_key_info;
		key_param.key_length = key_size;

		/*Now, Exec the IO_KEY_INFO_UPDATE_CMD*/
		ret = ali_csa_ioctl(s->dsc, (CSA_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_KEY_INFO_UPDATE_CMD), (__u32)&key_param);
		if (RET_SUCCESS != ret) {
			dev_dbg(s->dsc->dev, "csa up failed, ret:%d\n", ret);
			ret = -EIO;
		}
	} else {
		dev_dbg(s->dsc->dev, "Err: not support yet!\n");
		ret = -EPERM;
	}

	return ret;
}

static int ca_params_update_sc(struct ca_dsc_session *s,
	struct ca_update_params *update_params,
	struct ali_inst_key **inst_key)
{
	struct ali_inst_key *key = NULL;

	if (NULL == update_params || NULL == s) {
		dev_dbg(s->dsc->dev, "argument NULL\n");
		return -EINVAL;
	}

	if (INVALID_RESIDUE_MODE(update_params->residue_mode) &&
		(update_params->valid_mask & CA_VALID_RESIDUE_MODE)) {
		dev_dbg(s->dsc->dev, "Invalid residue, %d\n",
			update_params->residue_mode);
		return -EINVAL;
	}

	if (INVALID_WORK_MODE(update_params->chaining_mode) &&
		(update_params->valid_mask & CA_VALID_CHAINING_MODE)) {
		dev_dbg(s->dsc->dev, "Invalid chaining_mode\n");
		return -EINVAL;
	}

	if (INVALID_CRYPT_MODE(update_params->crypt_mode) &&
		(update_params->valid_mask & CA_VALID_CRYPT_MODE)) {
		dev_dbg(s->dsc->dev, "Invalid crypt_mode\n");
		return -EINVAL;
	}

	if (INVALID_PARITY(update_params->parity) &&
		(update_params->valid_mask & CA_VALID_PARITY)) {
		dev_dbg(s->dsc->dev, "Invalid parity\n");
		return -EINVAL;
	}

	/*find the key*/
	key = inst_key_find_by_handle(s, update_params->key_handle);
	if (!key)
		return -EINVAL;

	*inst_key = key;
	return 0;
}

static int ca_params_update(struct ca_dsc_session *s,
	struct ca_update_params *update_params)
{
	int ret;
	struct ali_inst_key *key;
	IV_OTHER_PARAM other_param;

	ret = ca_params_update_sc(s, update_params, &key);
	if (ret < 0)
		return ret;

	memset(&other_param, 0, sizeof(IV_OTHER_PARAM));

	/* update parameters */
	if (update_params->valid_mask & CA_VALID_RESIDUE_MODE) {
		s->residue_mode = update_params->residue_mode;

		other_param.residue = g_switch_residue[s->residue_mode];
		other_param.valid_mask |= UP_PARAM_RESIDUE;
	}

	if (update_params->valid_mask & CA_VALID_CRYPT_MODE)
		s->crypt_mode = update_params->crypt_mode;

	if (update_params->valid_mask & CA_VALID_CHAINING_MODE) {
		s->chaining_mode = update_params->chaining_mode;

		other_param.chaining = g_switch_chaining[s->chaining_mode];
		other_param.valid_mask |= UP_PARAM_CHAINING;
	}

	if (update_params->valid_mask & CA_VALID_PARITY) {
		s->parity = update_params->parity;

		other_param.parity = g_switch_parity[s->parity];
		other_param.valid_mask |= UP_PARAM_PARITY;
	}

	other_param.handle = key->key_handle;
	if (update_params->valid_mask & CA_VALID_IV_ODD) {
		memcpy(key->iv_odd, update_params->iv_odd,
			CA_IV_SIZE_MAX);

		memcpy(other_param.iv_odd, key->iv_odd, 16);
		other_param.valid_mask |= UP_PARAM_IV_ODD;
	}

	if (update_params->valid_mask & CA_VALID_IV_EVEN) {
		memcpy(key->iv_even, update_params->iv_even,
			CA_IV_SIZE_MAX);

		memcpy(other_param.iv_even, key->iv_even, 16);
		other_param.valid_mask |= UP_PARAM_IV_EVEN;
	}

	if (update_params->key_handle & (1 << 28)) {
		ret = ca_mix_key_update(s, (void *)update_params, key, 1);
		if (ret != 0)
			return ret;
	}

	other_param.no_even = key->no_even;
	other_param.no_odd = key->no_odd;
	other_param.even_key_locate = key->even_locate;
	other_param.odd_key_locate = key->odd_locate;
	if (key->key_type == DSC_INST_CLEAR_KEY)
		other_param.key_from = KEY_FROM_SRAM;
	else if (key->key_type == DSC_INST_KL_KEY)
		other_param.key_from = KEY_FROM_CRYPTO;
	else if (key->key_type == DSC_INST_MIX_KEY)
		other_param.key_from = KEY_FROM_MIX;

	if (key->cell) {
		other_param.pos = key->cell->pos;
		other_param.kl_sel = key->cell->kl_sel;
	}

	if (s->sub_module == AES) {
		ret = ali_aes_ioctl(s->dsc, (AES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_PARAM_INFO_UPDATE), (__u32)&other_param);
		if (RET_SUCCESS != ret) {
			dev_dbg(s->dsc->dev, "ret:%d\n", ret);
			ret = -EIO;
		}
	} else if (s->sub_module == DES || s->sub_module == TDES) {
		ret = ali_des_ioctl(s->dsc, (DES_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_PARAM_INFO_UPDATE), (__u32)&other_param);
		if (RET_SUCCESS != ret) {
			dev_dbg(s->dsc->dev, "ret:%d\n", ret);
			ret = -EIO;
		}
	} else if (s->sub_module == CSA) {
		ret = ali_csa_ioctl(s->dsc, (CSA_DEV *)s->sub_dev_see_hdl,
			DSC_IO_CMD(IO_PARAM_INFO_UPDATE), (__u32)&other_param);
		if (RET_SUCCESS != ret) {
			dev_dbg(s->dsc->dev, "ret:%d\n", ret);
			ret = -EIO;
		}
	} else {
		dev_dbg(s->dsc->dev, "Err: not support yet!\n");
		ret = -EPERM;
	}

	return ret;
}

static int ca_unset_key(struct ca_dsc_session *s, int key_id)
{
	struct ali_inst_key *key = inst_key_find_by_handle(s, key_id);
	if (!key)
		return -EINVAL;

	/*Delete this key from the key_list*/
	list_del(&key->key_node);

	/*unset this key, and the associated pids*/
	dsc_delete_crypto_stream(s, key->key_handle);
	inst_key_delete(key);

	return 0;
}

long ca_dsc_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	int ret = RET_SUCCESS;
	struct ca_dsc_session *s = NULL;

	s = (struct ca_dsc_session *)file->private_data;
	if (!s)
		return -EBADF;

	mutex_lock(&s->wr_mutex);

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(CA_SET_FORMAT):
	{
		int ca_format;

		ret = ali_dsc_umemcpy(&ca_format,
			(void __user *)args, sizeof(int));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_format_set(s, ca_format);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_CREATE_CLEAR_KEY):
	{
		struct ca_create_clear_key clear_key_info;

		memset(&clear_key_info, 0, sizeof(struct ca_create_clear_key));
		ret = ali_dsc_umemcpy(&clear_key_info, (void __user *)args,
			sizeof(struct ca_create_clear_key));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_clear_key_set(s, &clear_key_info);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_CREATE_KL_KEY):
	{
		struct ca_create_kl_key kl_key;

		memset(&kl_key, 0, sizeof(struct ca_create_kl_key));
		ret = ali_dsc_umemcpy(&kl_key, (void __user *)args,
			sizeof(struct ca_create_kl_key));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_kl_key_set(s, &kl_key);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_CREATE_OTP_KEY):
	{
		struct ca_create_otp_key otp_key_info;

		memset(&otp_key_info, 0, sizeof(struct ca_create_otp_key));
		ret = ali_dsc_umemcpy(&otp_key_info, (void __user *)args,
			sizeof(struct ca_create_otp_key));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_otp_key_set(s, &otp_key_info);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_ADD_PID):
	{
		struct ca_pid pid_info;

		memset(&pid_info, 0, sizeof(struct ca_pid));
		ret = ali_dsc_umemcpy(&pid_info, (void __user *)args,
			sizeof(struct ca_pid));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_keep_consistent(s);
		if (ret) {
			dev_dbg(s->dsc->dev,
				"cannot add pid now!\n");
			goto DONE;
		}

		ret = ca_pid_add(s, &pid_info);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_DEL_PID):
	{
		struct ca_pid pid_info;

		memset(&pid_info, 0, sizeof(struct ca_pid));
		ret = ali_dsc_umemcpy(&pid_info, (void __user *)args,
			sizeof(struct ca_pid));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_keep_consistent(s);
		if (ret) {
			dev_dbg(s->dsc->dev,
				"cannot del pid now!\n");
			goto DONE;
		}

		ret = ca_pid_del(s, &pid_info);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_UPDATE_CLEAR_KEY):
	{
		struct ca_update_clear_key update_clear_key;

		memset(&update_clear_key, 0,
			sizeof(struct ca_update_clear_key));
		ret = ali_dsc_umemcpy(&update_clear_key, (void __user *)args,
			sizeof(struct ca_update_clear_key));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_keep_consistent(s);
		if (ret) {
			dev_dbg(s->dsc->dev,
				"cannot update key now!\n");
			goto DONE;
		}

		ret = ca_clear_key_update(s, &update_clear_key);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_UPDATE_PARAMS):
	{
		struct ca_update_params update_params;

		memset(&update_params, 0, sizeof(struct ca_update_params));
		ret = ali_dsc_umemcpy(&update_params, (void __user *)args,
			sizeof(struct ca_update_params));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_keep_consistent(s);
		if (ret) {
			dev_dbg(s->dsc->dev,
				"cannot update parameters now!\n");
			goto DONE;
		}

		ret = ca_params_update(s, &update_params);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_DELETE_KEY):
	{
		int key_id;

		key_id = (int)args;

		ret = ca_keep_consistent(s);
		if (ret) {
			dev_dbg(s->dsc->dev,
				"cannot del key now!\n");
			goto DONE;
		}

		ret = ca_unset_key(s, key_id);
		if (ret < 0)
			goto DONE;

		break;
	}

	case DSC_IO_CMD(CA_SET_OPT):
	{
		int ca_opt;

		ret = s->engine.ops->is_empty(&s->engine);

		ca_opt = (int)args;
		ret = ca_opt_set(s, ca_opt);
		if (ret < 0)
			goto DONE;

		break;
	}

	default:
	{
		mutex_unlock(&s->wr_mutex);

		ret = ca_dsc_ioctl_legacy(file, cmd, args);
		if (ret)
			dev_dbg(s->dsc->dev, "invalid ioctl\n");

		return ret;
	}
	}

DONE:
	mutex_unlock(&s->wr_mutex);
	return ret;
}
