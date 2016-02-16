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

#ifndef _CA_DSC_RPC_H_
#define _CA_DSC_RPC_H_

#include <alidefinition/adf_dsc.h>

int ali_dsc_umemcpy(void *dest, const void *src, __u32 n);
int ali_des_ioctl(struct ca_dsc_dev *dsc,
	DES_DEV *pDesDev, __u32 cmd, __u32 param);
int ali_aes_ioctl(struct ca_dsc_dev *dsc,
	AES_DEV *pAesDev, __u32 cmd, __u32 param);
int ali_dsc_ioctl(struct ca_dsc_dev *dsc,
	DSC_DEV *pDscDev, __u32 cmd, __u32 param);
int ali_csa_ioctl(struct ca_dsc_dev *dsc,
	CSA_DEV *pCsaDev, __u32 cmd, __u32 param);

__u16 ali_dsc_get_free_stream_id(struct ca_dsc_dev *dsc,
	enum DMA_MODE dma_mode);
__u32 ali_dsc_get_free_sub_device_id(struct ca_dsc_dev *dsc,
	__u8 sub_mode);
int ali_dsc_set_sub_device_id_idle(struct ca_dsc_dev *dsc,
	__u8 sub_mode, __u32 device_id);
int ali_dsc_set_stream_id_idle(struct ca_dsc_dev *dsc,
	__u32 pos);

void ali_m36_dsc_see_init(struct ca_dsc_dev *dsc);
void ali_m36_dsc_see_uninit(struct ca_dsc_dev *dsc);
int ali_dsc_create_sbm_task(struct ca_dsc_dev *dsc,
	UINT32 sbm_id);
int ali_dsc_delete_sbm_task(struct ca_dsc_dev *dsc,
	UINT32 sbm_id);

#endif

