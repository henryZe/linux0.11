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
#ifndef __CA_DSC_PRIV_H__
#define __CA_DSC_PRIV_H__

#include <linux/idr.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#endif


#include <linux/ali_rpc.h>
#include <rpc_hld/ali_rpc_hld.h>
#include <ca_otp.h>

#include <alidefinition/adf_dsc.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#include "ca_dsc.h"
#include "see_bus.h"
#include "ali_sbm_client.h"
#include "ca_dsc_session_engine.h"

struct ca_dsc_session;

#define ALI_DSC_KERNEL_KEY_SIZE		(1024*20)
#define ALI_DSC_LLD_MAX_ITEM		(64)

#define TS_PACKET_SIZE				(188)

#define DSC_INVALID_TSC_FLAG		(0xFF)
#define DSC_INVALID_SUB_MODULE		(0xFF)
#define DSC_INVALID_DMA_MODE		(0xFF)
#define DSC_INVALID_PID				(0xFFFF)

#define DSC_INST_CLEAR_KEY			(0x80)
#define DSC_INST_KL_KEY				(0x81)
#define DSC_INST_OTP_KEY			(0x82)
#define DSC_INST_MIX_KEY			(0x83)

#define DSC_TSC_CLEAR_EVEN	(0)
#define DSC_TSC_CLEAR_ODD	(1)
#define DSC_TSC_CIPHER_EVEN	(2)
#define DSC_TSC_CIPHER_ODD	(3)

#define DSC_SCHE_DELAY usecs_to_jiffies(100)

struct dsc_pid {
	unsigned short pid;
	unsigned char ltsid;
	unsigned char tsc;

	struct list_head pid_node;
};

struct ali_inst_key {
	int key_id;
	unsigned int key_handle;

	/*DSC_INST_CLEAR_KEY, DSC_INST_KL_KEY or DSC_INST_OTP_KEY*/
	int key_type;
	unsigned char iv_odd[CA_IV_SIZE_MAX];
	unsigned char iv_even[CA_IV_SIZE_MAX];
	unsigned char key_odd[CA_KEY_SIZE_MAX];
	unsigned char key_even[CA_KEY_SIZE_MAX];
	int key_size;
	int kl_fd;
	struct kl_key_cell *cell;
	int otp_key_select;

	struct list_head pid_list;
	int pid_size;

	int no_even;
	int no_odd;
	int even_locate; /*0: host, 1: KL*/
	int odd_locate; /*0: host, 1: KL*/

	struct list_head key_node;
	struct ca_dsc_session *s;
};

/*
 * Device structure
 */
struct ca_dsc_dev {
	dev_t  devt;
	struct class *class;
	struct device *dev;
	struct cdev cdev;
	void *base;

	/* number of instance */
	int num_inst;
	unsigned int mode;
	struct mutex mutex;

	void *see_dsc_id;
	void *see_aes_id[VIRTUAL_DEV_NUM];
	void *see_des_id[VIRTUAL_DEV_NUM];
	void *see_csa_id[VIRTUAL_DEV_NUM];
	void *see_sha_id[VIRTUAL_DEV_NUM];

	unsigned char *dsc_key;
	dma_addr_t key_dma_hdl;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_dir;
	/*1: do not process by see hw*/
	int not_gothrough_hw;
#endif

	struct see_client *clnt;
	struct ida sess_ida;
	unsigned int dev_index;
	int debug_mode;
};

/*
 * Session structure
 */
struct ca_dsc_session {
	struct ca_dsc_dev *dsc;
	struct mutex rd_mutex;
	struct mutex wr_mutex;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs;
	struct dentry *choice;
	struct dentry *buffer_id;
#endif

	int id;
	struct ca_dsc_se engine;

	/* Externel Parameters */
	enum DMA_MODE dma_mode;
	enum WORK_SUB_MODULE sub_module;
	enum CSA_VERSION csa_version; /*available when algo is CSA*/

	struct list_head key_list;

	int algo;
	int crypt_mode;
	int chaining_mode;
	int residue_mode;
	int parity;
	int format;
	/*1: raw data; 188: TS188; 200: TS200*/
	int pkt_size;
	/*cork / uncork*/
	int opt;
	unsigned char ts_chaining;
	/*When working in Mode 2, scrambler will let
	the clear stream go through, with header/payloads
	unchanged even if key/pids are configured properly.
		0: mode 1
		1: mode 2
	*/
	unsigned char sc_mode;
	/*
	-----------------------------------------------
	received tsc bits	|tsc After DE	|tsc After EN (mode 1)
	-----------------------------------------------
	00 no scrambling	|00 (no DE)	|tsc (EN odd/even)
	11	odd parity	|tsc (odd DE)	|no change (no EN)
	10 even parity	|tsc (even DE)|no change (no EN)

	-----------------------------------------------
	received tsc bits	|tsc After DE	|tsc After EN (mode 2)
	-----------------------------------------------
	00 no scrambling	|00 (no DE)	|00 (stream remains clear)
	11 odd   parity	|tsc	(odd DE)	|tsc (EN with tsc parity)
	10 even parity	|tsc (even DE)|tsc (EN with tsc parity)
	*/
	unsigned char tsc_flag;

	/*Status*/
	unsigned char stream_id_flag;
	unsigned char fmt_flag;

	/*internal Resources*/
	struct ida key_ida;
	unsigned short stream_id;
	unsigned short sub_dev_id;
	/*sub device handler at see*/
	unsigned int sub_dev_see_hdl;

	struct see_sbm sbm;

#ifdef CONFIG_DEBUG_FS
	struct dentry *session_dir;
#endif
};

struct dsc_clr_key {
	__u16 pid_ptr[ALI_DSC_LLD_MAX_ITEM];
	union {
		AES_KEY_PARAM p_aes_key_info[ALI_DSC_LLD_MAX_ITEM];
		CSA_KEY_PARAM p_csa_key_info[ALI_DSC_LLD_MAX_ITEM];
		DES_KEY_PARAM p_des_key_info[ALI_DSC_LLD_MAX_ITEM];
	} key_ptr[1];

	union {
		AES_IV_INFO p_aes_iv_info[ALI_DSC_LLD_MAX_ITEM];
		DES_IV_INFO p_des_iv_info[ALI_DSC_LLD_MAX_ITEM];
	} iv_ptr[1];

	__u8 ctr_ptr[16];
};

int dsc_delete_crypto_stream(struct ca_dsc_session *s, int key_handle);
void inst_key_delete(struct ali_inst_key *inst_key);
int dsc_release_internel_resource(struct ca_dsc_session *s);

#endif


