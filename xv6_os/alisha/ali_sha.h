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

#ifndef __ALI_SHA_H__
#define __ALI_SHA_H__

#include <linux/types.h>
#include <linux/mutex.h>
#include <crypto/sha.h>
#include <alidefinition/adf_dsc.h>
#include <linux/ali_rpc.h>
#include <rpc_hld/ali_rpc_hld.h>
#include <linux/cdev.h>
#include <linux/idr.h>
#include "see_bus.h"
#include <ali_sbm_types.h>

#define NODE_NUM_OF_SBM 256
#define ALI_SHA_MAX_DIGEST_SIZE (64)
#define NO_CHRDEVS (1)
#define FIRST_MIN (0)

struct ali_sha_vm_node {
    struct ali_sha_vm_node *next;
    unsigned long vm_kaddr;
    unsigned long vm_start;
    unsigned long vm_end;
    size_t vm_size;
    long vm_owner;
	struct vm_area_struct *vma;
};

struct ali_sha_dev {
	dev_t  devt;
	struct cdev cdev;
	struct device *dev;
	struct class *class;
	struct mutex mutex;

	void *see_sha_id[VIRTUAL_DEV_NUM];
	struct see_client *clnt;
	int debug;
	int num_inst;

	struct ida sess_ida;
	struct ali_sha_vm_node* vm_area_list;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_dir;
#endif
};

struct ali_sha_session {
	struct ali_sha_dev *psha;
	struct mutex mutex;
	int id;

	unsigned int sub_dev_id;
	int init;
	int type;
	int dgt_size;
	int block_size;
	
#ifdef CONFIG_DEBUG_FS
	struct dentry *session_dir;
	struct dentry *debugfs;
	struct dentry *choice;
#endif
};

struct ali_sha_node {
	unsigned char *input;	/* pointer to the input data */
	unsigned char *output;	/* pointer to the output data */
	unsigned int size;		/* input data size in bytes */
};

void ali_m36_sha_see_init(void);
__u32 ali_sha_get_free_sub_device_id(void);
int ali_sha_set_sub_device_id_idle(__u32 device_id);
int ali_sha_ioctl(SHA_DEV *pShaDev, __u32 cmd, __u32 param);
int ali_sha_digest(SHA_DEV *pShaDev, __u8 *input, __u8 *output, u32 data_len);
int see_sha_sbm_open(SHA_DEV *pShaDev, int sbm_id);
int ali_sbm_release_task(int sbm_id);

#endif /*__ALI_SHA_H__*/


