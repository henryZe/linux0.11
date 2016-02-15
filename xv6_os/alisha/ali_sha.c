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

#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/semaphore.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <crypto/sha.h>
#include <asm/byteorder.h>
#include <linux/device.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/of.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/cdev.h>
#include <ali_sbm_client.h>
#include "ali_sha.h"
#include "ca_sha.h"
#include "ali_sha_sysfs.h"
#include "ali_sha_dbgfs.h"

#define SHA_INVALID_TYPE(type) ( \
	(type) != CA_SHA_TYPE_1 && \
	(type) != CA_SHA_TYPE_224 && \
	(type) != CA_SHA_TYPE_256 && \
	(type) != CA_SHA_TYPE_384 && \
	(type) != CA_SHA_TYPE_512)

#define __G_ALI_MM_SIZE PAGE_SIZE*10

static void *sha_mm_addr = NULL;

static int ca_sha_open(struct inode *inode, struct file *file)
{
	struct ali_sha_dev *psha = container_of(inode->i_cdev,
			struct ali_sha_dev, cdev);
	struct ali_sha_session *s;
	int ret;

	mutex_lock(&psha->mutex);

	if (psha->num_inst >= 8) {
		mutex_unlock(&psha->mutex);
		return -EBUSY;
	}

	s = devm_kzalloc(psha->dev,
			sizeof(struct ali_sha_session), GFP_KERNEL);
	if (!s) {
		ret = -ENOMEM;
		goto ZALLOC_FAIL;
	}

	sha_mm_addr = kmalloc(__G_ALI_MM_SIZE, GFP_KERNEL | __GFP_ZERO);

	psha->num_inst++;

	/*internal resource init*/
	memset(s, 0, sizeof(struct ali_sha_session));

	mutex_init(&s->mutex);
	s->psha = psha;
	file->private_data = (void *)s;
	s->id = ida_simple_get(&psha->sess_ida,
		0, 0, GFP_KERNEL);

	s->sub_dev_id = ali_sha_get_free_sub_device_id();
	if (s->sub_dev_id == ALI_INVALID_DSC_SUB_DEV_ID ||
		s->sub_dev_id >= VIRTUAL_DEV_NUM) {
		dev_dbg(&s->psha->clnt->dev,
			"fail to get SHA sub devId\n");
		goto GET_SUB_DEV_FAIL;
	}

	mutex_unlock(&psha->mutex);
	ca_sha_dbgfs_add_session(s);
	return 0;

GET_SUB_DEV_FAIL:
	devm_kfree(psha->dev, s);
ZALLOC_FAIL:
	mutex_unlock(&psha->mutex);
	return ret;
}

static int ca_sha_release(struct inode *inode, struct file *file)
{
	struct ali_sha_session *s = file->private_data;
	struct ali_sha_dev *psha;

	if (!s)
		return -EBADF;

	/*Do not release resource when debug*/
	if (s->psha->debug)
		return 0;

	psha = s->psha;

	mutex_lock(&psha->mutex);
	ali_sha_set_sub_device_id_idle(s->sub_dev_id);
	psha->num_inst--;
	mutex_destroy(&s->mutex);
	file->private_data = NULL;
	ida_simple_remove(&psha->sess_ida, s->id);

#ifndef CONFIG_DEBUG_FS
	ca_sha_dbgfs_del_session(s);
#endif

	devm_kfree(psha->dev, s);

	mutex_unlock(&psha->mutex);

	kfree(sha_mm_addr);
	sha_mm_addr = NULL;

	return 0;
}


static void ca_sha_munmap(struct vm_area_struct *vma)
{
	struct ali_sha_session *s = vma->vm_private_data;
	struct ali_sha_dev *psha = NULL;
	struct ali_sha_vm_node *p_last_node = NULL;
	struct ali_sha_vm_node *p_cur_node = NULL;

	if (!s)
		return;

	psha = s->psha;
	if (!psha)
		return;

	/*dev_info(psha->dev, "munmap--vma:%p, vm_start:%lx, end:%lx, len: 0x%lx\n",
                                vma, vma->vm_start, vma->vm_end,
                                vma->vm_end - vma->vm_start);*/

	mutex_lock(&s->mutex);

	for(p_cur_node=psha->vm_area_list; p_cur_node; p_cur_node=p_cur_node->next)
	{
		if (p_cur_node->vma == vma)
		{
			if(p_cur_node == psha->vm_area_list)
			{
				psha->vm_area_list = p_cur_node->next;
			}
			
			if (p_last_node)
			{
				p_last_node->next = p_cur_node->next;
			}
			
			kfree(p_cur_node);
			break;
		}

		p_last_node = p_cur_node;
	}

	mutex_unlock(&s->mutex);	
}

static const struct vm_operations_struct ca_sha_vmops = {
	.close = ca_sha_munmap,
};

static int ca_sha_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret = -1;
	struct ali_sha_session *s = file->private_data;
	struct ali_sha_dev *psha = NULL;
	struct ali_sha_vm_node *p_vm_node = NULL;
	struct ali_sha_vm_node *p_cur_node = NULL;
	size_t size = vma->vm_end - vma->vm_start;
	__u32 kaddr = (__u32)sha_mm_addr;
    __u32 ksize = __G_ALI_MM_SIZE;

	if (!s)
		return -EBADF;

	psha = s->psha;
	if (!psha)
		return -EBADF;

	/*dev_info(psha->dev, "mmap--vma:%p, kaddr:%p, ksize:%d, vm_start:%lx, end:%lx, len: 0x%lx\n",
                                vma, kaddr, ksize, vma->vm_start, vma->vm_end,
                                vma->vm_end - vma->vm_start);*/

	if (!size || (size > ksize))
    {
        dev_info(psha->dev, "size not support, size=0x%x, kbuf max:%dM\n", size, ksize/1024/1024);
        return -EPERM;
    }

	size = (size >= PAGE_SIZE) ? size : PAGE_SIZE;

	p_vm_node = kmalloc(sizeof(struct ali_sha_vm_node), GFP_KERNEL | __GFP_ZERO);
	if (!p_vm_node)
	{
		dev_dbg(psha->dev, "malloc vm node failed!\n");
        return -ENOMEM;
	}

	/* map vma->vm_start to kaddr('s page frame num) in size area */
	ret = remap_pfn_range(vma, vma->vm_start,
                        virt_to_phys((void *)kaddr) >> PAGE_SHIFT,
                        size,  pgprot_noncached(PAGE_SHARED));
    if (ret != 0) 
    {
        dev_dbg(psha->dev, "Kernel error - remap_pfn_range failed\n");
        kfree(p_vm_node);
        return -EAGAIN;
    }

	p_vm_node->vm_kaddr = kaddr;
	p_vm_node->vm_start = vma->vm_start;
	p_vm_node->vm_end = vma->vm_end;
	p_vm_node->vm_size = size;
	p_vm_node->vm_owner= sys_getpid();
	p_vm_node->next = NULL;
	p_vm_node->vma = vma;

	mutex_lock(&s->mutex);
	if (psha->vm_area_list)
	{
		for (p_cur_node = psha->vm_area_list; NULL != p_cur_node->next; 
									p_cur_node = p_cur_node->next);
    	p_cur_node->next = p_vm_node;
	}
	else
	{
		psha->vm_area_list = p_vm_node;
	}
	
	mutex_unlock(&s->mutex);

	//vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_NONLINEAR;
	vma->vm_private_data = s;
	vma->vm_ops = &ca_sha_vmops;

	return 0;
}

static int ca_sha_init(struct ali_sha_session *s,
	int type)
{
	int ret = 0;
	SHA_INIT_PARAM sha_param;
	const int work_mode[] = {
		[CA_SHA_TYPE_1] = SHA_SHA_1,
		[CA_SHA_TYPE_224] = SHA_SHA_224,
		[CA_SHA_TYPE_256] = SHA_SHA_256,
		[CA_SHA_TYPE_384] = SHA_SHA_384,
		[CA_SHA_TYPE_512] = SHA_SHA_512,
	};

	const int dgt_size[] = {
		[CA_SHA_TYPE_1] = 20,
		[CA_SHA_TYPE_224] = 28,
		[CA_SHA_TYPE_256] = 32,
		[CA_SHA_TYPE_384] = 48,
		[CA_SHA_TYPE_512] = 64,
	};

	const int block_size[] = {
		[CA_SHA_TYPE_1] = 64,
		[CA_SHA_TYPE_224] = 64,
		[CA_SHA_TYPE_256] = 64,
		[CA_SHA_TYPE_384] = 128,
		[CA_SHA_TYPE_512] = 128,
	};

	if (s->init) {
		dev_dbg(s->psha->dev, "cannot init twice!\n");
		return -EPERM;
	}

	if (SHA_INVALID_TYPE(type)) {
		dev_dbg(s->psha->dev, "Invalid type!\n");
		return -EINVAL;
	}

	memset(&sha_param, 0, sizeof(sha_param));
	sha_param.sha_work_mode = work_mode[type];
	sha_param.sha_data_source = SHA_DATA_SOURCE_FROM_DRAM;

	ret = ali_sha_ioctl(s->psha->see_sha_id[s->sub_dev_id],
		DSC_IO_CMD(IO_INIT_CMD), (__u32)(&sha_param));
	if (ret) {
		dev_dbg(s->psha->dev,
			"ali_sha_ioctl error: %d\n", ret);
		ret = -EIO;
	}

	s->init = 1;
	s->type = type;
	s->block_size = block_size[type];
	s->dgt_size = dgt_size[type];

	return ret;
}

static int ca_sha_digest(struct ali_sha_session *s,
	struct digest *pdgt)
{
	int ret;
	unsigned char *input = NULL;
	unsigned char output[64];
	dma_addr_t input_dma_hdl;
	long cur_pid = 0; 
	struct ali_sha_vm_node *p_cur_node = NULL;
	bool is_input_mmap_buffer = 0;

	if (!s->init) {
		dev_dbg(s->psha->dev, "pls init first!\n");
		return -EPERM;
	}

	if (!pdgt->input || !pdgt->output || !pdgt->data_len)
		return -EINVAL;

	if (pdgt->data_len > __G_ALI_MM_SIZE)
	{
		dev_info(s->psha->dev, "%s, input data len[0x%x] not support, max: %ldKB\n", 
					__func__, pdgt->data_len, __G_ALI_MM_SIZE/1024);
		return -ENOMEM;
	}

	cur_pid = sys_getpid();
	for (p_cur_node = s->psha->vm_area_list; p_cur_node; p_cur_node = p_cur_node->next)
    {
        if ((p_cur_node->vm_owner == cur_pid) &&
			((unsigned long)pdgt->input >= p_cur_node->vm_start) &&
			(((unsigned long)pdgt->input + (unsigned long)pdgt->data_len) <= p_cur_node->vm_end))
        {
            input = (__u8 *)(p_cur_node->vm_kaddr + 
							((unsigned long)pdgt->input - p_cur_node->vm_start));
			/*dev_info(s->psha->dev, "zero-copy matched >>>!!!, vm_kaddr:%p, input:%p\n", 
							p_cur_node->vm_kaddr, input);*/
            break;
        }
    }

	//if we can't find the input address in sha vm_area, we can alloc an dma buffer to calc the sha digest.
	if (NULL == input) {
		if (pdgt->data_len > 0x100000)
		{
			dev_info(s->psha->dev, "%s, input data len[0x%x] not support, max:1M, pls use mmap buffer.\n", 
					__func__, pdgt->data_len);
			return -ENOMEM;
		}
		
		input = dma_alloc_coherent(s->psha->dev,
			pdgt->data_len,	&input_dma_hdl, GFP_KERNEL | GFP_DMA);
		if (!input)
			return -ENOMEM;

		is_input_mmap_buffer = 0;

		ret = copy_from_user(input, pdgt->input,
				pdgt->data_len);
		if (ret) {
			dev_dbg(s->psha->dev, "%s, copy user data failed!\n", __func__);
			goto leave;
		}
	}
	else
	{
		is_input_mmap_buffer = 1;
	}
	

	ret = ali_sha_digest(s->psha->see_sha_id[s->sub_dev_id],
		input, output, pdgt->data_len);
	if (ret) {
		dev_dbg(s->psha->dev,
			"ali_sha_digest error: %d\n", ret);
		ret = -EIO;
		goto leave;
	}

	ret = copy_to_user(pdgt->output, output, s->dgt_size);
	if (ret) {
		dev_dbg(s->psha->dev, "%s\n", __func__);
		goto leave;
	}

leave:
	if (!is_input_mmap_buffer) {
		dma_free_coherent(s->psha->dev, pdgt->data_len,
			input, input_dma_hdl);
	}

	return ret;
}

long ca_sha_ioctl(struct file *file, unsigned int cmd,
	unsigned long args)
{
	int ret = RET_SUCCESS;
	struct ali_sha_session *s = NULL;

	s = (struct ali_sha_session *)file->private_data;
	if (!s)
		return -EBADF;

	mutex_lock(&s->mutex);

	switch (cmd) {
	case CA_SHA_SET_TYPE:
	{
		int type;

		ret = copy_from_user(&type,
			(void __user *)args, sizeof(int));
		if (ret) {
			dev_dbg(s->psha->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_sha_init(s, type);
		if (ret < 0)
			goto DONE;

		break;
	}

	case CA_SHA_DIGEST:
	{
		struct digest dgt;

		memset(&dgt, 0, sizeof(dgt));

		ret = copy_from_user(&dgt,
			(void __user *)args, sizeof(struct digest));
		if (ret) {
			dev_dbg(s->psha->dev, "%s\n", __func__);
			goto DONE;
		}

		ret = ca_sha_digest(s, &dgt);
		if (ret < 0)
			goto DONE;

		break;
	}

	default:
	{
		ret = -ENOIOCTLCMD;
		break;
	}
	}

DONE:
	mutex_unlock(&s->mutex);
	return ret;
}

static const struct file_operations ca_sha_fops = {
	.owner		= THIS_MODULE,
	.open		= ca_sha_open,
	.mmap		= ca_sha_mmap,
	.release		= ca_sha_release,
	.unlocked_ioctl	= ca_sha_ioctl,
};

static int ali_sha_probe(struct see_client *clnt)
{
	int i, ret;
	struct ali_sha_dev *psha = NULL;

	psha = devm_kzalloc(&clnt->dev,
		sizeof(struct ali_sha_dev), GFP_KERNEL);
	if (!psha)
		return -ENOMEM;

	psha->clnt = clnt;
	psha->debug = 0;

	/*
	* Character device initialisation
	*/
	ret = alloc_chrdev_region(&psha->devt, FIRST_MIN,
		NO_CHRDEVS, CA_SHA_BASENAME);
	if (ret < 0)
		goto chrdev_alloc_fail;

	cdev_init(&psha->cdev, &ca_sha_fops);
	ret = cdev_add(&psha->cdev, psha->devt, 1);
	if (ret < 0)
		goto cdev_add_fail;

	psha->class = class_create(THIS_MODULE, "ca_sha");
	if (IS_ERR(psha->class)) {
		ret = PTR_ERR(psha->dev);
		goto class_create_fail;
	}
	psha->dev = device_create(psha->class, &clnt->dev, psha->devt,
		psha, CA_SHA_BASENAME);
	if (IS_ERR(psha->dev)) {
		ret = PTR_ERR(psha->dev);
		goto device_create_fail;
	}

	mutex_init(&psha->mutex);

	ali_m36_sha_see_init();

	for (i = 0; i < VIRTUAL_DEV_NUM; i++) {
		psha->see_sha_id[i] = hld_dev_get_by_id(HLD_DEV_TYPE_SHA, i);
		if (NULL == psha->see_sha_id[i]) {
			dev_dbg(&clnt->dev, "SHA get see id error\n");
			goto sysfs_fail;
		}
	}

	psha->vm_area_list = NULL;

	ret = ca_sha_sysfs_create(psha);
	if (ret)
		goto sysfs_fail;

	ca_sha_dbgfs_create(psha);
	dev_set_drvdata(&clnt->dev, psha);
	dev_set_drvdata(psha->dev, psha);
	ida_init(&psha->sess_ida);

	psha->debug = 0;
	dev_info(&clnt->dev, "sha probe.\n");
	return 0;

	ca_sha_dbgfs_remove(psha);
	ca_sha_sysfs_remove(psha);
sysfs_fail:
	device_destroy(psha->class, psha->devt);
device_create_fail:
	class_destroy(psha->class);
class_create_fail:
	cdev_del(&psha->cdev);
cdev_add_fail:
	unregister_chrdev_region(psha->devt, NO_CHRDEVS);
chrdev_alloc_fail:
	devm_kfree(&clnt->dev, psha);

	return ret;
}

static int ali_sha_remove(struct see_client *clnt)
{
	struct ali_sha_vm_node* p_vm_node = NULL;
	struct ali_sha_vm_node* p_free_vm_node = NULL;
	struct ali_sha_dev *psha = dev_get_drvdata(&clnt->dev);
	if (!psha)
		return -ENODEV;

	dev_info(&clnt->dev, "removing SHA driver @%d\n",
		clnt->service_id);

	ca_sha_dbgfs_remove(psha);
	ca_sha_sysfs_remove(psha);
	dev_set_drvdata(&clnt->dev, NULL);
	dev_set_drvdata(psha->dev, NULL);

	for(p_vm_node = psha->vm_area_list; NULL != p_vm_node; )
	{
		p_free_vm_node = p_vm_node;
		p_vm_node = p_vm_node->next;
		kfree(p_free_vm_node);
	}
	psha->vm_area_list = NULL;

	mutex_destroy(&psha->mutex);

	device_destroy(psha->class, psha->devt);
	class_destroy(psha->class);
	cdev_del(&psha->cdev);
	unregister_chrdev_region(psha->devt, NO_CHRDEVS);

	ida_destroy(&psha->sess_ida);

	devm_kfree(&clnt->dev, psha);
	dev_info(&clnt->dev, "driver removed\n");

	return 0;
}

static const struct of_device_id see_sha_matchtbl[] = {
	{ .compatible = "alitech,sha" },
	{ }
};

static struct see_client_driver sha_drv = {
	.probe	= ali_sha_probe,
	.remove	= ali_sha_remove,
	.driver	= {
		.name		= "SHA",
		.of_match_table	= see_sha_matchtbl,
	},
	.see_min_version = SEE_MIN_VERSION(0, 1, 1, 0),
};

module_see_client_driver(sha_drv);

MODULE_DESCRIPTION("Old ALi SHA algorithms support.");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("ALi");
MODULE_VERSION("0.0.1");
MODULE_ALIAS("Ali-sha");

