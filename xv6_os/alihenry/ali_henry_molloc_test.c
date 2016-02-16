#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include <see_bus.h>
#include "ali_henry_priv.h"

#ifdef MMAP_TEST
#include <linux/mm.h>
#include <linux/vmalloc.h>

static int mem_alloc_page(void)
{
	struct page *p = NULL;
	void *vaddr;
	unsigned long paddr;

	p = alloc_page(GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	printk("alloc_page:\n");
	printk("\tAddress of page:%p\n", p);

	vaddr = page_address(p);
	printk("\tAddress of page_address:%p\n", vaddr);

	paddr = virt_to_phys(vaddr);
	printk("\tAddress of virt_to_phys:%lx\n", paddr);

	put_page(p);

	return 0;
}

static int mem_kmalloc(void)
{
	void *k = NULL;
	unsigned long paddr;

	k = kmalloc(100, GFP_KERNEL);
	if (!k)
		return -ENOMEM;

	printk("kmalloc:\n");
	printk("\tAddress of kmalloc:%p\n", k);
	
	paddr = virt_to_phys(k);
	printk("\tAddress of virt_to_phys:%lx\n", paddr);

	kfree(k);

	return 0;
}

static int mem_vmalloc(void)
{
	void *vk = NULL;
	unsigned long paddr;
	void *k;
	struct vm_struct *vm = NULL;
	int i;

	vk = vmalloc(8 * 1024);
	if (!vk)
		return -ENOMEM;

	memset(vk, 5, 8*1024);

	printk("vmalloc:\n");
	printk("\tAddress of vmalloc:%p\n", vk);

	paddr = virt_to_phys(vk);
	printk("\tAddress of virt_to_phys:%lx(NOT CORRECT!!)\n", paddr);

	vm = find_vm_area(vk);
	if (!vm)
		return -EFAULT;

	printk("\tvm info of vk[%p]: vm->addr[%p], vm->nr_pages[%d]\n",
		vk,	vm->addr, vm->nr_pages);

	for(i = 0; i < vm->nr_pages; i++) {
		k = page_address(vm->pages[i]);

		printk("\tpage[%d]:%p, vaddr[%p], paddr[%lx]\n",
			i, vm->pages[i], k, virt_to_phys(k));
	}

	vfree(vk);
	return 0;
}
#endif

static int henry_open
(
	struct inode *inode,
	struct file  *file
)
{
	struct henry_drv *drv =
		container_of(file->f_dentry->d_inode->i_cdev, struct henry_drv, cdev);

#ifdef MMAP_TEST
	mem_alloc_page();
	mem_kmalloc();
	mem_vmalloc();
#endif

	dev_info(drv->dev, "henry_drv_open\n");
	return 0;
}

static int henry_close
(
	struct inode *inode,
	struct file  *file
)
{
	struct henry_drv *drv =
		container_of(file->f_dentry->d_inode->i_cdev, struct henry_drv, cdev);

	dev_info(drv->dev, "henry_drv_close\n");
	return 0;
}

static ssize_t henry_read(struct file *file,
	char __user *buf, size_t size, loff_t *f_pos)
{
	struct henry_drv *drv =
		container_of(file->f_dentry->d_inode->i_cdev, struct henry_drv, cdev);

	dev_info(drv->dev, "henry_drv_read\n");
	return 0;
}

static ssize_t henry_write(struct file *file,
	const char __user *buf, size_t size, loff_t *offset)
{
	struct henry_drv *drv =
		container_of(file->f_dentry->d_inode->i_cdev, struct henry_drv, cdev);

	dev_info(drv->dev, "henry_drv_write\n");
	return 0;
}

static const struct file_operations g_henry_fops = {
	.open = henry_open,
	.release = henry_close,

	.read = henry_read,
	.write = henry_write,
	
};

static int henry_drv_probe(struct see_client *clnt)
{
	int ret = 0;
	struct henry_drv *drv = NULL;

	drv = kzalloc(sizeof(struct henry_drv),
			GFP_KERNEL);
	if (!drv)
		return -ENOMEM;

	ret = alloc_chrdev_region(&drv->dev_num, 0, 1, HENRY_DEV);
	if (ret < 0)
		return ret;

	cdev_init(&drv->cdev, &g_henry_fops);
	drv->cdev.owner = THIS_MODULE;
	ret = cdev_add(&drv->cdev, drv->dev_num, 1);
	if (ret < 0)
		goto out;

	drv->dev_class = class_create(THIS_MODULE, HENRY_DEV);
	if (IS_ERR_OR_NULL(drv->dev_class)) {
		ret = PTR_ERR(drv->dev_class);
		goto out;
	}

	drv->dev = device_create(drv->dev_class, NULL, drv->dev_num, drv,
						HENRY_DEV);
	if (IS_ERR_OR_NULL(drv->dev)) {
		ret = PTR_ERR(drv->dev);
		goto out;
	}

	dev_set_drvdata(&clnt->dev, drv);
	dev_info(&clnt->dev, "HENRY driver probed\n");

out:
	if (unlikely(ret)) {
		if (drv->dev_class) {
			/* device_create */
			device_destroy(drv->dev_class, drv->dev_num);
			/* cdev_add */
			cdev_del(&drv->cdev);
			/* class_create */
			class_destroy(drv->dev_class);
			/* alloc_chrdev_region */
			unregister_chrdev_region(drv->dev_num, 1);
		}
		kfree(drv);
	}

	return ret;
}

int henry_drv_remove(struct see_client *clnt)
{
	struct henry_drv *drv = dev_get_drvdata(&clnt->dev);

	unregister_chrdev_region(drv->dev_num, 1);
	device_destroy(drv->dev_class, drv->dev_num);
	cdev_del(&drv->cdev);
	class_destroy(drv->dev_class);
	kfree(drv);

	dev_info(&clnt->dev, "HENRY driver removed\n");

	return 0;
}

static const struct of_device_id see_henry_matchtbl[] = {
	{ .compatible = "alitech,henry" },
	{ }
};

static struct see_client_driver henry_drv = {
	.probe	= henry_drv_probe,
	.remove	= henry_drv_remove,
	.driver	= {
        .name = "HENRY",
		.of_match_table	= see_henry_matchtbl,
	},
	.see_min_version = SEE_MIN_VERSION(0, 1, 1, 0),
};

module_see_client_driver(henry_drv);

MODULE_AUTHOR("ALi (Zhuhai) Corporation");
MODULE_DESCRIPTION("HENRY Driver for testing");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.1.0");
