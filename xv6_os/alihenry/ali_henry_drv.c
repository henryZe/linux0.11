#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include <see_bus.h>
#include "ali_henry_drv_dbgfs.h"
#include "ali_henry_priv.h"

static int henry_open
(
	struct inode *inode,
	struct file  *file
)
{
	struct henry_drv *drv =
		container_of(file->f_dentry->d_inode->i_cdev, struct henry_drv, cdev);

	

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

	sha_dbgfs_create(drv);
	
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
	
	sha_dbgfs_remove(drv);

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
