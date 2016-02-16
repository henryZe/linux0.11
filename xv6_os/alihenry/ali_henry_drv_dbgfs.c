#include <linux/device.h>
#include <linux/debugfs.h>

#include "ali_henry_priv.h"

static int henry_show_status(struct seq_file *f, void *p)
{
	struct ca_dsc_session *s = f->private;

	if (!s)
		return -ENODEV;

	switch (choice) {
	case CA_DBG_PRINT_BAISC_STATUS:
		ca_dsc_show_basic(f, s);
	break;

	case CA_DBG_PRINT_GET_BUF_LIST:
		ca_dsc_show_get_buffer(f, s);
	break;

	default:
		break;
	}

	return 0;
}

static int henry_debugfs_open(struct inode *i, struct file *f)
{
	return single_open(f, henry_show_status, i->i_private);
}

static const struct file_operations sha_status_ops = {
	.open = sha_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

void henry_dbgfs_create(struct henry_drv *drv)
{
	drv->debugfs_dir = debugfs_create_dir(HENRY_DEV, NULL);

	if (!drv->debugfs_dir)
		dev_err(drv->dev, "debugfs create dentry failed\n");
}

void henry_dbgfs_remove(struct henry_drv *drv)
{
	if (drv && drv->debugfs_dir)
		debugfs_remove_recursive(drv->debugfs_dir);
}

