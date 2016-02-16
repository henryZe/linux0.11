#ifndef _ALI_HENRY_PRIV_H
#define _ALI_HENRY_PRIV_H

#include <linux/cdev.h>

#define HENRY_DEV "henry"

struct henry_drv {
	dev_t dev_num;
	struct cdev cdev;
	struct class *dev_class;
	struct device *dev;

	struct dentry *debugfs_dir;	
};


#endif

