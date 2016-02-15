/*
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


#include <linux/highmem.h>
#include "ali_sha.h"

static ssize_t att_store_info(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	return count;
}
static ssize_t att_show_info(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct ali_sha_dev *psha = NULL;
	ssize_t count = 0;

	psha = dev_get_drvdata(dev);
	mutex_lock(&psha->mutex);

	count += sprintf(buf, "total session: %d\n", psha->num_inst);

	mutex_unlock(&psha->mutex);
	return count;
}

static DEVICE_ATTR(info, 0666,
	att_show_info, att_store_info);

static const struct attribute *sysfs_attrs[] = {
	&dev_attr_info.attr,
	NULL,
};

int ca_sha_sysfs_create(struct ali_sha_dev *psha)
{
	int ret = sysfs_create_files(&psha->dev->kobj, sysfs_attrs);
	if (ret)
		dev_err(psha->dev, "sysfs create failed\n");

	return ret;
}

void ca_sha_sysfs_remove(struct ali_sha_dev *psha)
{
	sysfs_remove_files(&psha->dev->kobj, sysfs_attrs);
}

