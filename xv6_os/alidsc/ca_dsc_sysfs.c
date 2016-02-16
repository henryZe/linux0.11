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

#include <linux/highmem.h>
#include "ca_dsc_sysfs.h"

static ssize_t sysfs_store_mode(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct ca_dsc_dev *dsc = dev_get_drvdata(dev);
	long mode;
	if (kstrtol(buf, 10, &mode))
		return -EINVAL;

	mutex_lock(&dsc->mutex);
	dsc->mode = (__u32)mode;
	mutex_unlock(&dsc->mutex);
	return count;
}

static ssize_t sysfs_show_mode(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct ca_dsc_dev *dsc = dev_get_drvdata(dev);
	ssize_t count = 0;

	mutex_lock(&dsc->mutex);
	count += sprintf(buf, "mode %d\n", dsc->mode);
	mutex_unlock(&dsc->mutex);
	return count;
}

static ssize_t att_store_info(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	return count;
}

static ssize_t att_show_info(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct ca_dsc_dev *dsc = NULL;
	ssize_t count = 0;

	dsc = dev_get_drvdata(dev);
	mutex_lock(&dsc->mutex);

	count += sprintf(buf, "Total session: %d\n", dsc->num_inst);

	mutex_unlock(&dsc->mutex);
	return count;
}

static ssize_t att_show_debug_mode(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct ca_dsc_dev *dsc = NULL;
	ssize_t count = 0;

	dsc = dev_get_drvdata(dev);
	mutex_lock(&dsc->mutex);

	count += sprintf(buf, "debug_mode: %d\n", dsc->debug_mode);

	mutex_unlock(&dsc->mutex);
	return count;
}

static ssize_t att_store_debug_mode(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct ca_dsc_dev *dsc = dev_get_drvdata(dev);
	int debug_mode;
	if (kstrtoint(buf, 10, &debug_mode))
		return -EINVAL;

	mutex_lock(&dsc->mutex);
	dsc->debug_mode = (debug_mode & 0x01);
	mutex_unlock(&dsc->mutex);
	return count;
}

#ifdef CONFIG_DEBUG_FS
static ssize_t att_show_not_gothrough_hw(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct ca_dsc_dev *dsc = NULL;
	ssize_t count = 0;

	dsc = dev_get_drvdata(dev);
	mutex_lock(&dsc->mutex);

	count += sprintf(buf, "not_gothrough_hw: %d\n", dsc->not_gothrough_hw);

	mutex_unlock(&dsc->mutex);
	return count;
}

static ssize_t att_store_not_gothrough_hw(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct ca_dsc_dev *dsc = dev_get_drvdata(dev);
	int not_gothrough_hw;
	if (kstrtoint(buf, 10, &not_gothrough_hw))
		return -EINVAL;

	mutex_lock(&dsc->mutex);
	dsc->not_gothrough_hw = (not_gothrough_hw & 0x01);
	mutex_unlock(&dsc->mutex);
	return count;
}

static DEVICE_ATTR(not_gothrough_hw, 0666,
	att_show_not_gothrough_hw, att_store_not_gothrough_hw);
#endif

static DEVICE_ATTR(mode, 0660,
	sysfs_show_mode, sysfs_store_mode);
static DEVICE_ATTR(info, 0666,
	att_show_info, att_store_info);
static DEVICE_ATTR(debug_mode, 0666,
	att_show_debug_mode, att_store_debug_mode);

static const struct attribute *sysfs_attrs[] = {
	&dev_attr_mode.attr,
	&dev_attr_info.attr,
	&dev_attr_debug_mode.attr,
#ifdef CONFIG_DEBUG_FS
	&dev_attr_not_gothrough_hw.attr,
#endif
	NULL,
};

int ca_dsc_sysfs_create(struct ca_dsc_dev *dsc)
{
	int ret = sysfs_create_files(&dsc->dev->kobj, sysfs_attrs);
	if (ret)
		dev_err(dsc->dev, "sysfs create failed\n");

	return ret;
}

void ca_dsc_sysfs_remove(struct ca_dsc_dev *dsc)
{
	sysfs_remove_files(&dsc->dev->kobj, sysfs_attrs);
}

