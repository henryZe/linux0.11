#include "ali_henry_drv_sys.h"

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
	struct henry_drv *drv = dev_get_drvdata(dev);
	ssize_t count = 0;

	mutex_lock(&drv->mutex);
	count += sprintf(buf, "debug_mode: %d\n", drv->debug_mode);
	mutex_unlock(&drv->mutex);

	return count;
}

static ssize_t att_store_debug_mode(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct henry_drv *drv = dev_get_drvdata(dev);
	int debug_mode;

	if (kstrtoint(buf, 10, &debug_mode))
		return -EINVAL;

	mutex_lock(&drv->mutex);
	drv->debug_mode = (debug_mode & 0x01);
	mutex_unlock(&drv->mutex);

	return count;
}

static DEVICE_ATTR(info, 0666, att_show_info, att_store_info);
static DEVICE_ATTR(debug_mode, 0666, att_show_debug_mode, att_store_debug_mode);

static const struct attribute *sysfs_attrs[] = {
	&dev_attr_info.attr,
	&dev_attr_debug_mode.attr,
	NULL,
};

int henry_sysfs_create(struct henry_drv *drv)
{
	int ret = sysfs_create_files(&drv->dev->kobj, sysfs_attrs);
	if (ret)
		dev_err(drv->dev, "sysfs create failed\n");

	return ret;
}

void henry_sysfs_remove(struct henry_drv *drv)
{
	sysfs_remove_files(&drv->dev->kobj, sysfs_attrs);
}
