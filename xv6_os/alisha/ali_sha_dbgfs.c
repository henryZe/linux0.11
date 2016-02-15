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

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#endif

#include "ali_sha.h"
#include "ali_sha_dbgfs.h"

#define SHA_DBG_CHOICE_BAISC (0)

static int choice = SHA_DBG_CHOICE_BAISC;

static int ca_sha_show_basic(struct seq_file *f,
	struct ali_sha_session *s)
{
	seq_puts(f, "@@--BASIC INFO--@@:\n");
	seq_printf(f, "%12s: %d\n", "session_id", s->id);

	return 0;
}

static int ca_sha_show_status(struct seq_file *f, void *p)
{
	struct ali_sha_session *s = f->private;

	if (!s)
		return -ENODEV;

	switch (choice) {
	case SHA_DBG_CHOICE_BAISC:
		ca_sha_show_basic(f, s);
	break;

	default:
		break;
	}

	return 0;
}

static int ca_sha_debugfs_open(struct inode *i, struct file *f)
{
	return single_open(f, ca_sha_show_status, i->i_private);
}

static const struct file_operations ca_sha_status_ops = {
	.open = ca_sha_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

void ca_sha_dbgfs_create(struct ali_sha_dev *psha)
{
	psha->debugfs_dir = debugfs_create_dir("ca_sha", NULL);
	if (!psha->debugfs_dir || IS_ERR(psha->debugfs_dir))
		dev_err(psha->dev, "debugfs create dir failed\n");
}

void ca_sha_dbgfs_remove(struct ali_sha_dev *psha)
{
	debugfs_remove(psha->debugfs_dir);
}

int ca_sha_dbgfs_add_session(struct ali_sha_session *s)
{
	char name[128];
	struct ali_sha_dev *psha;

	if (!s)
		return -1;
	psha = s->psha;
	if (!psha || !psha->debugfs_dir)
		return -1;

	sprintf(name, "session@%d", s->id);
	s->session_dir = debugfs_create_dir(name, psha->debugfs_dir);
	if (!s->session_dir || IS_ERR(s->session_dir)) {
		dev_err(psha->dev, "create session dir failed\n");
		return -1;
	}

	sprintf(name, "dbg");
	s->debugfs = debugfs_create_file(name, S_IFREG | S_IRUGO,
		s->session_dir, (void *)s, &ca_sha_status_ops);
	if (!s->debugfs || IS_ERR(s->debugfs))
		dev_err(psha->dev, "debugfs create file failed\n");

	sprintf(name, "choice");
	s->choice = debugfs_create_u32(name, S_IFREG | S_IRUGO | S_IWUGO,
		s->session_dir, &choice);
	if (!s->choice || IS_ERR(s->choice))
		dev_err(psha->dev, "debugfs create choice failed\n");

	return 0;
}

int ca_sha_dbgfs_del_session(struct ali_sha_session *s)
{
	if (!s)
		return -1;

	debugfs_remove(s->debugfs);
	debugfs_remove(s->choice);
	debugfs_remove(s->session_dir);

	return 0;
}

