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

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/idr.h>
#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/splice.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/pagemap.h>

#include <ca_dsc.h>
#include "ca_dsc_priv.h"
#include "ca_dsc_sbm.h"
#include "ca_dsc_rpc.h"

static int ca_dio_fake_rw_check(struct ca_dsc_session *s,
	struct ca_dio_write_read *pdio)
{
	if (!s)
		return -EBADF;

	if (!s->fmt_flag)
		return -EPERM;

	if (!pdio || !pdio->input || !pdio->output || !pdio->length)
		return -EINVAL;

	if (pdio->crypt_mode != CA_ENCRYPT &&
		pdio->crypt_mode != CA_DECRYPT) {
		dev_dbg(s->dsc->dev, "invalid crypt_mode[%d]\n",
			pdio->crypt_mode);
		return -EINVAL;
	}

	if (s->crypt_mode != pdio->crypt_mode) {
		/*change the session crypto_mode here ?*/
		s->crypt_mode = pdio->crypt_mode;
	}

	return 0;
}

static int ca_dio_fake_rw(struct file *file,
	struct ca_dio_write_read *pdio)
{
	int ret;
	struct ca_dsc_session *s = file->private_data;
	int blocking = (file->f_flags & O_NONBLOCK) ? 0 : 1;
	int wr_pos = 0;
	int rd_pos = 0;
	int m = 0, n = 0;

	ret = ca_dio_fake_rw_check(s, pdio);
	if (ret)
		return ret;

	if (blocking)
		file->f_flags |= O_NONBLOCK;

	dev_dbg(s->dsc->dev, "input[%p],output[%p],len[%d]\n",
		pdio->input, pdio->output, pdio->length);

	while (wr_pos < pdio->length) {
		m = file->f_op->write(file, &pdio->input[wr_pos],
			pdio->length - wr_pos, NULL);
		if (m < 0) {
			if (m == -EAGAIN)
				continue;

			dev_dbg(s->dsc->dev, "%s:%d: %d\n", __func__,
				__LINE__, m);

			return m;
		}
		wr_pos += m;

		n = 0;
		while (n < m) {
			int len = m - n;
			int k;

			k = file->f_op->read(file, &pdio->output[rd_pos],
					len, NULL);

			if (k < 0) {
				if (k == -EAGAIN)
					continue;

				dev_dbg(s->dsc->dev, "%s:%d: %d\n", __func__,
					__LINE__, k);

				return k;
			}

			rd_pos += k;
			n += k;

			dev_dbg(s->dsc->dev, "rd_pos:%d,wr_pos:%d, n:%d, m:%d\n",
				rd_pos, wr_pos, n, m);
		}
	}

	if (blocking)
		file->f_flags &= ~O_NONBLOCK;

	return 0;
}

long ca_dsc_ioctl_legacy(struct file *file, unsigned int cmd,
			 unsigned long args)
{
	int ret = 0;
	struct ca_dsc_session *s = file->private_data;

	if (!s)
		return -EBADF;

	switch (DSC_IO_CMD(cmd)) {
	case DSC_IO_CMD(CA_DIO_WRITE_READ): {
		struct ca_dio_write_read dio;
		memset(&dio, 0, sizeof(struct ca_dio_write_read));
		ret = ali_dsc_umemcpy(&dio, (void __user *)args,
			sizeof(struct ca_dio_write_read));
		if (0 != ret) {
			dev_dbg(s->dsc->dev, "%s\n", __func__);
			goto exit;
		}

		ret = ca_dio_fake_rw(file, &dio);
		if (ret < 0)
			goto exit;

		break;
	}

	default:
		ret = -ENOIOCTLCMD;
	}

exit:
	return ret;
}
