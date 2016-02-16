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
#include <linux/poll.h>
#include <linux/of.h>
#include <linux/cdev.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/semaphore.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/list.h>
#include <ali_cache.h>
#include <linux/clk-provider.h>

#include <ca_dsc.h>
#include <ca_otp_dts.h>
#include "ca_dsc_priv.h"
#include "ca_dsc_ioctl.h"
#include "ca_dsc_sysfs.h"
#include "ca_dsc_dbgfs.h"
#include "ca_dsc_sbm.h"
#include "ca_dsc_rpc.h"


#define NO_CHRDEVS (1)
#define FIRST_MIN (0)

/*#define DSC_SI_ERRNO*/

static int ca_dsc_open(struct inode *inode, struct file *file)
{
	struct ca_dsc_dev *dsc = container_of(inode->i_cdev,
			struct ca_dsc_dev, cdev);
	struct ca_dsc_session *session;
	int ret;

	mutex_lock(&dsc->mutex);

	if (dsc->num_inst >= 8) {
		ret = -EBUSY;
		goto open_fail;
	}

	session = devm_kzalloc(dsc->dev,
		sizeof(struct ca_dsc_session), GFP_KERNEL);
	if (!session) {
		ret = -ENOMEM;
		goto open_fail;
	}

	dsc->num_inst++;

	/*external init*/
	session->sub_module = DSC_INVALID_SUB_MODULE;

	/*internal resource init*/
	memset(session, 0, sizeof(struct ca_dsc_session));
	session->dma_mode = DSC_INVALID_DMA_MODE;
	session->stream_id = ALI_INVALID_CRYPTO_STREAM_ID;
	session->sub_dev_id = ALI_INVALID_DSC_SUB_DEV_ID;
	session->tsc_flag = DSC_INVALID_TSC_FLAG;
	session->sub_dev_see_hdl = 0;

	INIT_LIST_HEAD(&session->key_list);
	ida_init(&session->key_ida);

	/* flags*/
	mutex_init(&session->rd_mutex);
	mutex_init(&session->wr_mutex);

	session->dsc = dsc;
	file->private_data = (void *)session;

	/* init sbm */
	ret = open_sbm(session);
	if (ret)
		goto open_sbm_failed;

	if (ca_dsc_se_register(session) != 0) {
		dev_dbg(dsc->dev, "dsc_se: failed register se\n");
		goto se_register_failed;
	}

	session->id = ida_simple_get(&dsc->sess_ida,
		0, 0, GFP_KERNEL);

	mutex_unlock(&dsc->mutex);
	ca_dsc_dbgfs_add_session(session);

	return 0;

se_register_failed:
	close_sbm(session);
open_sbm_failed:
	mutex_destroy(&session->rd_mutex);
	mutex_destroy(&session->wr_mutex);
	ida_destroy(&session->key_ida);
open_fail:
	mutex_unlock(&dsc->mutex);
	return ret;
}

static int ca_dsc_release(struct inode *inode, struct file *file)
{
	struct ca_dsc_session *session = file->private_data;
	struct ca_dsc_dev *dsc;
	struct ali_inst_key *key, *_key;

	if (!session)
		return -EBADF;

	/*Do not release resource in debug*/
	if (session->dsc->debug_mode)
		return 0;

	dsc = session->dsc;

	mutex_lock(&dsc->mutex);

	dsc->num_inst--;

	ca_dsc_se_unregister(session);

	/* release sbm */
	close_sbm(session);

	/*clean the key_list*/
	list_for_each_entry_safe(key, _key, &session->key_list, key_node) {
		dsc_delete_crypto_stream(session, key->key_handle);
		inst_key_delete(key);
	}

	ida_destroy(&session->key_ida);

	dsc_release_internel_resource(session);
	mutex_destroy(&session->rd_mutex);
	mutex_destroy(&session->wr_mutex);

	file->private_data = NULL;

	ida_simple_remove(&dsc->sess_ida, session->id);

#ifdef CONFIG_DEBUG_FS
	ca_dsc_dbgfs_del_session(session);
#endif

	devm_kfree(dsc->dev, session);

	mutex_unlock(&dsc->mutex);
	return 0;
}

static unsigned int ca_dsc_poll(struct file *file, poll_table *wait)
{
	struct ca_dsc_session *s = file->private_data;
	struct ca_dsc_se *engine;
	int ret;
	int w_mask = 0, r_mask = 0;

	if (!s)
		return -EBADF;

	engine = &s->engine;

	poll_wait(file, &engine->OutWq, wait);
	poll_wait(file, &engine->InWq, wait);

	ret = ca_dsc_se_wr_avail(engine);
	if (ret)
		w_mask |= POLLOUT | POLLWRNORM;

	if (!w_mask)
		schedule_delayed_work(&engine->wq_w_checker, 10);

	ret = ca_dsc_se_buffer_done(engine);
	if (ret)
		r_mask |= POLLIN | POLLRDNORM;
	if (!r_mask)
		schedule_delayed_work(&engine->wq_r_checker, 10);

	return w_mask | r_mask;
}

ssize_t ca_dsc_read(struct file *file, char __user *buf,
	size_t count, loff_t *f_pos)
{
	struct ca_dsc_session *s = file->private_data;
	struct ca_dsc_se *e;
	struct ca_dsc_se_buffer *sbuf;
	int ret = 0, rd_bytes = 0;
	struct page *page;
	char *vaddr;
	int blocking = (file->f_flags & O_NONBLOCK) ? 0 : 1;
	int bsize;

	if (!s)
		return -EBADF;

	e = &s->engine;

	dev_dbg(e->session->dsc->dev,
			"read: session#%d read request: %zd bytes\n",
			e->session->id, count);

	mutex_lock(&s->rd_mutex);

	while (count > 0) {
		/*check data available or not*/
		ret = ca_dsc_se_buffer_done(e);
		if (blocking) {
			while (!ret) {
				if (schedule_timeout_interruptible(
					DSC_SCHE_DELAY)) {
					ret = -ERESTARTSYS;
					goto out;
				}
				ret = ca_dsc_se_buffer_done(e);
			}
		} else if (!ret) {
			ret = -EAGAIN;
			break;
		}

		if (e->rd_tmpbuf.bfill) {
			bsize = min(count, e->rd_tmpbuf.bfill);

			if (copy_to_user(buf + rd_bytes,
					e->rd_tmpbuf.buf + e->rd_tmpbuf.boffset,
					bsize) < 0) {
				ret = -EFAULT;
				goto out;
			}

			rd_bytes += bsize;
			count -= bsize;

			e->rd_tmpbuf.bfill -= bsize;
			e->rd_tmpbuf.boffset += bsize;
			if (e->rd_tmpbuf.bfill == 0)
				e->rd_tmpbuf.boffset = 0;

			continue;
		}

		/* dequeue buffer */
		sbuf = ca_dsc_se_dequeue_buffer(e);
		if (!sbuf)
			continue;
		page = (e->in_place) ? sbuf->page : sbuf->opage;
		vaddr = kmap(page) + sbuf->o_off;

		/* fill userland buffer */
		bsize = min(count, (unsigned int)sbuf->len);
		if (copy_to_user(buf + rd_bytes, vaddr, bsize)) {
			ret = -EFAULT;
			kunmap(page);
			goto out;
		}

		/* resever the left data */
		if (bsize < sbuf->len) {
			memcpy(
				e->rd_tmpbuf.buf + e->rd_tmpbuf.boffset,
				vaddr + bsize,
				sbuf->len - bsize
			);

			e->rd_tmpbuf.bfill += (sbuf->len - bsize);
		}

		kunmap(page);

		/* increment read bytes */
		rd_bytes += bsize;
		/* decrement remaining bytes to read */
		count -= bsize;

		/* release buffer */
		e->ops->put_buffer(sbuf);
		blocking = 0;
	};

out:
	dev_dbg(e->session->dsc->dev,
		"read: session#%d read returned %d bytes\n",
		e->session->id, rd_bytes);

	if (rd_bytes) {
		e->read_bytes += rd_bytes;
		ret = rd_bytes;
	}

	mutex_unlock(&s->rd_mutex);
	return ret;
}

ssize_t ca_dsc_write(struct file *file, const char __user *buf,
	size_t count, loff_t *pos)
{
	struct ca_dsc_session *s = file->private_data;
	struct ca_dsc_se *e = NULL;
	ssize_t wr_bytes = 0;
	int ret = 0;
	int blocking = (file->f_flags & O_NONBLOCK) ? 0 : 1;

	if (!s)
		return -EBADF;

	if (!s->fmt_flag)
		return -EPERM;

	if (!count || (s->format != CA_FORMAT_RAW &&
		count % s->pkt_size))
		return -EINVAL;

	e = &s->engine;

	dev_dbg(e->session->dsc->dev,
			"write: session#%d write request: %zd bytes\n",
			e->session->id, count);

	mutex_lock(&s->wr_mutex);

	while (count > 0) {
		struct ca_dsc_se_buffer *sbuf = NULL;
		int bsize;

		ret = ca_dsc_se_wr_avail(e);
		if (blocking) {
			while (!ret) {
				if (schedule_timeout_interruptible(
					DSC_SCHE_DELAY)) {
					ret = -ERESTARTSYS;
					goto out;
				}

				ret = ca_dsc_se_wr_avail(e);
			}
		} else if (!ret) {
			ret = -EAGAIN;
			break;
		}

		if (count + e->wr_tmpbuf.bfill < s->pkt_size) {
			copy_from_user(
				e->wr_tmpbuf.buf + e->wr_tmpbuf.bfill,
				buf + wr_bytes,
				count
			);

			e->wr_tmpbuf.bfill += count;
			wr_bytes += count;
			count -= count;
			continue;
		}

		/* get free buffer */
		sbuf = e->ops->get_buffer(e, NULL);
		if (!sbuf)
			break;

		/* consume the accumuated buffer first*/
		if (e->wr_tmpbuf.bfill) {
			memcpy(kmap(sbuf->page), e->wr_tmpbuf.buf,
				e->wr_tmpbuf.bfill);

			kunmap(sbuf->page);
			sbuf->len += e->wr_tmpbuf.bfill;
			sbuf->size -= e->wr_tmpbuf.bfill;

			memset(e->wr_tmpbuf.buf, 0, PAGE_SIZE);
			e->wr_tmpbuf.bfill = 0;
		}

		/* adjust block size */
		bsize = (count >= sbuf->size) ? sbuf->size : count;
		/* round down block size if needed in TS format */
		if (sbuf->type && ((bsize + sbuf->len) % sbuf->type) &&
			(bsize + sbuf->len) > sbuf->type) {
			bsize -= (bsize + sbuf->len) % sbuf->type;
		}

		if (copy_from_user(kmap(sbuf->page) + sbuf->len,
				buf + wr_bytes, bsize)) {
			e->ops->put_buffer(sbuf);
			ret = -EFAULT;
			kunmap(sbuf->page);
			goto out;
		}

		/* set off && len */
		sbuf->len += bsize;
		kunmap(sbuf->page);

		/* queue_work */
		if (ca_dsc_se_enqueue_buffer(sbuf) < 0) {
			e->ops->put_buffer(sbuf);
			break;
		}

		wr_bytes += bsize;
		count -= bsize;
		blocking = 0;
	};

	/*enqueue the rest data that not enough packet_size*/
	if (e->wr_tmpbuf.bfill) {
		struct ca_dsc_se_buffer *sbuf = NULL;

		sbuf = e->ops->get_buffer(e, NULL);
		if (!sbuf)
			return -ENOMEM;

		memcpy(kmap(sbuf->page), e->wr_tmpbuf.buf,
			e->wr_tmpbuf.bfill);

		kunmap(sbuf->page);
		e->ops->set_buffer(sbuf, 0, e->wr_tmpbuf.bfill);

		/* queue_work */
		if (ca_dsc_se_enqueue_buffer(sbuf) < 0) {
			e->ops->put_buffer(sbuf);
			return -EFAULT;
		}

		memset(e->wr_tmpbuf.buf, 0, PAGE_SIZE);
		e->wr_tmpbuf.bfill = 0;
	}

out:
	dev_dbg(e->session->dsc->dev,
		"write: session#%d insert end of block mark (bsize: %zd)\n",
		e->session->id, wr_bytes);

	if (wr_bytes) {
		e->write_bytes += wr_bytes;
		ret = wr_bytes;
	}

	mutex_unlock(&s->wr_mutex);
	return ret;
}

static int ca_dsc_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct ca_dsc_se *engine = NULL;
	struct ca_dsc_se_buffer *sbuf = NULL;
	struct ca_dsc_session *s = vma->vm_private_data;
	int ret = 0;
	long bl;
	char *a;
	struct page *page = NULL;

	engine = &s->engine;

	while (!ret) {
		ret = wait_event_interruptible_timeout(
			engine->OutWq, ca_dsc_se_buffer_done(engine), 20);
		if (ret == -ERESTARTSYS) {
			dev_info(engine->session->dsc->dev, "VM_FAULT_NOPAGE\n");
			return VM_FAULT_NOPAGE;
		}
	}

	mutex_lock(&s->rd_mutex);

	if (ret < 0) {
#ifdef DSC_SI_ERRNO
		/*si_errno filed added to propagate from page fault to sigbus*/
		vma->si_errno = -EIO;
#endif
		pr_err("%s failed %d\n", __func__, ret);
		mutex_unlock(&s->rd_mutex);
		return VM_FAULT_SIGBUS;
	}

	/* dequeue buffer */
	sbuf = ca_dsc_se_dequeue_buffer(engine);

	mutex_unlock(&s->rd_mutex);

	if (!sbuf) {
#ifdef DSC_SI_ERRNO
		vma->si_errno = -EIO;
#endif
		return VM_FAULT_SIGBUS;
	}

	dev_dbg(engine->session->dsc->dev,
		"dsc_vm_fault: buffer#%d release %d bytes for session#%d\n",
		sbuf->id, sbuf->len, engine->session->id);

	engine->mmap_bytes += sbuf->len;

	page = sbuf->opage;

	a = kmap(page);
	/* if last 32 bits of page are unused then they are used for length.
	 */
	bl = PAGE_SIZE - sbuf->len - sizeof(u32);
	if (bl >= 0) {
		u32 *p = (u32 *)(a + PAGE_SIZE - sizeof(u32));
		*p = sbuf->len; /* length */
	}
	/* avoid leaking of kernel memory to user land */
	if (bl > 0)
		memset(a + sbuf->len, 0, bl);
	else if (bl < 0)
		memset(a + sbuf->len, 0, PAGE_SIZE - sbuf->len);

	kunmap(page);

	/* remain current page then release the internal sbuf */
	get_page(page);
	engine->ops->put_buffer(sbuf);

	vmf->page = page;

	return 0;
}

static const struct vm_operations_struct ca_dsc_vm_ops = {
	.fault = ca_dsc_vm_fault,
};

static int ca_dsc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct ca_dsc_session *s = file->private_data;

	if (!s)
		return -EBADF;

	if (s->engine.in_place)
		return -EPERM;

	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_NONLINEAR;
	vma->vm_private_data = s;
	vma->vm_ops = &ca_dsc_vm_ops;

	return 0;
}

static void ca_dsc_release_spd(struct splice_pipe_desc *s, unsigned int i)
{
	return;
}

static const struct pipe_buf_operations ca_dsc_pipe_buf_ops = {
	.can_merge = 0,
	.map = generic_pipe_buf_map,
	.unmap = generic_pipe_buf_unmap,
	.confirm = generic_pipe_buf_confirm,
	.release = generic_pipe_buf_release,
	.steal = generic_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

static ssize_t ca_dsc_splice_read(struct file *file, loff_t *ppos,
				  struct pipe_inode_info *pipe, size_t len,
				  unsigned int flags)
{
	struct ca_dsc_session *s = file->private_data;
	struct ca_dsc_se *engine;
	struct ca_dsc_se_buffer *sbuf;
	struct ca_dsc_se_buffer *sbufs[PIPE_DEF_BUFFERS];
	struct page *pages[PIPE_DEF_BUFFERS];
	struct partial_page partial[PIPE_DEF_BUFFERS];
	struct splice_pipe_desc spd = {
		.pages = pages,
		.partial = partial,
		.nr_pages_max = PIPE_DEF_BUFFERS,
		.flags = flags,
		.ops = &ca_dsc_pipe_buf_ops,
		.spd_release = ca_dsc_release_spd,
	};
	int count = len, i = 0, j;
	int ret = 0, rd_bytes = 0;
	int blocking = (file->f_flags & O_NONBLOCK) ? 0 : 1;

	if (!s)
		return -EBADF;

	if (s->engine.in_place)
		return -EPERM;

	dev_dbg(s->dsc->dev,
			"splice_read: session#%d read request: %zd bytes\n",
			s->id, count);

	mutex_lock(&s->rd_mutex);

	engine = &s->engine;
	if (splice_grow_spd(pipe, &spd)) {
		ret = -ENOMEM;
		goto out;
	}

	while (count && (i < spd.nr_pages_max)) {
		/*check data available or not*/
		ret = ca_dsc_se_buffer_done(engine);
		if (blocking) {
			while (!ret) {
				if (schedule_timeout_interruptible(
					DSC_SCHE_DELAY)) {
					ret = -ERESTARTSYS;
					goto out;
				}
				ret = ca_dsc_se_buffer_done(engine);
			}
		} else if (!ret) {
			ret = -EAGAIN;
			break;
		}

		/* dequeue buffer */
		sbuf = ca_dsc_se_dequeue_buffer(engine);
		if (!sbuf)
			continue;

		/* fill spd */
		spd.partial[i].len = sbuf->len;
		spd.partial[i].offset = sbuf->o_off;
		spd.pages[i] = sbuf->opage;

		sbufs[i] = sbuf;
		get_page(spd.pages[i]);

		/* increment read bytes */
		rd_bytes += sbuf->len;
		/* decrement remaining bytes to read */
		count -= sbuf->len;
		i++;

		blocking = 0;
	}

out:
	if (i) {
		spd.nr_pages = i;
		ret = splice_to_pipe(pipe, &spd);

		if (ret)
			engine->splice_read_bytes += ret;

		for (j = 0; j < (i - spd.nr_pages); j++)
			engine->ops->put_buffer(sbufs[j]);

		for (j = i - 1; j >= (i - spd.nr_pages); j--) {
			engine->ops->push_buffer(sbufs[j]);
			put_page(spd.pages[j]);
		}
	}

	splice_shrink_spd(&spd);
	mutex_unlock(&s->rd_mutex);
	return ret;
}

static int dsc_from_pipe(struct pipe_inode_info *pipe,
	struct pipe_buffer *buf, struct splice_desc *sd)
{
	struct file *filp = sd->u.file;
	struct ca_dsc_session *s = NULL;
	struct ca_dsc_se *e = NULL;
	struct ca_dsc_se_buffer *sbuf = NULL;
	int len;

	if (unlikely(!filp))
		return -EBADF;

	s = (struct ca_dsc_session *)filp->private_data;
	if (unlikely(!s))
		return -EBADF;

	if (unlikely(!buf->page))
		return -EPIPE;

	/*printk("%s - pipe->nrbufs[%d], pipe->curbuf[%d]: "
		"buf->len[%d], sd->len[%d], sd->total[%d]\n",
		__func__,
		pipe->nrbufs, pipe->curbuf,
		buf->len, sd->len, sd->total_len);*/

	e = &s->engine;

	if (!e->tmpbuf.page) {
		int o_fill, o_size;

		o_size = min(buf->len, sd->len);
		o_fill = o_size - (o_size % s->pkt_size);

		if (o_fill < o_size) {
			e->tmpbuf.pgfill = 0;
			e->tmpbuf.page = alloc_page(GFP_KERNEL | __GFP_DMA);
			if (!e->tmpbuf.page)
				return -ENOMEM;
		}

		len = 0;

		if (o_fill >= s->pkt_size) {
			len = o_fill;

			sbuf = e->ops->get_buffer(e, buf->page);
			if (!sbuf)
				return -ENOMEM;

			sbuf->external = 1;

			e->ops->set_buffer(sbuf, buf->offset, len);

			/* queue_work */
			if (ca_dsc_se_enqueue_buffer(sbuf) < 0) {
				e->ops->put_buffer(sbuf);
				return -EFAULT;
			}
		}
	} else {
		int i_size, o_size = 0;

		i_size = s->pkt_size - e->tmpbuf.pgfill;
		o_size = min(buf->len, sd->len);
		o_size = min(i_size, o_size);

		memcpy(
			kmap(e->tmpbuf.page) + e->tmpbuf.pgfill,
			kmap(buf->page) + buf->offset,
			o_size
		);

		kunmap(e->tmpbuf.page);
		kunmap(buf->page);

		e->tmpbuf.pgfill += o_size;
		len = o_size;

		if (e->tmpbuf.pgfill == s->pkt_size) {
			sbuf = e->ops->get_buffer(e, e->tmpbuf.page);
			if (!sbuf)
				return -ENOMEM;

			e->ops->set_buffer(sbuf, 0, s->pkt_size);

			/* queue_work */
			if (ca_dsc_se_enqueue_buffer(sbuf) < 0) {
				e->ops->put_buffer(sbuf);
				return -EFAULT;
			}

			put_page(e->tmpbuf.page);
			e->tmpbuf.page = NULL;
			e->tmpbuf.pgfill = 0;
		}
	}

	return len;
}

static ssize_t ca_dsc_splice_write(struct pipe_inode_info *pipe,
				   struct file *filp, loff_t *ppos,
				   size_t count, unsigned int flags)
{
	struct ca_dsc_session *s = filp->private_data;
	ssize_t ret;
	int blocking = (filp->f_flags & O_NONBLOCK) ? 0 : 1;
	struct ca_dsc_se_buffer *sbuf = NULL;
	struct ca_dsc_se *e = NULL;

	if (!s)
		return -EBADF;

	if (!s->fmt_flag)
		return -EPERM;

	if (!count || (s->format != CA_FORMAT_RAW &&
		count % s->pkt_size))
		return -EINVAL;

	if (s->engine.in_place)
		return -EPERM;

	dev_dbg(s->dsc->dev,
		"splice_write: session#%d write request: %zd bytes\n",
		s->id, count);

	mutex_lock(&s->wr_mutex);

	ret = ca_dsc_se_wr_avail(&s->engine);
	if (blocking) {
		while (!ret) {
			if (schedule_timeout_interruptible(DSC_SCHE_DELAY)) {
				ret = -ERESTARTSYS;
				goto out;
			}
			ret = ca_dsc_se_wr_avail(&s->engine);
		}
	} else if (!ret) {
		ret = -EAGAIN;
		goto out;
	}

	ret = splice_from_pipe(pipe, filp, ppos, count, flags, dsc_from_pipe);
	if (ret > 0) {
		s->engine.splice_write_bytes += ret;
		*ppos += ret;
	}

	/*enqueue the rest data that not enough packet_size*/
	e = &s->engine;
	if (e->tmpbuf.page && e->tmpbuf.pgfill) {
		sbuf = e->ops->get_buffer(e, e->tmpbuf.page);
		if (!sbuf)
			return -ENOMEM;

		e->ops->set_buffer(sbuf, 0, e->tmpbuf.pgfill);

		/* queue_work */
		if (ca_dsc_se_enqueue_buffer(sbuf) < 0) {
			e->ops->put_buffer(sbuf);
			goto out;
		}

		put_page(e->tmpbuf.page);
		e->tmpbuf.page = NULL;
		e->tmpbuf.pgfill = 0;
	}

	dev_dbg(s->dsc->dev,
		"splice_write: session#%d dsc_from_pipe %d bytes\n",
		s->id, ret);

out:
	mutex_unlock(&s->wr_mutex);
	return ret;
}

static const struct file_operations ca_dsc_fops = {
	.owner		= THIS_MODULE,
	.open		= ca_dsc_open,
	.read		= ca_dsc_read,
	.write		= ca_dsc_write,
	.poll			= ca_dsc_poll,
	.mmap		= ca_dsc_mmap,
	.splice_read	= ca_dsc_splice_read,
	.splice_write	= ca_dsc_splice_write,
	.release		= ca_dsc_release,
	.unlocked_ioctl	= ca_dsc_ioctl,
};

static int ca_dsc_probe_dt(struct see_client *clnt,
	struct ca_dsc_dev *dsc)
{
	struct device_node *dn = clnt->dev.of_node;
	const char *clk_name = NULL;
	struct clk *clk;
	int ret;

	dev_info(&clnt->dev, "parsing DSC@%d\n", clnt->service_id);

	/*clock*/
	of_property_read_string(dn, "clock-names", &clk_name);
	clk = devm_clk_get(&clnt->dev, clk_name);
	if (IS_ERR(clk)) {
		dev_dbg(&clnt->dev, "get clk error\n");
		return -EINVAL;
	}

	clk_prepare(clk);
	clk_enable(clk);

	/*dev index*/
	ret = of_property_read_u32(dn, (const char *)"dev-index",
		&dsc->dev_index);
	if (ret) {
		dev_dbg(&clnt->dev, "get dev-index error\n");
		return ret;
	}

	return 0;
}

static int ca_dsc_probe(struct see_client *clnt)
{
	struct ca_dsc_dev *dsc;
	int ret = -1;
	int idx;
	char basename[16];
	u32 dev_index = 0;

	dev_info(&clnt->dev, "probing DSC@%d\n", clnt->service_id);

	dsc = devm_kzalloc(&clnt->dev, sizeof(struct ca_dsc_dev), GFP_KERNEL);
	if (!dsc)
		return -ENOMEM;
	dsc->clnt = clnt;

	if (of_have_populated_dt()) {
		ret = ca_dsc_probe_dt(clnt, dsc);
		if (ret < 0) {
			dev_dbg(&clnt->dev, "Failed to parse DT\n");
			devm_kfree(&clnt->dev, dsc);
			return ret;
		}
	}

	sprintf(basename, "%s%d", CA_DSC_BASENAME, dev_index);

	/*
	* Character device initialisation
	*/
	ret = alloc_chrdev_region(&dsc->devt, FIRST_MIN,
		NO_CHRDEVS, basename);
	if (ret < 0)
		goto chrdev_alloc_fail;

	cdev_init(&dsc->cdev, &ca_dsc_fops);
	ret = cdev_add(&dsc->cdev, dsc->devt, 1);
	if (ret < 0)
		goto cdev_add_fail;

	dsc->class = class_create(THIS_MODULE, CA_DSC_DRVNAME);
	if (IS_ERR(dsc->class)) {
		ret = PTR_ERR(dsc->dev);
		goto class_create_fail;
	}
	dsc->dev = device_create(dsc->class, &clnt->dev, dsc->devt,
		dsc, basename);
	if (IS_ERR(dsc->dev)) {
		ret = PTR_ERR(dsc->dev);
		goto device_create_fail;
	}

	mutex_init(&dsc->mutex);

	/*open see dsc module*/
	ali_m36_dsc_see_init(dsc);

	/* Init devices' handler at see*/
	dsc->see_dsc_id = hld_dev_get_by_id(HLD_DEV_TYPE_DSC, 0);
	if (NULL == dsc->see_dsc_id) {
		dev_dbg(&clnt->dev, "Get DSC handler error!\n");
		goto sysfs_fail;
	}

	for (idx = 0; idx < VIRTUAL_DEV_NUM; idx++) {
		dsc->see_aes_id[idx] = hld_dev_get_by_id(HLD_DEV_TYPE_AES, idx);
		dsc->see_des_id[idx] = hld_dev_get_by_id(HLD_DEV_TYPE_DES, idx);
		dsc->see_csa_id[idx] = hld_dev_get_by_id(HLD_DEV_TYPE_CSA, idx);
		dsc->see_sha_id[idx] = hld_dev_get_by_id(HLD_DEV_TYPE_SHA, idx);
		if (NULL == dsc->see_aes_id[idx] ||
			NULL == dsc->see_des_id[idx] ||
			NULL == dsc->see_csa_id[idx] ||
			NULL == dsc->see_sha_id[idx]) {
			dev_dbg(&clnt->dev, "Get Sub device's handler error!\n");
			goto sysfs_fail;
		}
	}

	dsc->dsc_key =  dma_alloc_coherent(dsc->dev, ALI_DSC_KERNEL_KEY_SIZE,
		&dsc->key_dma_hdl, GFP_KERNEL | GFP_DMA);
	if (!dsc->dsc_key)
		return -ENOMEM;

	ret = ca_dsc_sysfs_create(dsc);
	if (ret)
		goto sysfs_fail;

	ret = ca_dsc_wq_create();
	if (ret)
		goto sysfs_fail;

	ca_dsc_dbgfs_create(dsc);
	dev_set_drvdata(&clnt->dev, dsc);
	dev_set_drvdata(dsc->dev, dsc);
	ida_init(&dsc->sess_ida);

	dsc->debug_mode = 0;
#ifdef CONFIG_DEBUG_FS
	dsc->not_gothrough_hw = 0;
#endif
	dev_info(&clnt->dev, "driver probed\n");
	return 0;

	ca_dsc_dbgfs_remove(dsc);
	ca_dsc_sysfs_remove(dsc);
sysfs_fail:
	device_destroy(dsc->class, dsc->devt);
device_create_fail:
	class_destroy(dsc->class);
class_create_fail:
	cdev_del(&dsc->cdev);
cdev_add_fail:
	unregister_chrdev_region(dsc->devt, NO_CHRDEVS);
chrdev_alloc_fail:
	devm_kfree(&clnt->dev, dsc);
	return ret;
}

static int ca_dsc_remove(struct see_client *clnt)
{
	struct device_node *dn = clnt->dev.of_node;
	const char *clk_name = NULL;
	struct clk *clk;
	struct ca_dsc_dev *dsc = dev_get_drvdata(&clnt->dev);
	if (!dsc)
		return -ENODEV;

	dev_info(&clnt->dev, "removing DSC SEE driver @%d\n",
		clnt->service_id);

	of_property_read_string(dn, "clock-names", &clk_name);
	clk = devm_clk_get(&clnt->dev, clk_name);

	if (IS_ERR(clk)) {
		dev_dbg(&clnt->dev, "get clk error\n");
	} else {
		clk_disable(clk);
		clk_unprepare(clk);
	}

	ca_dsc_dbgfs_remove(dsc);
	ca_dsc_sysfs_remove(dsc);

	dev_set_drvdata(&clnt->dev, NULL);
	dev_set_drvdata(dsc->dev, NULL);

	dma_free_coherent(dsc->dev, ALI_DSC_KERNEL_KEY_SIZE,
		dsc->dsc_key, dsc->key_dma_hdl);

	mutex_destroy(&dsc->mutex);

	device_destroy(dsc->class, dsc->devt);
	class_destroy(dsc->class);
	cdev_del(&dsc->cdev);
	unregister_chrdev_region(dsc->devt, NO_CHRDEVS);

	ca_dsc_wq_delete();
	ida_destroy(&dsc->sess_ida);

	devm_kfree(&clnt->dev, dsc);
	dev_info(&clnt->dev, "driver removed\n");
	return 0;
}

static const struct of_device_id see_dsc_matchtbl[] = {
	{ .compatible = "alitech,dsc" },
	{ }
};

static struct see_client_driver dsc_drv = {
	.probe	= ca_dsc_probe,
	.remove	= ca_dsc_remove,
	.driver	= {
		.name		= "DSC",
		.of_match_table	= see_dsc_matchtbl,
	},
	.see_min_version = SEE_MIN_VERSION(0, 1, 1, 0),
};

module_see_client_driver(dsc_drv);

MODULE_AUTHOR("ALi Corporation");
MODULE_DESCRIPTION("ALi DeScramble Core");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.1.0");

