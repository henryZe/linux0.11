/*
 * DeScrambler Core driver
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

#include <linux/highmem.h>
#include "ca_dsc_priv.h"
#include "ca_dsc_dbgfs.h"
#include "../ali_kl_fd_framework/ca_kl_fd_dispatch.h"


#define CA_DBG_PRINT_BAISC_STATUS			(0)
#define CA_DBG_PRINT_GET_BUF_LIST			(1)
#define CA_DBG_PRINT_PUT_BUF_LIST			(2)
#define CA_DBG_PRINT_BUF_IN_OUT_NOT_EQUAL	(3)
#define CA_DBG_DUMP_SINGLE_BUF				(4)
#define CA_DBG_DEQUEUE_MANUAL				(5)
#define CA_DBG_DUMP_SYNC_ERR				(6)

static int choice = CA_DBG_PRINT_BAISC_STATUS;
static int buffer_id;

static void ca_dsc_show_format(struct seq_file *f,
	struct ca_dsc_session *s)
{
	char cfmt[][32] = {
		[CA_FORMAT_RAW] = "raw",
		[CA_FORMAT_TS188] = "ts188",
		[CA_FORMAT_TS188_LTSID] = "ts188-ltsid",
		[CA_FORMAT_TS200] = "ts200",
	};

	if (s->format < CA_FORMAT_RAW || s->format > CA_FORMAT_TS200)
		seq_printf(f, "%12s: Invalid[%d]\n", "format", s->format);
	else
		seq_printf(f, "%12s: %s\n", "format", cfmt[s->format]);
}

static void ca_dsc_show_algo(struct seq_file *f,
	struct ca_dsc_session *s)
{
	char calgo[][32] = {
		[CA_ALGO_AES] = "AES",
		[CA_ALGO_DES] = "DES",
		[CA_ALGO_TDES] = "TDES",
		[CA_ALGO_CSA1] = "CSA1",
		[CA_ALGO_CSA2] = "CSA2",
		[CA_ALGO_CSA3] = "CSA3",
	};

	if (s->algo < CA_ALGO_AES || s->algo > CA_ALGO_CSA3)
		seq_printf(f, "%12s: Invalid[%d]\n", "algo", s->algo);
	else
		seq_printf(f, "%12s: %s\n", "algo", calgo[s->algo]);
}

static void ca_dsc_show_crypto(struct seq_file *f,
	struct ca_dsc_session *s)
{
	if (s->crypt_mode == CA_ENCRYPT)
		seq_printf(f, "%12s: ENCRYPT\n", "crypto");
	else if (s->crypt_mode == CA_DECRYPT)
		seq_printf(f, "%12s: DECRYPT\n", "crypto");
	else
		seq_printf(f, "%12s: Invalid[%d]\n", "crypto", s->crypt_mode);
}

static void ca_dsc_show_chaining(struct seq_file *f,
	struct ca_dsc_session *s)
{
	char cmode[][32] = {
		[CA_MODE_ECB] = "ECB",
		[CA_MODE_CBC] = "CBC",
		[CA_MODE_OFB] = "OFB",
		[CA_MODE_CFB] = "CFB",
		[CA_MODE_CTR] = "CTR",
		[CA_MODE_CTR8] = "CTR8",
	};

	if (s->chaining_mode < CA_MODE_ECB ||
		s->chaining_mode > CA_MODE_CTR8)
		seq_printf(f, "%12s: Invalid[%d]\n", "mode", s->chaining_mode);
	else
		seq_printf(f, "%12s: %s\n", "mode", cmode[s->chaining_mode]);
}

static void ca_dsc_show_residue(struct seq_file *f,
	struct ca_dsc_session *s)
{
	char cresidue[][32] = {
		[CA_RESIDUE_CLEAR] = "Clear",
		[CA_RESIDUE_AS_ATSC] = "AS-ATSC",
		[CA_RESIDUE_HW_CTS] = "HW-CTS",
		[CA_RESIDUE_CTR_HDL] = "CTR-HDL",
	};

	if (s->residue_mode < CA_RESIDUE_CLEAR ||
		s->residue_mode > CA_RESIDUE_CTR_HDL)
		seq_printf(f, "%12s: Invalid[%d]\n",
			"residue", s->residue_mode);
	else
		seq_printf(f, "%12s: %s\n", "residue",
			cresidue[s->residue_mode]);
}

static void ca_dsc_show_parity(struct seq_file *f,
	struct ca_dsc_session *s)
{
	char cparity[][32] = {
		[CA_PARITY_AUTO] = "Auto",
		[CA_PARITY_ODD] = "Odd",
		[CA_PARITY_EVEN] = "Even",
	};

	if (s->parity < CA_PARITY_AUTO || s->parity > CA_PARITY_EVEN)
		seq_printf(f, "%12s: Invalid[%d]\n", "parity", s->parity);
	else
		seq_printf(f, "%12s: %s\n", "parity", cparity[s->parity]);
}

static void ca_dsc_show_cork(struct seq_file *f,
	struct ca_dsc_session *s)
{
	char ccork[][32] = {
		[CA_SET_UNCORK] = "uncork",
		[CA_SET_CORK] = "cork",
	};

	if (s->opt != CA_SET_CORK && s->opt != CA_SET_UNCORK)
		seq_printf(f, "%12s: Invalid[%d]\n", "opt", s->opt);
	else
		seq_printf(f, "%12s: %s\n", "opt", ccork[s->opt]);
}


static void ca_dsc_show_key(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ali_inst_key *key;
	struct dsc_pid *ppid;
	int idx;

	char ckeytype[][32] = {
		[DSC_INST_CLEAR_KEY - DSC_INST_CLEAR_KEY] = "CLEAR",
		[DSC_INST_KL_KEY - DSC_INST_CLEAR_KEY] = "KL",
		[DSC_INST_OTP_KEY - DSC_INST_CLEAR_KEY] = "OTP",
	};

	if (list_empty(&s->key_list)) {
		seq_puts(f, "\tnone\n");
		return;
	}

	list_for_each_entry(key, &s->key_list, key_node) {
		seq_printf(f, "%5s@0x%x:\n", "KEY", key->key_id);
		seq_printf(f, "%20s: %x\n", "handle", key->key_handle);
		seq_printf(f, "%20s: %s\n", "type",
			ckeytype[key->key_type - DSC_INST_CLEAR_KEY]);

		if (key->cell)
			seq_printf(f, "%20s: fd[%d]:kl_sel[%d],pos[0x%x],num[%d]\n",
				   "kl_fd", key->kl_fd,
				   key->cell->kl_sel, key->cell->pos, key->cell->num);
		else
			seq_printf(f, "%20s: None\n", "kl_fd");

		seq_printf(f, "%20s: %d\n", "no_even", key->no_even);
		seq_printf(f, "%20s: %d\n", "no_odd", key->no_odd);
		seq_printf(f, "%20s: %d\n", "even_locate", key->even_locate);
		seq_printf(f, "%20s: %d\n", "odd_locate", key->odd_locate);
		seq_printf(f, "%20s: %d\n", "otp_key", key->otp_key_select);

		/*pid*/
		seq_printf(f, "%20s: ", "[ltsid]pid|tsc");
		list_for_each_entry(ppid, &key->pid_list, pid_node)
			seq_printf(f, "[%02x]%04x|%02x ", ppid->ltsid,
				   ppid->pid, ppid->tsc);
		seq_puts(f, "\n");

		/*key*/
		seq_printf(f, "%20s: %d\n", "size", key->key_size);
		seq_printf(f, "%20s: ", "even_key");
		for (idx = 0; idx < key->key_size; idx++)
			seq_printf(f, "%02x ", key->key_even[idx]);
		seq_puts(f, "\n");

		seq_printf(f, "%20s: ", "odd_key");
		for (idx = 0; idx < key->key_size; idx++)
			seq_printf(f, "%02x ", key->key_odd[idx]);
		seq_puts(f, "\n");

		/*iv*/
		seq_printf(f, "%20s: ", "even_iv");
		for (idx = 0; idx < CA_IV_SIZE_MAX; idx++)
			seq_printf(f, "%02x ", key->iv_even[idx]);
		seq_puts(f, "\n");

		seq_printf(f, "%20s: ", "odd_iv");
		for (idx = 0; idx < CA_IV_SIZE_MAX; idx++)
			seq_printf(f, "%02x ", key->iv_odd[idx]);
		seq_puts(f, "\n");
	}
}

static void ca_dsc_show_queue_buffer(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ca_dsc_se *engine = &s->engine;
	struct ca_dsc_se_buffer *sbuf;

	mutex_lock(&engine->queue_lock);

	seq_printf(f, "\tBuffer Totally Enqueued: %d, Bytes: %lld\n",
		engine->total_enqueued_buffers,
		engine->total_enqueued_bytes);
	seq_printf(f, "\tBuffer Totally Dequeued: %d, Bytes: %lld\n",
		engine->total_dequeued_buffers,
		engine->total_dequeued_bytes);
	seq_printf(f, "\tBuffer Remain In Queue: %d, bytes: %lld\n",
		engine->queued_buffers,
		engine->queued_bytes);

	seq_printf(f, "\tBuffer Totally Read Bytes: %lld\n",
		engine->read_bytes);
	seq_printf(f, "\tBuffer Totally Write Bytes: %lld\n",
		engine->write_bytes);
	seq_printf(f, "\tBuffer Remain buffer Bytes: %d\n",
		engine->wr_tmpbuf.bfill);
	seq_printf(f, "\tBuffer Totally MMap Bytes: %lld\n",
		engine->mmap_bytes);
	seq_printf(f, "\tBuffer Totally SpliceRead Bytes: %lld\n",
		engine->splice_read_bytes);
	seq_printf(f, "\tBuffer Totally SpliceWrite Bytes: %lld\n",
		engine->splice_write_bytes);
	seq_printf(f, "\tBuffer Remain Page[%p] Bytes: %d\n",
		engine->tmpbuf.page,
		engine->tmpbuf.pgfill);

	if (!s->dsc->debug_mode)
		goto out;

	if (list_empty(&engine->buf_queue)) {
		seq_puts(f, "\tno buffer in the queue\n");
		goto out;
	}

	seq_puts(f, "\t------------------------------------------------\n");
	seq_puts(f, "\tID\tlen\tInPage[dma_addr]|off"
		"\tOutPage[dma_addr]|off\tDONE SBMQ Queued RQ Ex\n");

	list_for_each_entry(sbuf, &engine->buf_queue, node) {

		seq_printf(f, "\t%d\t%d\t%p[%08x]|%d\t%p[%08x]|%d\t%d %d %d %d %d\n",
			sbuf->id, sbuf->len,
			sbuf->page, sbuf->dma_hdl, sbuf->i_off,
			sbuf->opage, sbuf->odma_hdl, sbuf->o_off,
			sbuf->done,
			!query_sbm_entry(engine->session, &sbuf->entry),
			sbuf->queued, sbuf->rq, sbuf->external);
	}

out:
	mutex_unlock(&engine->queue_lock);
}

static void ca_dsc_dump_single_buffer(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ca_dsc_se *engine = &s->engine;
	struct ca_dsc_se_buffer *sbuf;
	unsigned char *addr1, *addr2;
	int found = 0;
	unsigned int idx;

	if (!s->dsc->debug_mode)
		return;

	mutex_lock(&engine->queue_lock);

	seq_printf(f, "@@--DUMP Buffer[%d] --@@:\n", buffer_id);
	if (list_empty(&engine->buf_get)) {
		seq_puts(f, "\tno buffer in the buf_get list\n");
		goto out;
	}

	seq_puts(f, "\t------------------------------------------------\n");
	seq_puts(f, "\tID\tlen\tInPage[dma_addr]|off"
		"\tOutPage[dma_addr]|off\tDONE\tSBMQ\tQueued\tRQ\n");
	list_for_each_entry(sbuf, &engine->buf_get, get_node) {
		if (sbuf->id == buffer_id) {
			found = 1;
			break;
		}
	}

	if (!found) {
		seq_printf(f, "Cannot find buffer id[%d]\n", buffer_id);
		goto out;
	}

	seq_printf(f, "\t%d\t%d\t%p[%08x]|%d\t%p[%08x]|%d\t%d\t%d\t%d\t%d\n",
		sbuf->id, sbuf->len,
		sbuf->page, sbuf->dma_hdl, sbuf->i_off,
		sbuf->opage, sbuf->odma_hdl, sbuf->o_off,
		sbuf->done,
		!query_sbm_entry(engine->session, &sbuf->entry),
		sbuf->queued, sbuf->rq);

	addr1 = kmap(sbuf->page) + sbuf->i_off;
	addr2 = kmap(sbuf->opage) + sbuf->o_off;

	seq_puts(f, "InPut Data:");
	for (idx = 0; idx < sbuf->len; idx++) {
		if (idx % 16 == 0)
			seq_puts(f, "\n");
		seq_printf(f, "%02x ", addr1[idx]);
	}
	seq_puts(f, "\n");

	seq_puts(f, "\nOutPut Data:");
	for (idx = 0; idx < sbuf->len; idx++) {
		if (idx % 16 == 0)
			seq_puts(f, "\n");
		seq_printf(f, "%02x ", addr2[idx]);
	}
	seq_puts(f, "\n");

	kunmap(sbuf->page);
	kunmap(sbuf->opage);

out:
	mutex_unlock(&engine->queue_lock);
}

static void ca_dsc_dump_sync_err(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ca_dsc_se *engine = &s->engine;
	struct ca_dsc_se_buffer *sbuf;
	unsigned char *addr1, *addr2;

	if (!s->dsc->debug_mode)
		return;

	mutex_lock(&engine->queue_lock);

	seq_puts(f, "@@--SYNC BYTE ERR PAGES --@@:\n");
	if (list_empty(&engine->buf_get)) {
		seq_puts(f, "\tno buffer in the buf_get list\n");
		mutex_unlock(&engine->queue_lock);
		return;
	}

	seq_puts(f, "\t------------------------------------------------\n");
	seq_puts(f, "\tID\tlen\tInPage[dma_addr]|off"
		"\tOutPage[dma_addr]|off\tDONE SBMQ Queued RQ Ex Offset\n");
	list_for_each_entry(sbuf, &engine->buf_get, get_node) {

		int idx;
		unsigned char *psync1, *psync2;

		addr1 = kmap(sbuf->page) + sbuf->i_off;
		addr2 = kmap(sbuf->opage) + sbuf->o_off;

		for (idx = 0; idx < sbuf->len; idx += s->pkt_size) {
			psync1 = addr1 + (s->pkt_size - 188);
			psync2 = addr2 + (s->pkt_size - 188);

			if (*psync1 != 0x47 || *psync2 != 0x47) {
				seq_printf(f, "\t%d\t%d\t%p[%08x]|%d\t%p[%08x]|%d\t%d %d %d %d %d\n",
					sbuf->id, sbuf->len,
					sbuf->page, sbuf->dma_hdl, sbuf->i_off,
					sbuf->opage, sbuf->odma_hdl, sbuf->o_off,
					sbuf->done,
					!query_sbm_entry(engine->session, &sbuf->entry),
					sbuf->queued, sbuf->rq, sbuf->external);
				seq_printf(f, "No.%d packet: In[0x%02x],Out[0x%02x]\n",
					idx, *psync1, *psync2);
			}
		}

		kunmap(sbuf->page);
		kunmap(sbuf->opage);
	}

	mutex_unlock(&engine->queue_lock);
}



static void ca_dsc_check_in_out_not_equal(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ca_dsc_se *engine = &s->engine;
	struct ca_dsc_se_buffer *sbuf;
	char *addr1, *addr2;

	if (!s->dsc->debug_mode)
		return;

	mutex_lock(&engine->queue_lock);

	seq_puts(f, "@@--IN != OUT BUFFER --@@:\n");
	if (list_empty(&engine->buf_get)) {
		seq_puts(f, "\tno buffer in the buf_get list\n");
		mutex_unlock(&engine->queue_lock);
		return;
	}

	seq_puts(f, "\t------------------------------------------------\n");
	seq_puts(f, "\tID\tlen\tInPage[dma_addr]|off"
		"\tOutPage[dma_addr]|off\tDONE\tSBMQ\tQueued\tRQ\n");
	list_for_each_entry(sbuf, &engine->buf_get, get_node) {

		addr1 = kmap(sbuf->page) + sbuf->i_off;
		addr2 = kmap(sbuf->opage) + sbuf->o_off;

		if (memcmp(addr1, addr2, sbuf->len)) {
			seq_printf(f, "\t%d\t%d\t%p[%08x]|%d\t%p[%08x]|%d\t%d\t%d\t%d\t%d\n",
				sbuf->id, sbuf->len,
				sbuf->page, sbuf->dma_hdl, sbuf->i_off,
				sbuf->opage, sbuf->odma_hdl, sbuf->o_off,
				sbuf->done,
				!query_sbm_entry(engine->session, &sbuf->entry),
				sbuf->queued, sbuf->rq);
		}

		kunmap(sbuf->page);
		kunmap(sbuf->opage);
	}

	mutex_unlock(&engine->queue_lock);
}

static void ca_dsc_show_get_buffer(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ca_dsc_se *engine = &s->engine;
	struct ca_dsc_se_buffer *sbuf;

	if (!s->dsc->debug_mode)
		return;

	mutex_lock(&engine->queue_lock);

	seq_puts(f, "@@--GET BUFFER --@@:\n");
	if (list_empty(&engine->buf_get)) {
		seq_puts(f, "\tno buffer in the buf_get list\n");
		mutex_unlock(&engine->queue_lock);
		return;
	}

	seq_puts(f, "\t------------------------------------------------\n");
	seq_puts(f, "\tID\tlen\tInPage[dma_addr]|off"
		"\tOutPage[dma_addr]|off\tDONE SBMQ Queued RQ Ex Offset\n");
	list_for_each_entry(sbuf, &engine->buf_get, get_node) {
		seq_printf(f, "\t%d\t%d\t%p[%08x]|%d\t%p[%08x]|%d\t%d %d %d %d %d\n",
			sbuf->id, sbuf->len,
			sbuf->page, sbuf->dma_hdl, sbuf->i_off,
			sbuf->opage, sbuf->odma_hdl, sbuf->o_off,
			sbuf->done,
			!query_sbm_entry(engine->session, &sbuf->entry),
			sbuf->queued, sbuf->rq, sbuf->external);
	}

	mutex_unlock(&engine->queue_lock);
}

static void ca_dsc_show_put_buffer(struct seq_file *f,
	struct ca_dsc_session *s)
{
	struct ca_dsc_se *engine = &s->engine;
	struct ca_dsc_se_buffer *sbuf;

	if (!s->dsc->debug_mode)
		return;

	mutex_lock(&engine->queue_lock);

	seq_puts(f, "@@--PUT BUFFER --@@:\n");
	if (list_empty(&engine->buf_put)) {
		seq_puts(f, "\tno buffer in the buf_put list\n");
		mutex_unlock(&engine->queue_lock);
		return;
	}

	seq_puts(f, "\t------------------------------------------------\n");
	seq_puts(f, "\tID\tlen\tInPage[dma_addr]"
		"\tOutPage[dma_addr]\tDONE\tSBMQ\tQueued\tRQ\n");
	list_for_each_entry(sbuf, &engine->buf_put, put_node) {
		seq_printf(f, "\t%d\t%d\t%p[%08x]\t%p[%08x]\t%d\t%d\t%d\t%d\n",
			sbuf->id, sbuf->len, sbuf->page, sbuf->dma_hdl,
			sbuf->opage, sbuf->odma_hdl,
			sbuf->done,
			!query_sbm_entry(engine->session, &sbuf->entry),
			sbuf->queued, sbuf->rq);
	}

	mutex_unlock(&engine->queue_lock);
}

static int ca_dsc_show_basic(struct seq_file *f,
	struct ca_dsc_session *s)
{
	seq_puts(f, "choice: basic[0], get_buf[1], put_buf[2], check_not_equal[3], dump[4]\n");
	seq_puts(f, "@@--BASIC INFO--@@:\n");
	ca_dsc_show_format(f, s);
	ca_dsc_show_algo(f, s);
	ca_dsc_show_crypto(f, s);
	ca_dsc_show_chaining(f, s);
	ca_dsc_show_residue(f, s);
	ca_dsc_show_parity(f, s);
	ca_dsc_show_cork(f, s);
	seq_printf(f, "%12s: %d\n", "tsc_flag", s->tsc_flag);
	seq_printf(f, "%12s: %d\n", "ts_chaining", s->ts_chaining);
	seq_printf(f, "%12s: %d\n", "sc_mode", s->sc_mode);
	seq_printf(f, "%12s: %d\n", "streamID", s->stream_id);
	seq_printf(f, "%12s: %d\n", "subDevId", s->sub_dev_id);
	seq_printf(f, "%12s: %08x\n", "subDevHld", s->sub_dev_see_hdl);

	seq_puts(f, "@@--KEY INFO--@@:\n");
	ca_dsc_show_key(f, s);

	seq_puts(f, "@@--QUEUE BUFFER --@@:\n");
	ca_dsc_show_queue_buffer(f, s);

	return 0;
}

static int ca_dsc_show_status(struct seq_file *f, void *p)
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

	case CA_DBG_PRINT_PUT_BUF_LIST:
		ca_dsc_show_put_buffer(f, s);
	break;

	case CA_DBG_PRINT_BUF_IN_OUT_NOT_EQUAL:
		ca_dsc_check_in_out_not_equal(f, s);
	break;

	case CA_DBG_DUMP_SINGLE_BUF:
		ca_dsc_dump_single_buffer(f, s);
	break;

	case CA_DBG_DEQUEUE_MANUAL:
		s->engine.force = 1;
		ca_dsc_se_dequeue_buffer(&s->engine);
		s->engine.force = 0;
	break;

	case CA_DBG_DUMP_SYNC_ERR:
		ca_dsc_dump_sync_err(f, s);
	break;

	default:
		break;
	}

	return 0;
}

static int ca_dsc_debugfs_open(struct inode *i, struct file *f)
{
	return single_open(f, ca_dsc_show_status, i->i_private);
}

static const struct file_operations ca_dsc_status_ops = {
	.open = ca_dsc_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.owner = THIS_MODULE,
};

void ca_dsc_dbgfs_create(struct ca_dsc_dev *dsc)
{
	dsc->debugfs_dir = debugfs_create_dir("ca_dsc", NULL);
	if (!dsc->debugfs_dir || IS_ERR(dsc->debugfs_dir))
		dev_dbg(dsc->dev, "debugfs create dir failed\n");
}

void ca_dsc_dbgfs_remove(struct ca_dsc_dev *dsc)
{
	debugfs_remove(dsc->debugfs_dir);
}

int ca_dsc_dbgfs_add_session(struct ca_dsc_session *sess)
{
	char name[128];
	struct ca_dsc_dev *dsc;

	if (!sess)
		return -1;
	dsc = sess->dsc;
	if (!dsc || !dsc->debugfs_dir)
		return -1;

	sprintf(name, "session@%d", sess->id);
	sess->session_dir = debugfs_create_dir(name, dsc->debugfs_dir);
	if (!sess->session_dir || IS_ERR(sess->session_dir)) {
		dev_dbg(dsc->dev, "create session dir failed\n");
		return -1;
	}

	sprintf(name, "dbg");
	sess->debugfs = debugfs_create_file(name, S_IFREG | S_IRUGO,
		sess->session_dir, (void *)sess, &ca_dsc_status_ops);
	if (!sess->debugfs || IS_ERR(sess->debugfs))
		dev_dbg(dsc->dev, "debugfs create file failed\n");

	sprintf(name, "choice");
	sess->choice = debugfs_create_u32(name, S_IFREG | S_IRUGO | S_IWUGO,
		sess->session_dir, &choice);
	if (!sess->choice || IS_ERR(sess->choice))
		dev_dbg(dsc->dev, "debugfs create choice failed\n");

	sprintf(name, "buffer_id");
	sess->buffer_id = debugfs_create_u32(name, S_IFREG | S_IRUGO | S_IWUGO,
		sess->session_dir, &buffer_id);
	if (!sess->buffer_id || IS_ERR(sess->buffer_id))
		dev_dbg(dsc->dev, "debugfs create choice failed\n");

	return 0;
}

int ca_dsc_dbgfs_del_session(struct ca_dsc_session *sess)
{
	if (!sess)
		return -1;

	debugfs_remove(sess->debugfs);
	debugfs_remove(sess->choice);
	debugfs_remove(sess->buffer_id);

	debugfs_remove(sess->session_dir);

	return 0;
}

