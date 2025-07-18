/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2012, 2020 by Delphix. All rights reserved.
 * Copyright (c) 2024, Rob Norris <robn@despairlabs.com>
 * Copyright (c) 2024, Klara, Inc.
 */

#include <sys/dataset_kstats.h>
#include <sys/dbuf.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_prop.h>
#include <sys/dsl_dir.h>
#include <sys/zap.h>
#include <sys/zfeature.h>
#include <sys/zil_impl.h>
#include <sys/dmu_tx.h>
#include <sys/zio.h>
#include <sys/zfs_rlock.h>
#include <sys/spa_impl.h>
#include <sys/zvol.h>
#include <sys/zvol_impl.h>
#include <cityhash.h>

#include <linux/blkdev_compat.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/workqueue.h>
#include <linux/blk-mq.h>

static void zvol_request_impl(zvol_state_t *zv, struct bio *bio,
    struct request *rq, boolean_t force_sync);

static unsigned int zvol_major = ZVOL_MAJOR;
static unsigned int zvol_request_sync = 0;
static unsigned int zvol_prefetch_bytes = (128 * 1024);
static unsigned long zvol_max_discard_blocks = 16384;

/*
 * Switch taskq at multiple of 512 MB offset. This can be set to a lower value
 * to utilize more threads for small files but may affect prefetch hits.
 */
#define	ZVOL_TASKQ_OFFSET_SHIFT 29

#ifndef HAVE_BLKDEV_GET_ERESTARTSYS
static unsigned int zvol_open_timeout_ms = 1000;
#endif

static unsigned int zvol_threads = 0;
static unsigned int zvol_blk_mq_threads = 0;
static unsigned int zvol_blk_mq_actual_threads;
static boolean_t zvol_use_blk_mq = B_FALSE;

/*
 * The maximum number of volblocksize blocks to process per thread.  Typically,
 * write heavy workloads preform better with higher values here, and read
 * heavy workloads preform better with lower values, but that's not a hard
 * and fast rule.  It's basically a knob to tune between "less overhead with
 * less parallelism" and "more overhead, but more parallelism".
 *
 * '8' was chosen as a reasonable, balanced, default based off of sequential
 * read and write tests to a zvol in an NVMe pool (with 16 CPUs).
 */
static unsigned int zvol_blk_mq_blocks_per_thread = 8;

static unsigned int zvol_num_taskqs = 0;

#ifndef	BLKDEV_DEFAULT_RQ
/* BLKDEV_MAX_RQ was renamed to BLKDEV_DEFAULT_RQ in the 5.16 kernel */
#define	BLKDEV_DEFAULT_RQ BLKDEV_MAX_RQ
#endif

/*
 * Finalize our BIO or request.
 */
static inline void
zvol_end_io(struct bio *bio, struct request *rq, int error)
{
	if (bio) {
		bio->bi_status = errno_to_bi_status(-error);
		bio_endio(bio);
	} else {
		blk_mq_end_request(rq, errno_to_bi_status(error));
	}
}

static unsigned int zvol_blk_mq_queue_depth = BLKDEV_DEFAULT_RQ;
static unsigned int zvol_actual_blk_mq_queue_depth;

struct zvol_state_os {
	struct gendisk		*zvo_disk;	/* generic disk */
	struct request_queue	*zvo_queue;	/* request queue */
	dev_t			zvo_dev;	/* device id */

	struct blk_mq_tag_set tag_set;

	/* Set from the global 'zvol_use_blk_mq' at zvol load */
	boolean_t use_blk_mq;
};

typedef struct zv_taskq {
	uint_t tqs_cnt;
	taskq_t **tqs_taskq;
} zv_taskq_t;
static zv_taskq_t zvol_taskqs;
static struct ida zvol_ida;

typedef struct zv_request_stack {
	zvol_state_t	*zv;
	struct bio	*bio;
	struct request *rq;
} zv_request_t;

typedef struct zv_work {
	struct request  *rq;
	struct work_struct work;
} zv_work_t;

typedef struct zv_request_task {
	zv_request_t zvr;
	taskq_ent_t	ent;
} zv_request_task_t;

static zv_request_task_t *
zv_request_task_create(zv_request_t zvr)
{
	zv_request_task_t *task;
	task = kmem_alloc(sizeof (zv_request_task_t), KM_SLEEP);
	taskq_init_ent(&task->ent);
	task->zvr = zvr;
	return (task);
}

static void
zv_request_task_free(zv_request_task_t *task)
{
	kmem_free(task, sizeof (*task));
}

/*
 * This is called when a new block multiqueue request comes in.  A request
 * contains one or more BIOs.
 */
static blk_status_t zvol_mq_queue_rq(struct blk_mq_hw_ctx *hctx,
    const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	zvol_state_t *zv = rq->q->queuedata;

	/* Tell the kernel that we are starting to process this request */
	blk_mq_start_request(rq);

	if (blk_rq_is_passthrough(rq)) {
		/* Skip non filesystem request */
		blk_mq_end_request(rq, BLK_STS_IOERR);
		return (BLK_STS_IOERR);
	}

	zvol_request_impl(zv, NULL, rq, 0);

	/* Acknowledge to the kernel that we got this request */
	return (BLK_STS_OK);
}

static struct blk_mq_ops zvol_blk_mq_queue_ops = {
	.queue_rq = zvol_mq_queue_rq,
};

/* Initialize our blk-mq struct */
static int zvol_blk_mq_alloc_tag_set(zvol_state_t *zv)
{
	struct zvol_state_os *zso = zv->zv_zso;

	memset(&zso->tag_set, 0, sizeof (zso->tag_set));

	/* Initialize tag set. */
	zso->tag_set.ops = &zvol_blk_mq_queue_ops;
	zso->tag_set.nr_hw_queues = zvol_blk_mq_actual_threads;
	zso->tag_set.queue_depth = zvol_actual_blk_mq_queue_depth;
	zso->tag_set.numa_node = NUMA_NO_NODE;
	zso->tag_set.cmd_size = 0;

	/*
	 * We need BLK_MQ_F_BLOCKING here since we do blocking calls in
	 * zvol_request_impl()
	 */
	zso->tag_set.flags = BLK_MQ_F_BLOCKING;

#ifdef BLK_MQ_F_SHOULD_MERGE
	/*
	 * Linux 6.14 removed BLK_MQ_F_SHOULD_MERGE and made it implicit.
	 * For older kernels, we set it.
	 */
	zso->tag_set.flags |= BLK_MQ_F_SHOULD_MERGE;
#endif

	zso->tag_set.driver_data = zv;

	return (blk_mq_alloc_tag_set(&zso->tag_set));
}

/*
 * Given a path, return TRUE if path is a ZVOL.
 */
boolean_t
zvol_os_is_zvol(const char *path)
{
	dev_t dev = 0;

	if (vdev_lookup_bdev(path, &dev) != 0)
		return (B_FALSE);

	if (MAJOR(dev) == zvol_major)
		return (B_TRUE);

	return (B_FALSE);
}

static void
zvol_write(zv_request_t *zvr)
{
	struct bio *bio = zvr->bio;
	struct request *rq = zvr->rq;
	int error = 0;
	zfs_uio_t uio;
	zvol_state_t *zv = zvr->zv;
	struct request_queue *q;
	struct gendisk *disk;
	unsigned long start_time = 0;
	boolean_t acct = B_FALSE;

	ASSERT3P(zv, !=, NULL);
	ASSERT3U(zv->zv_open_count, >, 0);
	ASSERT3P(zv->zv_zilog, !=, NULL);

	q = zv->zv_zso->zvo_queue;
	disk = zv->zv_zso->zvo_disk;

	/* bio marked as FLUSH need to flush before write */
	if (io_is_flush(bio, rq))
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	/* Some requests are just for flush and nothing else. */
	if (io_size(bio, rq) == 0) {
		rw_exit(&zv->zv_suspend_lock);
		zvol_end_io(bio, rq, 0);
		return;
	}

	zfs_uio_bvec_init(&uio, bio, rq);

	ssize_t start_resid = uio.uio_resid;

	/*
	 * With use_blk_mq, accounting is done by blk_mq_start_request()
	 * and blk_mq_end_request(), so we can skip it here.
	 */
	if (bio) {
		acct = blk_queue_io_stat(q);
		if (acct) {
			start_time = blk_generic_start_io_acct(q, disk, WRITE,
			    bio);
		}
	}

	boolean_t sync =
	    io_is_fua(bio, rq) || zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS;

	zfs_locked_range_t *lr = zfs_rangelock_enter(&zv->zv_rangelock,
	    uio.uio_loffset, uio.uio_resid, RL_WRITER);

	uint64_t volsize = zv->zv_volsize;
	while (uio.uio_resid > 0 && uio.uio_loffset < volsize) {
		uint64_t bytes = MIN(uio.uio_resid, DMU_MAX_ACCESS >> 1);
		uint64_t off = uio.uio_loffset;
		dmu_tx_t *tx = dmu_tx_create(zv->zv_objset);

		if (bytes > volsize - off)	/* don't write past the end */
			bytes = volsize - off;

		dmu_tx_hold_write_by_dnode(tx, zv->zv_dn, off, bytes);

		/* This will only fail for ENOSPC */
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			break;
		}
		error = dmu_write_uio_dnode(zv->zv_dn, &uio, bytes, tx);
		if (error == 0) {
			zvol_log_write(zv, tx, off, bytes, sync);
		}
		dmu_tx_commit(tx);

		if (error)
			break;
	}
	zfs_rangelock_exit(lr);

	int64_t nwritten = start_resid - uio.uio_resid;
	dataset_kstats_update_write_kstats(&zv->zv_kstat, nwritten);
	task_io_account_write(nwritten);

	if (sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

	rw_exit(&zv->zv_suspend_lock);

	if (bio && acct) {
		blk_generic_end_io_acct(q, disk, WRITE, bio, start_time);
	}

	zvol_end_io(bio, rq, -error);
}

static void
zvol_write_task(void *arg)
{
	zv_request_task_t *task = arg;
	zvol_write(&task->zvr);
	zv_request_task_free(task);
}

static void
zvol_discard(zv_request_t *zvr)
{
	struct bio *bio = zvr->bio;
	struct request *rq = zvr->rq;
	zvol_state_t *zv = zvr->zv;
	uint64_t start = io_offset(bio, rq);
	uint64_t size = io_size(bio, rq);
	uint64_t end = start + size;
	boolean_t sync;
	int error = 0;
	dmu_tx_t *tx;
	struct request_queue *q = zv->zv_zso->zvo_queue;
	struct gendisk *disk = zv->zv_zso->zvo_disk;
	unsigned long start_time = 0;
	boolean_t acct = B_FALSE;

	ASSERT3P(zv, !=, NULL);
	ASSERT3U(zv->zv_open_count, >, 0);
	ASSERT3P(zv->zv_zilog, !=, NULL);

	if (bio) {
		acct = blk_queue_io_stat(q);
		if (acct) {
			start_time = blk_generic_start_io_acct(q, disk, WRITE,
			    bio);
		}
	}

	sync = io_is_fua(bio, rq) || zv->zv_objset->os_sync == ZFS_SYNC_ALWAYS;

	if (end > zv->zv_volsize) {
		error = SET_ERROR(EIO);
		goto unlock;
	}

	/*
	 * Align the request to volume block boundaries when a secure erase is
	 * not required.  This will prevent dnode_free_range() from zeroing out
	 * the unaligned parts which is slow (read-modify-write) and useless
	 * since we are not freeing any space by doing so.
	 */
	if (!io_is_secure_erase(bio, rq)) {
		start = P2ROUNDUP(start, zv->zv_volblocksize);
		end = P2ALIGN_TYPED(end, zv->zv_volblocksize, uint64_t);
		size = end - start;
	}

	if (start >= end)
		goto unlock;

	zfs_locked_range_t *lr = zfs_rangelock_enter(&zv->zv_rangelock,
	    start, size, RL_WRITER);

	tx = dmu_tx_create(zv->zv_objset);
	dmu_tx_mark_netfree(tx);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error != 0) {
		dmu_tx_abort(tx);
	} else {
		zvol_log_truncate(zv, tx, start, size, B_TRUE);
		dmu_tx_commit(tx);
		error = dmu_free_long_range(zv->zv_objset,
		    ZVOL_OBJ, start, size);
	}
	zfs_rangelock_exit(lr);

	if (error == 0 && sync)
		zil_commit(zv->zv_zilog, ZVOL_OBJ);

unlock:
	rw_exit(&zv->zv_suspend_lock);

	if (bio && acct) {
		blk_generic_end_io_acct(q, disk, WRITE, bio,
		    start_time);
	}

	zvol_end_io(bio, rq, -error);
}

static void
zvol_discard_task(void *arg)
{
	zv_request_task_t *task = arg;
	zvol_discard(&task->zvr);
	zv_request_task_free(task);
}

static void
zvol_read(zv_request_t *zvr)
{
	struct bio *bio = zvr->bio;
	struct request *rq = zvr->rq;
	int error = 0;
	zfs_uio_t uio;
	boolean_t acct = B_FALSE;
	zvol_state_t *zv = zvr->zv;
	struct request_queue *q;
	struct gendisk *disk;
	unsigned long start_time = 0;

	ASSERT3P(zv, !=, NULL);
	ASSERT3U(zv->zv_open_count, >, 0);

	zfs_uio_bvec_init(&uio, bio, rq);

	q = zv->zv_zso->zvo_queue;
	disk = zv->zv_zso->zvo_disk;

	ssize_t start_resid = uio.uio_resid;

	/*
	 * When blk-mq is being used, accounting is done by
	 * blk_mq_start_request() and blk_mq_end_request().
	 */
	if (bio) {
		acct = blk_queue_io_stat(q);
		if (acct)
			start_time = blk_generic_start_io_acct(q, disk, READ,
			    bio);
	}

	zfs_locked_range_t *lr = zfs_rangelock_enter(&zv->zv_rangelock,
	    uio.uio_loffset, uio.uio_resid, RL_READER);

	uint64_t volsize = zv->zv_volsize;

	while (uio.uio_resid > 0 && uio.uio_loffset < volsize) {
		uint64_t bytes = MIN(uio.uio_resid, DMU_MAX_ACCESS >> 1);

		/* don't read past the end */
		if (bytes > volsize - uio.uio_loffset)
			bytes = volsize - uio.uio_loffset;

		error = dmu_read_uio_dnode(zv->zv_dn, &uio, bytes);
		if (error) {
			/* convert checksum errors into IO errors */
			if (error == ECKSUM)
				error = SET_ERROR(EIO);
			break;
		}
	}
	zfs_rangelock_exit(lr);

	int64_t nread = start_resid - uio.uio_resid;
	dataset_kstats_update_read_kstats(&zv->zv_kstat, nread);
	task_io_account_read(nread);

	rw_exit(&zv->zv_suspend_lock);

	if (bio && acct) {
		blk_generic_end_io_acct(q, disk, READ, bio, start_time);
	}

	zvol_end_io(bio, rq, -error);
}

static void
zvol_read_task(void *arg)
{
	zv_request_task_t *task = arg;
	zvol_read(&task->zvr);
	zv_request_task_free(task);
}


/*
 * Process a BIO or request
 *
 * Either 'bio' or 'rq' should be set depending on if we are processing a
 * bio or a request (both should not be set).
 *
 * force_sync:	Set to 0 to defer processing to a background taskq
 *			Set to 1 to process data synchronously
 */
static void
zvol_request_impl(zvol_state_t *zv, struct bio *bio, struct request *rq,
    boolean_t force_sync)
{
	fstrans_cookie_t cookie = spl_fstrans_mark();
	uint64_t offset = io_offset(bio, rq);
	uint64_t size = io_size(bio, rq);
	int rw = io_data_dir(bio, rq);

	if (unlikely(zv->zv_flags & ZVOL_REMOVING)) {
		zvol_end_io(bio, rq, -SET_ERROR(ENXIO));
		goto out;
	}

	if (zvol_request_sync)
		force_sync = 1;

	zv_request_t zvr = {
		.zv = zv,
		.bio = bio,
		.rq = rq,
	};

	if (io_has_data(bio, rq) && offset + size > zv->zv_volsize) {
		printk(KERN_INFO "%s: bad access: offset=%llu, size=%lu\n",
		    zv->zv_zso->zvo_disk->disk_name,
		    (long long unsigned)offset,
		    (long unsigned)size);

		zvol_end_io(bio, rq, -SET_ERROR(EIO));
		goto out;
	}

	zv_request_task_t *task;
	zv_taskq_t *ztqs = &zvol_taskqs;
	uint_t blk_mq_hw_queue = 0;
	uint_t tq_idx;
	uint_t taskq_hash;
	if (rq)
#ifdef HAVE_BLK_MQ_RQ_HCTX
		blk_mq_hw_queue = rq->mq_hctx->queue_num;
#else
		blk_mq_hw_queue =
		    rq->q->queue_hw_ctx[rq->q->mq_map[rq->cpu]]->queue_num;
#endif
	taskq_hash = cityhash4((uintptr_t)zv, offset >> ZVOL_TASKQ_OFFSET_SHIFT,
	    blk_mq_hw_queue, 0);
	tq_idx = taskq_hash % ztqs->tqs_cnt;

	if (rw == WRITE) {
		if (unlikely(zv->zv_flags & ZVOL_RDONLY)) {
			zvol_end_io(bio, rq, -SET_ERROR(EROFS));
			goto out;
		}

		/*
		 * Prevents the zvol from being suspended, or the ZIL being
		 * concurrently opened.  Will be released after the i/o
		 * completes.
		 */
		rw_enter(&zv->zv_suspend_lock, RW_READER);

		/*
		 * Open a ZIL if this is the first time we have written to this
		 * zvol. We protect zv->zv_zilog with zv_suspend_lock rather
		 * than zv_state_lock so that we don't need to acquire an
		 * additional lock in this path.
		 */
		if (zv->zv_zilog == NULL) {
			rw_exit(&zv->zv_suspend_lock);
			rw_enter(&zv->zv_suspend_lock, RW_WRITER);
			if (zv->zv_zilog == NULL) {
				zv->zv_zilog = zil_open(zv->zv_objset,
				    zvol_get_data, &zv->zv_kstat.dk_zil_sums);
				zv->zv_flags |= ZVOL_WRITTEN_TO;
				/* replay / destroy done in zvol_create_minor */
				VERIFY0((zv->zv_zilog->zl_header->zh_flags &
				    ZIL_REPLAY_NEEDED));
			}
			rw_downgrade(&zv->zv_suspend_lock);
		}

		/*
		 * We don't want this thread to be blocked waiting for i/o to
		 * complete, so we instead wait from a taskq callback. The
		 * i/o may be a ZIL write (via zil_commit()), or a read of an
		 * indirect block, or a read of a data block (if this is a
		 * partial-block write).  We will indicate that the i/o is
		 * complete by calling END_IO() from the taskq callback.
		 *
		 * This design allows the calling thread to continue and
		 * initiate more concurrent operations by calling
		 * zvol_request() again. There are typically only a small
		 * number of threads available to call zvol_request() (e.g.
		 * one per iSCSI target), so keeping the latency of
		 * zvol_request() low is important for performance.
		 *
		 * The zvol_request_sync module parameter allows this
		 * behavior to be altered, for performance evaluation
		 * purposes.  If the callback blocks, setting
		 * zvol_request_sync=1 will result in much worse performance.
		 *
		 * We can have up to zvol_threads concurrent i/o's being
		 * processed for all zvols on the system.  This is typically
		 * a vast improvement over the zvol_request_sync=1 behavior
		 * of one i/o at a time per zvol.  However, an even better
		 * design would be for zvol_request() to initiate the zio
		 * directly, and then be notified by the zio_done callback,
		 * which would call END_IO().  Unfortunately, the DMU/ZIL
		 * interfaces lack this functionality (they block waiting for
		 * the i/o to complete).
		 */
		if (io_is_discard(bio, rq) || io_is_secure_erase(bio, rq)) {
			if (force_sync) {
				zvol_discard(&zvr);
			} else {
				task = zv_request_task_create(zvr);
				taskq_dispatch_ent(ztqs->tqs_taskq[tq_idx],
				    zvol_discard_task, task, 0, &task->ent);
			}
		} else {
			if (force_sync) {
				zvol_write(&zvr);
			} else {
				task = zv_request_task_create(zvr);
				taskq_dispatch_ent(ztqs->tqs_taskq[tq_idx],
				    zvol_write_task, task, 0, &task->ent);
			}
		}
	} else {
		/*
		 * The SCST driver, and possibly others, may issue READ I/Os
		 * with a length of zero bytes.  These empty I/Os contain no
		 * data and require no additional handling.
		 */
		if (size == 0) {
			zvol_end_io(bio, rq, 0);
			goto out;
		}

		rw_enter(&zv->zv_suspend_lock, RW_READER);

		/* See comment in WRITE case above. */
		if (force_sync) {
			zvol_read(&zvr);
		} else {
			task = zv_request_task_create(zvr);
			taskq_dispatch_ent(ztqs->tqs_taskq[tq_idx],
			    zvol_read_task, task, 0, &task->ent);
		}
	}

out:
	spl_fstrans_unmark(cookie);
}

#ifdef HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS
#ifdef HAVE_BDEV_SUBMIT_BIO_RETURNS_VOID
static void
zvol_submit_bio(struct bio *bio)
#else
static blk_qc_t
zvol_submit_bio(struct bio *bio)
#endif
#else
static MAKE_REQUEST_FN_RET
zvol_request(struct request_queue *q, struct bio *bio)
#endif
{
#ifdef HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS
#if defined(HAVE_BIO_BDEV_DISK)
	struct request_queue *q = bio->bi_bdev->bd_disk->queue;
#else
	struct request_queue *q = bio->bi_disk->queue;
#endif
#endif
	zvol_state_t *zv = q->queuedata;

	zvol_request_impl(zv, bio, NULL, 0);
#if defined(HAVE_MAKE_REQUEST_FN_RET_QC) || \
	defined(HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS) && \
	!defined(HAVE_BDEV_SUBMIT_BIO_RETURNS_VOID)
	return (BLK_QC_T_NONE);
#endif
}

static int
#ifdef HAVE_BLK_MODE_T
zvol_open(struct gendisk *disk, blk_mode_t flag)
#else
zvol_open(struct block_device *bdev, fmode_t flag)
#endif
{
	zvol_state_t *zv;
	int error = 0;
	boolean_t drop_suspend = B_FALSE;
#ifndef HAVE_BLKDEV_GET_ERESTARTSYS
	hrtime_t timeout = MSEC2NSEC(zvol_open_timeout_ms);
	hrtime_t start = gethrtime();

retry:
#endif
	rw_enter(&zvol_state_lock, RW_READER);
	/*
	 * Obtain a copy of private_data under the zvol_state_lock to make
	 * sure that either the result of zvol free code path setting
	 * disk->private_data to NULL is observed, or zvol_os_free()
	 * is not called on this zv because of the positive zv_open_count.
	 */
#ifdef HAVE_BLK_MODE_T
	zv = disk->private_data;
#else
	zv = bdev->bd_disk->private_data;
#endif
	if (zv == NULL) {
		rw_exit(&zvol_state_lock);
		return (-SET_ERROR(ENXIO));
	}

	mutex_enter(&zv->zv_state_lock);

	if (unlikely(zv->zv_flags & ZVOL_REMOVING)) {
		mutex_exit(&zv->zv_state_lock);
		rw_exit(&zvol_state_lock);
		return (-SET_ERROR(ENXIO));
	}

	/*
	 * Make sure zvol is not suspended during first open
	 * (hold zv_suspend_lock) and respect proper lock acquisition
	 * ordering - zv_suspend_lock before zv_state_lock
	 */
	if (zv->zv_open_count == 0) {
		if (!rw_tryenter(&zv->zv_suspend_lock, RW_READER)) {
			mutex_exit(&zv->zv_state_lock);
			rw_enter(&zv->zv_suspend_lock, RW_READER);
			mutex_enter(&zv->zv_state_lock);
			/* check to see if zv_suspend_lock is needed */
			if (zv->zv_open_count != 0) {
				rw_exit(&zv->zv_suspend_lock);
			} else {
				drop_suspend = B_TRUE;
			}
		} else {
			drop_suspend = B_TRUE;
		}
	}
	rw_exit(&zvol_state_lock);

	ASSERT(MUTEX_HELD(&zv->zv_state_lock));

	if (zv->zv_open_count == 0) {
		boolean_t drop_namespace = B_FALSE;

		ASSERT(RW_READ_HELD(&zv->zv_suspend_lock));

		/*
		 * In all other call paths the spa_namespace_lock is taken
		 * before the bdev->bd_mutex lock.  However, on open(2)
		 * the __blkdev_get() function calls fops->open() with the
		 * bdev->bd_mutex lock held.  This can result in a deadlock
		 * when zvols from one pool are used as vdevs in another.
		 *
		 * To prevent a lock inversion deadlock we preemptively
		 * take the spa_namespace_lock.  Normally the lock will not
		 * be contended and this is safe because spa_open_common()
		 * handles the case where the caller already holds the
		 * spa_namespace_lock.
		 *
		 * When the lock cannot be aquired after multiple retries
		 * this must be the vdev on zvol deadlock case and we have
		 * no choice but to return an error.  For 5.12 and older
		 * kernels returning -ERESTARTSYS will result in the
		 * bdev->bd_mutex being dropped, then reacquired, and
		 * fops->open() being called again.  This process can be
		 * repeated safely until both locks are acquired.  For 5.13
		 * and newer the -ERESTARTSYS retry logic was removed from
		 * the kernel so the only option is to return the error for
		 * the caller to handle it.
		 */
		if (!mutex_owned(&spa_namespace_lock)) {
			if (!mutex_tryenter(&spa_namespace_lock)) {
				mutex_exit(&zv->zv_state_lock);
				rw_exit(&zv->zv_suspend_lock);

#ifdef HAVE_BLKDEV_GET_ERESTARTSYS
				schedule();
				return (-SET_ERROR(ERESTARTSYS));
#else
				if ((gethrtime() - start) > timeout)
					return (-SET_ERROR(ERESTARTSYS));

				schedule_timeout_interruptible(
					MSEC_TO_TICK(10));
				goto retry;
#endif
			} else {
				drop_namespace = B_TRUE;
			}
		}

		error = -zvol_first_open(zv, !(blk_mode_is_open_write(flag)));

		if (drop_namespace)
			mutex_exit(&spa_namespace_lock);
	}

	if (error == 0) {
		if ((blk_mode_is_open_write(flag)) &&
		    (zv->zv_flags & ZVOL_RDONLY)) {
			if (zv->zv_open_count == 0)
				zvol_last_close(zv);

			error = -SET_ERROR(EROFS);
		} else {
			zv->zv_open_count++;
		}
	}

	mutex_exit(&zv->zv_state_lock);
	if (drop_suspend)
		rw_exit(&zv->zv_suspend_lock);

	if (error == 0)
#ifdef HAVE_BLK_MODE_T
		disk_check_media_change(disk);
#else
		zfs_check_media_change(bdev);
#endif

	return (error);
}

static void
#ifdef HAVE_BLOCK_DEVICE_OPERATIONS_RELEASE_1ARG
zvol_release(struct gendisk *disk)
#else
zvol_release(struct gendisk *disk, fmode_t unused)
#endif
{
#if !defined(HAVE_BLOCK_DEVICE_OPERATIONS_RELEASE_1ARG)
	(void) unused;
#endif
	zvol_state_t *zv;
	boolean_t drop_suspend = B_TRUE;

	rw_enter(&zvol_state_lock, RW_READER);
	zv = disk->private_data;

	mutex_enter(&zv->zv_state_lock);
	ASSERT3U(zv->zv_open_count, >, 0);
	/*
	 * make sure zvol is not suspended during last close
	 * (hold zv_suspend_lock) and respect proper lock acquisition
	 * ordering - zv_suspend_lock before zv_state_lock
	 */
	if (zv->zv_open_count == 1) {
		if (!rw_tryenter(&zv->zv_suspend_lock, RW_READER)) {
			mutex_exit(&zv->zv_state_lock);
			rw_enter(&zv->zv_suspend_lock, RW_READER);
			mutex_enter(&zv->zv_state_lock);
			/* check to see if zv_suspend_lock is needed */
			if (zv->zv_open_count != 1) {
				rw_exit(&zv->zv_suspend_lock);
				drop_suspend = B_FALSE;
			}
		}
	} else {
		drop_suspend = B_FALSE;
	}
	rw_exit(&zvol_state_lock);

	ASSERT(MUTEX_HELD(&zv->zv_state_lock));

	zv->zv_open_count--;
	if (zv->zv_open_count == 0) {
		ASSERT(RW_READ_HELD(&zv->zv_suspend_lock));
		zvol_last_close(zv);
	}

	mutex_exit(&zv->zv_state_lock);

	if (drop_suspend)
		rw_exit(&zv->zv_suspend_lock);
}

static int
zvol_ioctl(struct block_device *bdev, fmode_t mode,
    unsigned int cmd, unsigned long arg)
{
	zvol_state_t *zv = bdev->bd_disk->private_data;
	int error = 0;

	ASSERT3U(zv->zv_open_count, >, 0);

	switch (cmd) {
	case BLKFLSBUF:
#ifdef HAVE_FSYNC_BDEV
		fsync_bdev(bdev);
#elif defined(HAVE_SYNC_BLOCKDEV)
		sync_blockdev(bdev);
#else
#error "Neither fsync_bdev() nor sync_blockdev() found"
#endif
		invalidate_bdev(bdev);
		rw_enter(&zv->zv_suspend_lock, RW_READER);

		if (!(zv->zv_flags & ZVOL_RDONLY))
			txg_wait_synced(dmu_objset_pool(zv->zv_objset), 0);

		rw_exit(&zv->zv_suspend_lock);
		break;

	case BLKZNAME:
		mutex_enter(&zv->zv_state_lock);
		error = copy_to_user((void *)arg, zv->zv_name, MAXNAMELEN);
		mutex_exit(&zv->zv_state_lock);
		break;

	default:
		error = -ENOTTY;
		break;
	}

	return (SET_ERROR(error));
}

#ifdef CONFIG_COMPAT
static int
zvol_compat_ioctl(struct block_device *bdev, fmode_t mode,
    unsigned cmd, unsigned long arg)
{
	return (zvol_ioctl(bdev, mode, cmd, arg));
}
#else
#define	zvol_compat_ioctl	NULL
#endif

static unsigned int
zvol_check_events(struct gendisk *disk, unsigned int clearing)
{
	unsigned int mask = 0;

	rw_enter(&zvol_state_lock, RW_READER);

	zvol_state_t *zv = disk->private_data;
	if (zv != NULL) {
		mutex_enter(&zv->zv_state_lock);
		mask = zv->zv_changed ? DISK_EVENT_MEDIA_CHANGE : 0;
		zv->zv_changed = 0;
		mutex_exit(&zv->zv_state_lock);
	}

	rw_exit(&zvol_state_lock);

	return (mask);
}

static int
zvol_revalidate_disk(struct gendisk *disk)
{
	rw_enter(&zvol_state_lock, RW_READER);

	zvol_state_t *zv = disk->private_data;
	if (zv != NULL) {
		mutex_enter(&zv->zv_state_lock);
		set_capacity(zv->zv_zso->zvo_disk,
		    zv->zv_volsize >> SECTOR_BITS);
		mutex_exit(&zv->zv_state_lock);
	}

	rw_exit(&zvol_state_lock);

	return (0);
}

int
zvol_os_update_volsize(zvol_state_t *zv, uint64_t volsize)
{
	struct gendisk *disk = zv->zv_zso->zvo_disk;

#if defined(HAVE_REVALIDATE_DISK_SIZE)
	revalidate_disk_size(disk, zvol_revalidate_disk(disk) == 0);
#elif defined(HAVE_REVALIDATE_DISK)
	revalidate_disk(disk);
#else
	zvol_revalidate_disk(disk);
#endif
	return (0);
}

void
zvol_os_clear_private(zvol_state_t *zv)
{
	/*
	 * Cleared while holding zvol_state_lock as a writer
	 * which will prevent zvol_open() from opening it.
	 */
	zv->zv_zso->zvo_disk->private_data = NULL;
}

/*
 * Provide a simple virtual geometry for legacy compatibility.  For devices
 * smaller than 1 MiB a small head and sector count is used to allow very
 * tiny devices.  For devices over 1 Mib a standard head and sector count
 * is used to keep the cylinders count reasonable.
 */
static int
zvol_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	zvol_state_t *zv = bdev->bd_disk->private_data;
	sector_t sectors;

	ASSERT3U(zv->zv_open_count, >, 0);

	sectors = get_capacity(zv->zv_zso->zvo_disk);

	if (sectors > 2048) {
		geo->heads = 16;
		geo->sectors = 63;
	} else {
		geo->heads = 2;
		geo->sectors = 4;
	}

	geo->start = 0;
	geo->cylinders = sectors / (geo->heads * geo->sectors);

	return (0);
}

/*
 * Why have two separate block_device_operations structs?
 *
 * Normally we'd just have one, and assign 'submit_bio' as needed.  However,
 * it's possible the user's kernel is built with CONSTIFY_PLUGIN, meaning we
 * can't just change submit_bio dynamically at runtime.  So just create two
 * separate structs to get around this.
 */
static const struct block_device_operations zvol_ops_blk_mq = {
	.open			= zvol_open,
	.release		= zvol_release,
	.ioctl			= zvol_ioctl,
	.compat_ioctl		= zvol_compat_ioctl,
	.check_events		= zvol_check_events,
#ifdef HAVE_BLOCK_DEVICE_OPERATIONS_REVALIDATE_DISK
	.revalidate_disk	= zvol_revalidate_disk,
#endif
	.getgeo			= zvol_getgeo,
	.owner			= THIS_MODULE,
};

static const struct block_device_operations zvol_ops = {
	.open			= zvol_open,
	.release		= zvol_release,
	.ioctl			= zvol_ioctl,
	.compat_ioctl		= zvol_compat_ioctl,
	.check_events		= zvol_check_events,
#ifdef HAVE_BLOCK_DEVICE_OPERATIONS_REVALIDATE_DISK
	.revalidate_disk	= zvol_revalidate_disk,
#endif
	.getgeo			= zvol_getgeo,
	.owner			= THIS_MODULE,
#ifdef HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS
	.submit_bio		= zvol_submit_bio,
#endif
};

/*
 * Since 6.9, Linux has been removing queue limit setters in favour of an
 * initial queue_limits struct applied when the device is open. Since 6.11,
 * queue_limits is being extended to allow more things to be applied when the
 * device is open. Setters are also being removed for this.
 *
 * For OpenZFS, this means that depending on kernel version, some options may
 * be set up before the device is open, and some applied to an open device
 * (queue) after the fact.
 *
 * We manage this complexity by having our own limits struct,
 * zvol_queue_limits_t, in which we carry any queue config that we're
 * interested in setting. This structure is the same on all kernels.
 *
 * These limits are then applied to the queue at device open time by the most
 * appropriate method for the kernel.
 *
 * zvol_queue_limits_convert() is used on 6.9+ (where the two-arg form of
 * blk_alloc_disk() exists). This converts our limits struct to a proper Linux
 * struct queue_limits, and passes it in. Any fields added in later kernels are
 * (obviously) not set up here.
 *
 * zvol_queue_limits_apply() is called on all kernel versions after the queue
 * is created, and applies any remaining config. Before 6.9 that will be
 * everything, via setter methods. After 6.9 that will be whatever couldn't be
 * put into struct queue_limits. (This implies that zvol_queue_limits_apply()
 * will always be a no-op on the latest kernel we support).
 */
typedef struct zvol_queue_limits {
	unsigned int	zql_max_hw_sectors;
	unsigned short	zql_max_segments;
	unsigned int	zql_max_segment_size;
	unsigned int	zql_io_opt;
	unsigned int	zql_physical_block_size;
	unsigned int	zql_max_discard_sectors;
	unsigned int	zql_discard_granularity;
} zvol_queue_limits_t;

static void
zvol_queue_limits_init(zvol_queue_limits_t *limits, zvol_state_t *zv,
    boolean_t use_blk_mq)
{
	limits->zql_max_hw_sectors = (DMU_MAX_ACCESS / 4) >> 9;

	if (use_blk_mq) {
		/*
		 * IO requests can be really big (1MB).  When an IO request
		 * comes in, it is passed off to zvol_read() or zvol_write()
		 * in a new thread, where it is chunked up into 'volblocksize'
		 * sized pieces and processed.  So for example, if the request
		 * is a 1MB write and your volblocksize is 128k, one zvol_write
		 * thread will take that request and sequentially do ten 128k
		 * IOs.  This is due to the fact that the thread needs to lock
		 * each volblocksize sized block.  So you might be wondering:
		 * "instead of passing the whole 1MB request to one thread,
		 * why not pass ten individual 128k chunks to ten threads and
		 * process the whole write in parallel?"  The short answer is
		 * that there's a sweet spot number of chunks that balances
		 * the greater parallelism with the added overhead of more
		 * threads. The sweet spot can be different depending on if you
		 * have a read or write  heavy workload.  Writes typically want
		 * high chunk counts while reads typically want lower ones.  On
		 * a test pool with 6 NVMe drives in a 3x 2-disk mirror
		 * configuration, with volblocksize=8k, the sweet spot for good
		 * sequential reads and writes was at 8 chunks.
		 */

		/*
		 * Below we tell the kernel how big we want our requests
		 * to be.  You would think that blk_queue_io_opt() would be
		 * used to do this since it is used to "set optimal request
		 * size for the queue", but that doesn't seem to do
		 * anything - the kernel still gives you huge requests
		 * with tons of little PAGE_SIZE segments contained within it.
		 *
		 * Knowing that the kernel will just give you PAGE_SIZE segments
		 * no matter what, you can say "ok, I want PAGE_SIZE byte
		 * segments, and I want 'N' of them per request", where N is
		 * the correct number of segments for the volblocksize and
		 * number of chunks you want.
		 */
		if (zvol_blk_mq_blocks_per_thread != 0) {
			unsigned int chunks;
			chunks = MIN(zvol_blk_mq_blocks_per_thread, UINT16_MAX);

			limits->zql_max_segment_size = PAGE_SIZE;
			limits->zql_max_segments =
			    (zv->zv_volblocksize * chunks) / PAGE_SIZE;
		} else {
			/*
			 * Special case: zvol_blk_mq_blocks_per_thread = 0
			 * Max everything out.
			 */
			limits->zql_max_segments = UINT16_MAX;
			limits->zql_max_segment_size = UINT_MAX;
		}
	} else {
		limits->zql_max_segments = UINT16_MAX;
		limits->zql_max_segment_size = UINT_MAX;
	}

	limits->zql_io_opt = zv->zv_volblocksize;

	limits->zql_physical_block_size = zv->zv_volblocksize;
	limits->zql_max_discard_sectors =
	    (zvol_max_discard_blocks * zv->zv_volblocksize) >> 9;
	limits->zql_discard_granularity = zv->zv_volblocksize;
}

#ifdef HAVE_BLK_ALLOC_DISK_2ARG
static void
zvol_queue_limits_convert(zvol_queue_limits_t *limits,
    struct queue_limits *qlimits)
{
	memset(qlimits, 0, sizeof (struct queue_limits));
	qlimits->max_hw_sectors = limits->zql_max_hw_sectors;
	qlimits->max_segments = limits->zql_max_segments;
	qlimits->max_segment_size = limits->zql_max_segment_size;
	qlimits->io_opt = limits->zql_io_opt;
	qlimits->physical_block_size = limits->zql_physical_block_size;
	qlimits->max_discard_sectors = limits->zql_max_discard_sectors;
	qlimits->max_hw_discard_sectors = limits->zql_max_discard_sectors;
	qlimits->discard_granularity = limits->zql_discard_granularity;
#ifdef HAVE_BLKDEV_QUEUE_LIMITS_FEATURES
	qlimits->features =
	    BLK_FEAT_WRITE_CACHE | BLK_FEAT_FUA | BLK_FEAT_IO_STAT;
#endif
}
#endif

static void
zvol_queue_limits_apply(zvol_queue_limits_t *limits,
    struct request_queue *queue)
{
#ifndef HAVE_BLK_ALLOC_DISK_2ARG
	blk_queue_max_hw_sectors(queue, limits->zql_max_hw_sectors);
	blk_queue_max_segments(queue, limits->zql_max_segments);
	blk_queue_max_segment_size(queue, limits->zql_max_segment_size);
	blk_queue_io_opt(queue, limits->zql_io_opt);
	blk_queue_physical_block_size(queue, limits->zql_physical_block_size);
	blk_queue_max_discard_sectors(queue, limits->zql_max_discard_sectors);
	blk_queue_discard_granularity(queue, limits->zql_discard_granularity);
#endif
#ifndef HAVE_BLKDEV_QUEUE_LIMITS_FEATURES
	blk_queue_set_write_cache(queue, B_TRUE);
	blk_queue_flag_set(QUEUE_FLAG_IO_STAT, queue);
#endif
}

static int
zvol_alloc_non_blk_mq(struct zvol_state_os *zso, zvol_queue_limits_t *limits)
{
#if defined(HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS)
#if defined(HAVE_BLK_ALLOC_DISK)
	zso->zvo_disk = blk_alloc_disk(NUMA_NO_NODE);
	if (zso->zvo_disk == NULL)
		return (1);

	zso->zvo_disk->minors = ZVOL_MINORS;
	zso->zvo_queue = zso->zvo_disk->queue;
#elif defined(HAVE_BLK_ALLOC_DISK_2ARG)
	struct queue_limits qlimits;
	zvol_queue_limits_convert(limits, &qlimits);
	struct gendisk *disk = blk_alloc_disk(&qlimits, NUMA_NO_NODE);
	if (IS_ERR(disk)) {
		zso->zvo_disk = NULL;
		return (1);
	}

	zso->zvo_disk = disk;
	zso->zvo_disk->minors = ZVOL_MINORS;
	zso->zvo_queue = zso->zvo_disk->queue;

#else
	zso->zvo_queue = blk_alloc_queue(NUMA_NO_NODE);
	if (zso->zvo_queue == NULL)
		return (1);

	zso->zvo_disk = alloc_disk(ZVOL_MINORS);
	if (zso->zvo_disk == NULL) {
		blk_cleanup_queue(zso->zvo_queue);
		return (1);
	}

	zso->zvo_disk->queue = zso->zvo_queue;
#endif /* HAVE_BLK_ALLOC_DISK */
#else
	zso->zvo_queue = blk_generic_alloc_queue(zvol_request, NUMA_NO_NODE);
	if (zso->zvo_queue == NULL)
		return (1);

	zso->zvo_disk = alloc_disk(ZVOL_MINORS);
	if (zso->zvo_disk == NULL) {
		blk_cleanup_queue(zso->zvo_queue);
		return (1);
	}

	zso->zvo_disk->queue = zso->zvo_queue;
#endif /* HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS */

	zvol_queue_limits_apply(limits, zso->zvo_queue);

	return (0);

}

static int
zvol_alloc_blk_mq(zvol_state_t *zv, zvol_queue_limits_t *limits)
{
	struct zvol_state_os *zso = zv->zv_zso;

	/* Allocate our blk-mq tag_set */
	if (zvol_blk_mq_alloc_tag_set(zv) != 0)
		return (1);

#if defined(HAVE_BLK_ALLOC_DISK)
	zso->zvo_disk = blk_mq_alloc_disk(&zso->tag_set, zv);
	if (zso->zvo_disk == NULL) {
		blk_mq_free_tag_set(&zso->tag_set);
		return (1);
	}
	zso->zvo_queue = zso->zvo_disk->queue;
	zso->zvo_disk->minors = ZVOL_MINORS;
#elif defined(HAVE_BLK_ALLOC_DISK_2ARG)
	struct queue_limits qlimits;
	zvol_queue_limits_convert(limits, &qlimits);
	struct gendisk *disk = blk_mq_alloc_disk(&zso->tag_set, &qlimits, zv);
	if (IS_ERR(disk)) {
		zso->zvo_disk = NULL;
		blk_mq_free_tag_set(&zso->tag_set);
		return (1);
	}

	zso->zvo_disk = disk;
	zso->zvo_queue = zso->zvo_disk->queue;
	zso->zvo_disk->minors = ZVOL_MINORS;
#else
	zso->zvo_disk = alloc_disk(ZVOL_MINORS);
	if (zso->zvo_disk == NULL) {
		blk_cleanup_queue(zso->zvo_queue);
		blk_mq_free_tag_set(&zso->tag_set);
		return (1);
	}
	/* Allocate queue */
	zso->zvo_queue = blk_mq_init_queue(&zso->tag_set);
	if (IS_ERR(zso->zvo_queue)) {
		blk_mq_free_tag_set(&zso->tag_set);
		return (1);
	}

	/* Our queue is now created, assign it to our disk */
	zso->zvo_disk->queue = zso->zvo_queue;
#endif

	zvol_queue_limits_apply(limits, zso->zvo_queue);

	return (0);
}

/*
 * Allocate memory for a new zvol_state_t and setup the required
 * request queue and generic disk structures for the block device.
 */
static zvol_state_t *
zvol_alloc(dev_t dev, const char *name, uint64_t volblocksize)
{
	zvol_state_t *zv;
	struct zvol_state_os *zso;
	uint64_t volmode;
	int ret;

	if (dsl_prop_get_integer(name, "volmode", &volmode, NULL) != 0)
		return (NULL);

	if (volmode == ZFS_VOLMODE_DEFAULT)
		volmode = zvol_volmode;

	if (volmode == ZFS_VOLMODE_NONE)
		return (NULL);

	zv = kmem_zalloc(sizeof (zvol_state_t), KM_SLEEP);
	zso = kmem_zalloc(sizeof (struct zvol_state_os), KM_SLEEP);
	zv->zv_zso = zso;
	zv->zv_volmode = volmode;
	zv->zv_volblocksize = volblocksize;

	list_link_init(&zv->zv_next);
	mutex_init(&zv->zv_state_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&zv->zv_removing_cv, NULL, CV_DEFAULT, NULL);

	zv->zv_zso->use_blk_mq = zvol_use_blk_mq;

	zvol_queue_limits_t limits;
	zvol_queue_limits_init(&limits, zv, zv->zv_zso->use_blk_mq);

	/*
	 * The block layer has 3 interfaces for getting BIOs:
	 *
	 * 1. blk-mq request queues (new)
	 * 2. submit_bio() (oldest)
	 * 3. regular request queues (old).
	 *
	 * Each of those interfaces has two permutations:
	 *
	 * a) We have blk_alloc_disk()/blk_mq_alloc_disk(), which allocates
	 *    both the disk and its queue (5.14 kernel or newer)
	 *
	 * b) We don't have blk_*alloc_disk(), and have to allocate the
	 *    disk and the queue separately. (5.13 kernel or older)
	 */
	if (zv->zv_zso->use_blk_mq) {
		ret = zvol_alloc_blk_mq(zv, &limits);
		if (ret != 0)
			goto out_kmem;
		zso->zvo_disk->fops = &zvol_ops_blk_mq;
	} else {
		ret = zvol_alloc_non_blk_mq(zso, &limits);
		if (ret != 0)
			goto out_kmem;
		zso->zvo_disk->fops = &zvol_ops;
	}

	/* Limit read-ahead to a single page to prevent over-prefetching. */
	blk_queue_set_read_ahead(zso->zvo_queue, 1);

	if (!zv->zv_zso->use_blk_mq) {
		/* Disable write merging in favor of the ZIO pipeline. */
		blk_queue_flag_set(QUEUE_FLAG_NOMERGES, zso->zvo_queue);
	}

	zso->zvo_queue->queuedata = zv;
	zso->zvo_dev = dev;
	zv->zv_open_count = 0;
	strlcpy(zv->zv_name, name, MAXNAMELEN);

	zfs_rangelock_init(&zv->zv_rangelock, NULL, NULL);
	rw_init(&zv->zv_suspend_lock, NULL, RW_DEFAULT, NULL);

	zso->zvo_disk->major = zvol_major;
	zso->zvo_disk->events = DISK_EVENT_MEDIA_CHANGE;

	/*
	 * Setting ZFS_VOLMODE_DEV disables partitioning on ZVOL devices.
	 * This is accomplished by limiting the number of minors for the
	 * device to one and explicitly disabling partition scanning.
	 */
	if (volmode == ZFS_VOLMODE_DEV) {
		zso->zvo_disk->minors = 1;
		zso->zvo_disk->flags &= ~GENHD_FL_EXT_DEVT;
		zso->zvo_disk->flags |= GENHD_FL_NO_PART;
	}

	zso->zvo_disk->first_minor = (dev & MINORMASK);
	zso->zvo_disk->private_data = zv;
	snprintf(zso->zvo_disk->disk_name, DISK_NAME_LEN, "%s%d",
	    ZVOL_DEV_NAME, (dev & MINORMASK));

	return (zv);

out_kmem:
	kmem_free(zso, sizeof (struct zvol_state_os));
	kmem_free(zv, sizeof (zvol_state_t));
	return (NULL);
}

/*
 * Cleanup then free a zvol_state_t which was created by zvol_alloc().
 * At this time, the structure is not opened by anyone, is taken off
 * the zvol_state_list, and has its private data set to NULL.
 * The zvol_state_lock is dropped.
 *
 * This function may take many milliseconds to complete (e.g. we've seen
 * it take over 256ms), due to the calls to "blk_cleanup_queue" and
 * "del_gendisk". Thus, consumers need to be careful to account for this
 * latency when calling this function.
 */
void
zvol_os_free(zvol_state_t *zv)
{

	ASSERT(!RW_LOCK_HELD(&zv->zv_suspend_lock));
	ASSERT(!MUTEX_HELD(&zv->zv_state_lock));
	ASSERT0(zv->zv_open_count);
	ASSERT3P(zv->zv_zso->zvo_disk->private_data, ==, NULL);

	rw_destroy(&zv->zv_suspend_lock);
	zfs_rangelock_fini(&zv->zv_rangelock);

	del_gendisk(zv->zv_zso->zvo_disk);
#if defined(HAVE_SUBMIT_BIO_IN_BLOCK_DEVICE_OPERATIONS) && \
	(defined(HAVE_BLK_ALLOC_DISK) || defined(HAVE_BLK_ALLOC_DISK_2ARG))
#if defined(HAVE_BLK_CLEANUP_DISK)
	blk_cleanup_disk(zv->zv_zso->zvo_disk);
#else
	put_disk(zv->zv_zso->zvo_disk);
#endif
#else
	blk_cleanup_queue(zv->zv_zso->zvo_queue);
	put_disk(zv->zv_zso->zvo_disk);
#endif

	if (zv->zv_zso->use_blk_mq)
		blk_mq_free_tag_set(&zv->zv_zso->tag_set);

	ida_simple_remove(&zvol_ida,
	    MINOR(zv->zv_zso->zvo_dev) >> ZVOL_MINOR_BITS);

	cv_destroy(&zv->zv_removing_cv);
	mutex_destroy(&zv->zv_state_lock);
	dataset_kstats_destroy(&zv->zv_kstat);

	kmem_free(zv->zv_zso, sizeof (struct zvol_state_os));
	kmem_free(zv, sizeof (zvol_state_t));
}

void
zvol_wait_close(zvol_state_t *zv)
{
}

struct add_disk_work {
	struct delayed_work work;
	struct gendisk *disk;
	int error;
};

static int
__zvol_os_add_disk(struct gendisk *disk)
{
	int error = 0;
#ifdef HAVE_ADD_DISK_RET
	error = add_disk(disk);
#else
	add_disk(disk);
#endif
	return (error);
}

#if defined(HAVE_BDEV_FILE_OPEN_BY_PATH)
static void
zvol_os_add_disk_work(struct work_struct *work)
{
	struct add_disk_work *add_disk_work;
	add_disk_work = container_of(work, struct add_disk_work, work.work);
	add_disk_work->error = __zvol_os_add_disk(add_disk_work->disk);
}
#endif

/*
 * SPECIAL CASE:
 *
 * This function basically calls add_disk() from a workqueue.   You may be
 * thinking: why not just call add_disk() directly?
 *
 * When you call add_disk(), the zvol appears to the world.  When this happens,
 * the kernel calls disk_scan_partitions() on the zvol, which behaves
 * differently on the 6.9+ kernels:
 *
 * - 6.8 and older kernels -
 * disk_scan_partitions()
 *	handle = bdev_open_by_dev(
 *		zvol_open()
 *	bdev_release(handle);
 *		zvol_release()
 *
 *
 * - 6.9+ kernels -
 * disk_scan_partitions()
 * 	file = bdev_file_open_by_dev()
 *		zvol_open()
 *	fput(file)
 *	< wait for return to userspace >
 *		zvol_release()
 *
 * The difference is that the bdev_release() from the 6.8 kernel is synchronous
 * while the fput() from the 6.9 kernel is async.  Or more specifically it's
 * async that has to wait until we return to userspace (since it adds the fput
 * into the caller's work queue with the TWA_RESUME flag set).  This is not the
 * behavior we want, since we want do things like create+destroy a zvol within
 * a single ZFS_IOC_CREATE ioctl, and the "create" part needs to release the
 * reference to the zvol while we're in the IOCTL, which can't wait until we
 * return to userspace.
 *
 * We can get around this since fput() has a special codepath for when it's
 * running in a kernel thread or interrupt.  In those cases, it just puts the
 * fput into the system workqueue, which we can force to run with
 * __flush_workqueue().  That is why we call add_disk() from a workqueue - so it
 * run from a kernel thread and "tricks" the fput() codepaths.
 *
 * Note that __flush_workqueue() is slowly getting deprecated.  This may be ok
 * though, since our IOCTL will spin on EBUSY waiting for the zvol release (via
 * fput) to happen, which it eventually, naturally, will from the system_wq
 * without us explicitly calling __flush_workqueue().
 */
static int
zvol_os_add_disk(struct gendisk *disk)
{
#if defined(HAVE_BDEV_FILE_OPEN_BY_PATH)	/* 6.9+ kernel */
	struct add_disk_work add_disk_work;

	INIT_DELAYED_WORK(&add_disk_work.work, zvol_os_add_disk_work);
	add_disk_work.disk = disk;
	add_disk_work.error = 0;

	/* Use *_delayed_work functions since they're not GPL'd */
	schedule_delayed_work(&add_disk_work.work, 0);
	flush_delayed_work(&add_disk_work.work);

	__flush_workqueue(system_wq);
	return (add_disk_work.error);
#else	/* <= 6.8 kernel */
	return (__zvol_os_add_disk(disk));
#endif
}

/*
 * Create a block device minor node and setup the linkage between it
 * and the specified volume.  Once this function returns the block
 * device is live and ready for use.
 */
int
zvol_os_create_minor(const char *name)
{
	zvol_state_t *zv;
	objset_t *os;
	dmu_object_info_t *doi;
	uint64_t volsize;
	uint64_t len;
	unsigned minor = 0;
	int error = 0;
	int idx;
	uint64_t hash = zvol_name_hash(name);
	bool replayed_zil = B_FALSE;

	if (zvol_inhibit_dev)
		return (0);

	idx = ida_simple_get(&zvol_ida, 0, 0, kmem_flags_convert(KM_SLEEP));
	if (idx < 0)
		return (SET_ERROR(-idx));
	minor = idx << ZVOL_MINOR_BITS;
	if (MINOR(minor) != minor) {
		/* too many partitions can cause an overflow */
		zfs_dbgmsg("zvol: create minor overflow: %s, minor %u/%u",
		    name, minor, MINOR(minor));
		ida_simple_remove(&zvol_ida, idx);
		return (SET_ERROR(EINVAL));
	}

	zv = zvol_find_by_name_hash(name, hash, RW_NONE);
	if (zv) {
		ASSERT(MUTEX_HELD(&zv->zv_state_lock));
		mutex_exit(&zv->zv_state_lock);
		ida_simple_remove(&zvol_ida, idx);
		return (SET_ERROR(EEXIST));
	}

	doi = kmem_alloc(sizeof (dmu_object_info_t), KM_SLEEP);

	error = dmu_objset_own(name, DMU_OST_ZVOL, B_TRUE, B_TRUE, FTAG, &os);
	if (error)
		goto out_doi;

	error = dmu_object_info(os, ZVOL_OBJ, doi);
	if (error)
		goto out_dmu_objset_disown;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize);
	if (error)
		goto out_dmu_objset_disown;

	zv = zvol_alloc(MKDEV(zvol_major, minor), name,
	    doi->doi_data_block_size);
	if (zv == NULL) {
		error = SET_ERROR(EAGAIN);
		goto out_dmu_objset_disown;
	}
	zv->zv_hash = hash;

	if (dmu_objset_is_snapshot(os))
		zv->zv_flags |= ZVOL_RDONLY;

	zv->zv_volsize = volsize;
	zv->zv_objset = os;

	set_capacity(zv->zv_zso->zvo_disk, zv->zv_volsize >> 9);

#ifdef QUEUE_FLAG_DISCARD
	blk_queue_flag_set(QUEUE_FLAG_DISCARD, zv->zv_zso->zvo_queue);
#endif
#ifdef QUEUE_FLAG_NONROT
	blk_queue_flag_set(QUEUE_FLAG_NONROT, zv->zv_zso->zvo_queue);
#endif
#ifdef QUEUE_FLAG_ADD_RANDOM
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, zv->zv_zso->zvo_queue);
#endif
	/* This flag was introduced in kernel version 4.12. */
#ifdef QUEUE_FLAG_SCSI_PASSTHROUGH
	blk_queue_flag_set(QUEUE_FLAG_SCSI_PASSTHROUGH, zv->zv_zso->zvo_queue);
#endif

	ASSERT3P(zv->zv_kstat.dk_kstats, ==, NULL);
	error = dataset_kstats_create(&zv->zv_kstat, zv->zv_objset);
	if (error)
		goto out_dmu_objset_disown;
	ASSERT3P(zv->zv_zilog, ==, NULL);
	zv->zv_zilog = zil_open(os, zvol_get_data, &zv->zv_kstat.dk_zil_sums);
	if (spa_writeable(dmu_objset_spa(os))) {
		if (zil_replay_disable)
			replayed_zil = zil_destroy(zv->zv_zilog, B_FALSE);
		else
			replayed_zil = zil_replay(os, zv, zvol_replay_vector);
	}
	if (replayed_zil)
		zil_close(zv->zv_zilog);
	zv->zv_zilog = NULL;

	/*
	 * When udev detects the addition of the device it will immediately
	 * invoke blkid(8) to determine the type of content on the device.
	 * Prefetching the blocks commonly scanned by blkid(8) will speed
	 * up this process.
	 */
	len = MIN(zvol_prefetch_bytes, SPA_MAXBLOCKSIZE);
	if (len > 0) {
		dmu_prefetch(os, ZVOL_OBJ, 0, 0, len, ZIO_PRIORITY_SYNC_READ);
		dmu_prefetch(os, ZVOL_OBJ, 0, volsize - len, len,
		    ZIO_PRIORITY_SYNC_READ);
	}

	zv->zv_objset = NULL;
out_dmu_objset_disown:
	dmu_objset_disown(os, B_TRUE, FTAG);
out_doi:
	kmem_free(doi, sizeof (dmu_object_info_t));

	/*
	 * Keep in mind that once add_disk() is called, the zvol is
	 * announced to the world, and zvol_open()/zvol_release() can
	 * be called at any time. Incidentally, add_disk() itself calls
	 * zvol_open()->zvol_first_open() and zvol_release()->zvol_last_close()
	 * directly as well.
	 */
	if (error == 0) {
		rw_enter(&zvol_state_lock, RW_WRITER);
		zvol_insert(zv);
		rw_exit(&zvol_state_lock);
		error = zvol_os_add_disk(zv->zv_zso->zvo_disk);
	} else {
		ida_simple_remove(&zvol_ida, idx);
	}

	return (error);
}

void
zvol_os_rename_minor(zvol_state_t *zv, const char *newname)
{
	int readonly = get_disk_ro(zv->zv_zso->zvo_disk);

	ASSERT(RW_LOCK_HELD(&zvol_state_lock));
	ASSERT(MUTEX_HELD(&zv->zv_state_lock));

	strlcpy(zv->zv_name, newname, sizeof (zv->zv_name));

	/* move to new hashtable entry  */
	zv->zv_hash = zvol_name_hash(newname);
	hlist_del(&zv->zv_hlink);
	hlist_add_head(&zv->zv_hlink, ZVOL_HT_HEAD(zv->zv_hash));

	/*
	 * The block device's read-only state is briefly changed causing
	 * a KOBJ_CHANGE uevent to be issued.  This ensures udev detects
	 * the name change and fixes the symlinks.  This does not change
	 * ZVOL_RDONLY in zv->zv_flags so the actual read-only state never
	 * changes.  This would normally be done using kobject_uevent() but
	 * that is a GPL-only symbol which is why we need this workaround.
	 */
	set_disk_ro(zv->zv_zso->zvo_disk, !readonly);
	set_disk_ro(zv->zv_zso->zvo_disk, readonly);

	dataset_kstats_rename(&zv->zv_kstat, newname);
}

void
zvol_os_set_disk_ro(zvol_state_t *zv, int flags)
{

	set_disk_ro(zv->zv_zso->zvo_disk, flags);
}

void
zvol_os_set_capacity(zvol_state_t *zv, uint64_t capacity)
{

	set_capacity(zv->zv_zso->zvo_disk, capacity);
}

int
zvol_init(void)
{
	int error;

	/*
	 * zvol_threads is the module param the user passes in.
	 *
	 * zvol_actual_threads is what we use internally, since the user can
	 * pass zvol_thread = 0 to mean "use all the CPUs" (the default).
	 */
	static unsigned int zvol_actual_threads;

	if (zvol_threads == 0) {
		/*
		 * See dde9380a1 for why 32 was chosen here.  This should
		 * probably be refined to be some multiple of the number
		 * of CPUs.
		 */
		zvol_actual_threads = MAX(num_online_cpus(), 32);
	} else {
		zvol_actual_threads = MIN(MAX(zvol_threads, 1), 1024);
	}

	/*
	 * Use atleast 32 zvol_threads but for many core system,
	 * prefer 6 threads per taskq, but no more taskqs
	 * than threads in them on large systems.
	 *
	 *                 taskq   total
	 * cpus    taskqs  threads threads
	 * ------- ------- ------- -------
	 * 1       1       32       32
	 * 2       1       32       32
	 * 4       1       32       32
	 * 8       2       16       32
	 * 16      3       11       33
	 * 32      5       7        35
	 * 64      8       8        64
	 * 128     11      12       132
	 * 256     16      16       256
	 */
	zv_taskq_t *ztqs = &zvol_taskqs;
	uint_t num_tqs = MIN(num_online_cpus(), zvol_num_taskqs);
	if (num_tqs == 0) {
		num_tqs = 1 + num_online_cpus() / 6;
		while (num_tqs * num_tqs > zvol_actual_threads)
			num_tqs--;
	}
	uint_t per_tq_thread = zvol_actual_threads / num_tqs;
	if (per_tq_thread * num_tqs < zvol_actual_threads)
		per_tq_thread++;
	ztqs->tqs_cnt = num_tqs;
	ztqs->tqs_taskq = kmem_alloc(num_tqs * sizeof (taskq_t *), KM_SLEEP);
	error = register_blkdev(zvol_major, ZVOL_DRIVER);
	if (error) {
		kmem_free(ztqs->tqs_taskq, ztqs->tqs_cnt * sizeof (taskq_t *));
		ztqs->tqs_taskq = NULL;
		printk(KERN_INFO "ZFS: register_blkdev() failed %d\n", error);
		return (error);
	}

	if (zvol_blk_mq_queue_depth == 0) {
		zvol_actual_blk_mq_queue_depth = BLKDEV_DEFAULT_RQ;
	} else {
		zvol_actual_blk_mq_queue_depth =
		    MAX(zvol_blk_mq_queue_depth, BLKDEV_MIN_RQ);
	}

	if (zvol_blk_mq_threads == 0) {
		zvol_blk_mq_actual_threads = num_online_cpus();
	} else {
		zvol_blk_mq_actual_threads = MIN(MAX(zvol_blk_mq_threads, 1),
		    1024);
	}

	for (uint_t i = 0; i < num_tqs; i++) {
		char name[32];
		(void) snprintf(name, sizeof (name), "%s_tq-%u",
		    ZVOL_DRIVER, i);
		ztqs->tqs_taskq[i] = taskq_create(name, per_tq_thread,
		    maxclsyspri, per_tq_thread, INT_MAX,
		    TASKQ_PREPOPULATE | TASKQ_DYNAMIC);
		if (ztqs->tqs_taskq[i] == NULL) {
			for (int j = i - 1; j >= 0; j--)
				taskq_destroy(ztqs->tqs_taskq[j]);
			unregister_blkdev(zvol_major, ZVOL_DRIVER);
			kmem_free(ztqs->tqs_taskq, ztqs->tqs_cnt *
			    sizeof (taskq_t *));
			ztqs->tqs_taskq = NULL;
			return (-ENOMEM);
		}
	}

	zvol_init_impl();
	ida_init(&zvol_ida);
	return (0);
}

void
zvol_fini(void)
{
	zv_taskq_t *ztqs = &zvol_taskqs;
	zvol_fini_impl();
	unregister_blkdev(zvol_major, ZVOL_DRIVER);

	if (ztqs->tqs_taskq == NULL) {
		ASSERT3U(ztqs->tqs_cnt, ==, 0);
	} else {
		for (uint_t i = 0; i < ztqs->tqs_cnt; i++) {
			ASSERT3P(ztqs->tqs_taskq[i], !=, NULL);
			taskq_destroy(ztqs->tqs_taskq[i]);
		}
		kmem_free(ztqs->tqs_taskq, ztqs->tqs_cnt *
		    sizeof (taskq_t *));
		ztqs->tqs_taskq = NULL;
	}

	ida_destroy(&zvol_ida);
}

/* BEGIN CSTYLED */
module_param(zvol_inhibit_dev, uint, 0644);
MODULE_PARM_DESC(zvol_inhibit_dev, "Do not create zvol device nodes");

module_param(zvol_major, uint, 0444);
MODULE_PARM_DESC(zvol_major, "Major number for zvol device");

module_param(zvol_threads, uint, 0444);
MODULE_PARM_DESC(zvol_threads, "Number of threads to handle I/O requests. Set"
    "to 0 to use all active CPUs");

module_param(zvol_request_sync, uint, 0644);
MODULE_PARM_DESC(zvol_request_sync, "Synchronously handle bio requests");

module_param(zvol_max_discard_blocks, ulong, 0444);
MODULE_PARM_DESC(zvol_max_discard_blocks, "Max number of blocks to discard");

module_param(zvol_num_taskqs, uint, 0444);
MODULE_PARM_DESC(zvol_num_taskqs, "Number of zvol taskqs");

module_param(zvol_prefetch_bytes, uint, 0644);
MODULE_PARM_DESC(zvol_prefetch_bytes, "Prefetch N bytes at zvol start+end");

module_param(zvol_volmode, uint, 0644);
MODULE_PARM_DESC(zvol_volmode, "Default volmode property value");

module_param(zvol_blk_mq_queue_depth, uint, 0644);
MODULE_PARM_DESC(zvol_blk_mq_queue_depth, "Default blk-mq queue depth");

module_param(zvol_use_blk_mq, uint, 0644);
MODULE_PARM_DESC(zvol_use_blk_mq, "Use the blk-mq API for zvols");

module_param(zvol_blk_mq_blocks_per_thread, uint, 0644);
MODULE_PARM_DESC(zvol_blk_mq_blocks_per_thread,
    "Process volblocksize blocks per thread");

#ifndef HAVE_BLKDEV_GET_ERESTARTSYS
module_param(zvol_open_timeout_ms, uint, 0644);
MODULE_PARM_DESC(zvol_open_timeout_ms, "Timeout for ZVOL open retries");
#endif

/* END CSTYLED */
