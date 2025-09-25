/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2004-2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/bio.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <geom/geom.h>
#include <geom/geom_dbg.h>
#include <geom/logstor/g_logstor.h>

FEATURE(geom_logstor, "GEOM logstor support");

static MALLOC_DEFINE(M_LOGSTOR, "logstor_data", "GEOM_LOGSTOR Data");

SYSCTL_DECL(_kern_geom);
static SYSCTL_NODE(_kern_geom, OID_AUTO, logstor, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "GEOM_LOGSTOR stuff");
static u_int g_logstor_debug = 0;
SYSCTL_UINT(_kern_geom_logstor, OID_AUTO, debug, CTLFLAG_RWTUN, &g_logstor_debug, 0,
    "Debug level");

#define MY_DEBUG
#define MY_PANIC()	panic("panic: %s %d %s\n", __FILE__, __LINE__, __func__)
#define MY_ASSERT(x)\
    do\
	if (!(x))\
	    panic("assert fail: %s %d %s\n", __FILE__, __LINE__, __func__);\
    while(0)

#define G_LOGSTOR_SUFFIX	".logstor"

#define	SEG_SIZE	0x400000		// 4M
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE)	// 1024
#define BLOCKS_PER_SEG	(SECTORS_PER_SEG - 1)
#define SEG_SUM_OFFSET	(SECTORS_PER_SEG - 1)	// segment summary offset
#define SB_CNT	8	// number of superblock sectors
#define SEC_PER_SEG_SHIFT 10	// sectors per segment shift

/*
  The max file size is 1K*1K*4K=4G, each entry is 4 bytes
  so the max block number is 4G/4 = 1G
*/
#define BLOCK_MAX	0x40000000	// 1G
// the address [BLOCK_MAX..META_STAR) are invalid block/metadata address
#define BLOCK_INVALID	(BLOCK_MAX+1)
#define META_INVALID	(BLOCK_MAX+1)

enum {
	SECTOR_NULL,	// the metadata are all NULL
	SECTOR_DEL,	// the file does not exist or don't look the mapping further, it is NULL
	SECTOR_CACHE,	// the root sector of the file is still in the cache
};

#define	META_START	(((union meta_addr){.meta = 0xFF}).uint32)	// metadata block address start
#define	IS_META_ADDR(x)	((x) >= META_START)

#define FBUF_CLEAN_THRESHOLD	32
#define FBUF_MIN	1564
#define FBUF_MAX	(FBUF_MIN * 2)
// the last bucket is reserved for queuing fbufs that will not be searched
#define FBUF_BUCKET_LAST 953	// this should be a prime number
#define FBUF_BUCKET_CNT	(FBUF_BUCKET_LAST+1)

#define FD_COUNT	4		// max number of metadata files supported
#define FD_INVALID	FD_COUNT	// the valid file descriptor are 0 to 3

struct _superblock {
	uint32_t magic;
	uint32_t version;
	char name[16];
	uint64_t provsize;	// Provider's size
	/*
	   The segments are treated as circular buffer
	 */
	uint32_t seg_cnt;	// total number of segments
	// since the max meta file size is 4G (1K*1K*4K) and the entry size is 4
	// block_cnt must be < (4G/4)
	uint32_t block_cnt;	// max block number for the virtual disk

	uint32_t sb_gen;	// the generation number. Used for redo after system crash
	uint32_t seg_allocp;	// allocate this segment
	uint32_t sectors_free;
	/*
	   The files for forward mapping

	   New mapping is written to %fd_cur. When snapshot command is issued
	   %fd_cur is movied to %fd_prev, %fd_prev and %fd_snap are merged to %fd_snap_new
	   After the snapshot command is complete, %fd_snap_new is movied to %fd_snap
	   and %fd_prev is deleted.

	   So the actual mapping in normal state is
	       %fd_cur || %fd_snap
	   and during snapshot it is
	       %fd_cur || %fd_prev || %fd_snap

	   The first mapping that is not null is used.
	   To support trim command, the mapping marked as delete will stop
	   the checking for the next mapping file and return null immediately
	*/
	struct { // file handles
		uint32_t root;	// the root sector of the file
		uint32_t written;// number of blocks written to this virtual disk
	} fh[FD_COUNT];
	uint8_t fd_prev;	// the file descriptor for previous current mapping
	uint8_t fd_snap;	// the file descriptor for snapshot mapping
	uint8_t fd_cur;		// the file descriptor for current mapping
	uint8_t fd_snap_new;	// the file descriptor for new snapshot mapping
} __packed;

_Static_assert(sizeof(struct _superblock) < SECTOR_SIZE,
	"The size of the super block must be smaller than SECTOR_SIZE");

/*
  Forward map and its indirect blocks are also stored in the downstream disk.
  The sectors used to store the forward map and its indirect blocks are called metadata.

  Each metadata block has a corresponding metadata address.
  Below is the format of the metadata address.

  The metadata address occupies a small portion of block address space.
  For block address that is >= META_START, it is actually a metadata address.
*/
#define META_LEAF_DEPTH	2
#define IDX_BITS	10	// number of index bits
union meta_addr { // metadata address for file data and its indirect blocks
	uint32_t	uint32;
	struct {
		uint32_t index1 :IDX_BITS;	// index for indirect block of depth 1
		uint32_t index0 :IDX_BITS;	// index for indirect block of depth 0
		uint32_t depth	:2;	// depth of the node
		uint32_t fd	:2;	// file descriptor
		uint32_t meta	:8;	// 0xFF for metadata address
	};
	struct {
		uint32_t index :20;	// index for indirect blocks
	};
};

_Static_assert(sizeof(union meta_addr) == 4, "The size of emta_addr must be 4");

// when processing queues, we always process it from the leaf to root
// so leaf has lower queue number
enum {
	QUEUE_F0_CLEAN,	// floor 0, clean queue
	QUEUE_F0_DIRTY,	// floor 0, dirty queue
	QUEUE_F1,	// floor 1
	QUEUE_F2,	// floor 2
	QUEUE_CNT,
};

struct _fbuf_comm {
	struct _fbuf *queue_next;
	struct _fbuf *queue_prev;
	bool is_sentinel;
	bool accessed;	/* only used for fbufs on circular queue */
	bool modified;	/* the fbuf is dirty */
};

struct _fbuf_sentinel {
	// if this is a sentinel for bucket queue
	// fc.queue_next is actually fc.bucket_next
	// fc.queue_prev is actually fc.bucket_prev
	struct _fbuf_comm fc;
};

/*
  Metadata is cached in memory. The access unit of metadata is block so each cache line
  stores a block of metadata
*/
struct _fbuf { // file buffer
	struct _fbuf_comm fc;
	// for bucket sentinel bucket_next is stored in fc.queue_next
	// for bucket sentinel bucket_prev is stored in fc.queue_prev
	struct _fbuf *bucket_next;
	struct _fbuf *bucket_prev;
	struct _fbuf *parent;
	uint16_t child_cnt; // number of children reference this fbuf

	union meta_addr	ma;	// the metadata address
	uint16_t queue_which;
#if defined(MY_DEBUG)
	uint16_t bucket_which;
	uint16_t index; // the array index for this fbuf
	uint16_t dbg_child_cnt;
	uint32_t sa;	// the sector address of the @data
	struct _fbuf 	*child[SECTOR_SIZE/sizeof(uint32_t)];
#endif
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
};

/*
  The last sector in a segment is the segment summary. It stores the reverse mapping table
*/
struct _seg_sum {
	uint32_t ss_rm[SECTORS_PER_SEG - 1];	// reverse map
	// reverse map SECTORS_PER_SEG - 1 is not used so we store something here
	uint32_t ss_allocp;	// the sector for allocation in the segment
	//uint32_t ss_gen;  // sequence number. used for redo after system crash
} __packed;

_Static_assert(sizeof(struct _seg_sum) == SECTOR_SIZE,
	"The size of segment summary must be equal to SECTOR_SIZE");

/*
	logstor soft control
*/
struct g_logstor_softc {
	struct g_geom	*sc_geom;
	bool (*is_sec_inuse_fp)(struct g_logstor_softc *sc, uint32_t ba_rev, uint32_t sa);
	uint32_t (*ba2sa_fp)(struct g_logstor_softc *sc, uint32_t ba);

	struct _superblock superblock;
	struct _seg_sum seg_sum;// segment summary for the current segment
	uint32_t sb_sa; 	// superblock's sector address
	bool sb_modified;	// is the super block modified
	bool ss_modified;	// is segment summary modified

	uint32_t seg_allocp_start;// the starting segment for doing logstor_write
	uint32_t seg_allocp_sa;	// the sector address of the segment for allocation

	int fbuf_count;
	struct _fbuf *fbufs;	// an array of fbufs
	struct _fbuf *fbuf_allocp; // point to the fbuf candidate for replacement
	struct _fbuf_sentinel fbuf_queue[QUEUE_CNT];
	struct _fbuf_sentinel fbuf_bucket[FBUF_BUCKET_CNT]; // buffer hash queue
	int fbuf_queue_len[QUEUE_CNT];
#if defined(MY_DEBUG)
	int fbuf_bucket_len[FBUF_BUCKET_CNT];
#endif
	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;
};

/*******************************
 *        logstor              *
 *******************************/
static uint32_t logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data);
static uint32_t sec_alloc_for_write(struct g_logstor_softc *sc, uint32_t ba);

static void seg_alloc(struct g_logstor_softc *sc);
static void seg_sum_write(struct g_logstor_softc *sc);

static struct _superblock *superblock_read(struct g_consumer *cp, uint32_t *sb_sa);
static void superblock_write(struct g_logstor_softc *sc);

static struct _fbuf *file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t offset, uint32_t *off_4byte);
static uint32_t file_read_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba);
static void file_write_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba, uint32_t sa);

static void fbuf_mod_init(struct g_logstor_softc *sc);
static void fbuf_mod_fini(struct g_logstor_softc *sc);
static void fbuf_queue_init(struct g_logstor_softc *sc, int which);
static void fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf);
static void fbuf_queue_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static struct _fbuf *fbuf_search(struct g_logstor_softc *sc, union meta_addr ma);
static void fbuf_hash_insert_head(struct g_logstor_softc *sc, struct _fbuf *fbuf, union meta_addr ma);
static void fbuf_bucket_init(struct g_logstor_softc *sc, int which);
static void fbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf);
static void fbuf_bucket_remove(struct _fbuf *fbuf);
static void fbuf_write(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static struct _fbuf *fbuf_alloc(struct g_logstor_softc *sc, union meta_addr ma, int depth);
static struct _fbuf *fbuf_access(struct g_logstor_softc *sc, union meta_addr ma);
static void fbuf_cache_flush(struct g_logstor_softc *sc);
static void fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2);
static void fbuf_clean_queue_check(struct g_logstor_softc *sc);

static union meta_addr ma2pma(union meta_addr ma, unsigned *pindex_out);
static uint32_t ma2sa(struct g_logstor_softc *sc, union meta_addr ma);

static uint32_t ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba);
static uint32_t ba2sa_during_snapshot(struct g_logstor_softc *sc, uint32_t ba);
static bool is_sec_inuse_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_inuse_during_snapshot(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
#if defined(MY_DEBUG)
static void logstor_check(struct g_logstor_softc *sc);
#endif
static void md_read(struct g_consumer *cp, void *buf, uint32_t sa);
static void md_write(struct g_consumer *cp, void *buf, uint32_t sa);

/*
Description:
    segment address to sector address
*/
static inline uint32_t
sega2sa(uint32_t sega)
{
	return sega << SEC_PER_SEG_SHIFT;
}

static void
invalid_g_start(struct bio *bp __unused)
{
	panic("%s: something is wrong here.", __func__);
}

static int
invalid_g_access(struct g_provider *gp __unused, int dr __unused, int dw __unused, int de __unused)
{
	panic("%s: something is wrong here.", __func__);
	return 1;
}

static void
invalid_g_orphan(struct g_consumer *gc __unused)
{
	panic("%s: something is wrong here.", __func__);
}

/*
Description:
    Write the initialized supeblock to the downstream disk

Parameters:
    sb_sa: the sector address of the superblock

Return:
    The superblock
*/
static struct _superblock *
disk_init(struct g_class *mp, struct g_provider *pp, uint32_t *sb_sa)
{
	struct _seg_sum *seg_sum;
	int error;
	uint32_t sector_cnt;

	struct _superblock *sb = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK | M_ZERO);
	sb->magic = G_LOGSTOR_MAGIC;
	sb->version = G_LOGSTOR_VERSION;
	sb->sb_gen = arc4random();
	sector_cnt = pp->mediasize / SECTOR_SIZE;
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	sb->block_cnt = sb->seg_cnt * BLOCKS_PER_SEG - SB_CNT -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT * 4;
	MY_ASSERT(sb->block_cnt < 0x40000000); // 1G
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u block_cnt %u\n",
	    __func__, sector_cnt, sb->block_cnt);
#endif
	sb->seg_allocp = 0;	// segment allocation starts from here

	sb->fd_cur = 0;			// current mapping is file 0
	sb->fd_snap = 1;		// snapshot mapping is file 1
	sb->fd_prev = FD_INVALID;	// previous mapping does not eixt
	sb->fd_snap_new = FD_INVALID;	// snap_new mapping does not eixt

	sb->fh[0].root = SECTOR_NULL;	// file 0 is all 0
	sb->fh[0].written = 0;
	// files 1, 2 and 3: read returns 0 and write not allowed
	for (int i = 1; i < FD_COUNT; i++) {
		sb->fh[i].root = SECTOR_DEL;	// the file does not exit
	}
	memset((char *)sb + sizeof(*sb), 0, SECTOR_SIZE - sizeof(*sb));

	struct g_geom *gp = g_new_geom(mp, "logstor:init");
	gp->start = invalid_g_start;
	gp->access = invalid_g_access;
	gp->orphan = invalid_g_orphan;
	struct g_consumer *cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	error = g_attach(cp, pp);
	if (error) {
		goto fail0;
	}
	g_topology_assert();
	error = g_access(cp, 0, 0, 1);
	if (error) {
		printf("%s: Cannot store metadata on %s: %d",
		    __func__, cp->provider->name, error);
		goto fail1;
	}

	// write out the first super block
	*sb_sa = 0;
	error = g_write_data(cp, 0, sb, SECTOR_SIZE);
	if (error)
		goto fail2;

	// clear the rest of the supeblocks
	char *buf = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK | M_ZERO);
	for (int i = 1; i < SB_CNT; i++) {
		error = g_write_data(cp, i * SECTOR_SIZE, buf, SECTOR_SIZE);
		if (error)
			goto fail3;
	}
	// initialize the segment summary block
	seg_sum = (struct _seg_sum *)buf;
	for (int i = 0; i < BLOCKS_PER_SEG; ++i)
		seg_sum->ss_rm[i] = BLOCK_INVALID;

	// write out the first segment summary block
	seg_sum->ss_allocp = SB_CNT;
	error = g_write_data(cp, SEG_SUM_OFFSET * SECTOR_SIZE, seg_sum, SECTOR_SIZE);
	if (error)
		goto fail3;

	// write out the rest of the segment summary blocks
	seg_sum->ss_allocp = 0;
	for (int i = 1; i < sb->seg_cnt; ++i) {
		uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		error = g_write_data(cp, (off_t)sa * SECTOR_SIZE, seg_sum, SECTOR_SIZE);
		if (error)
			goto fail3;
	}
fail3:
	free(buf, M_LOGSTOR);
fail2:
	(void)g_access(cp, 0, 0, -1);
fail1:
	g_detach(cp);
fail0:
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	if (error) {
		free(sb, M_LOGSTOR);
		sb = NULL;
	}
	return sb;
}

// The common part of is_sec_inuse
static bool
is_sec_inuse_comm(uint8_t fd[], int fd_cnt, struct g_logstor_softc *sc, uint32_t ba_rev, uint32_t sa)
{
	uint32_t sa_rev; // the sector address for ba_rev

	MY_ASSERT(ba_rev < BLOCK_MAX);
	for (int i = 0; i < fd_cnt; ++i) {
		sa_rev = file_read_4byte(sc, fd[i], ba_rev);
		if (sa_rev == sa)
			return true;
	}
	return false;
}
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

// Is a sector with a reverse ba valid?
// This function is called normally
static bool
is_sec_inuse_normal(struct g_logstor_softc *sc, uint32_t ba_rev, uint32_t sa)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return is_sec_inuse_comm(fd, NUM_OF_ELEMS(fd), sc, ba_rev, sa);
}

// Is a sector with a reverse ba valid?
// This function is called during snapshot
static bool
is_sec_inuse_during_snapshot(struct g_logstor_softc *sc, uint32_t ba_rev, uint32_t sa)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return is_sec_inuse_comm(fd, NUM_OF_ELEMS(fd), sc, ba_rev, sa);
}

// Is a sector with a reverse ba valid?
static bool
is_sec_inuse(struct g_logstor_softc *sc, uint32_t ba_rev, uint32_t sa)
{
#if defined(MY_DEBUG)
	union meta_addr ma_rev __unused;
	ma_rev.uint32 = ba_rev;
#endif
	if (ba_rev < BLOCK_MAX) {
		return sc->is_sec_inuse_fp(sc, ba_rev, sa);
#if defined(WYC)
		is_sec_inuse_normal();
		is_sec_inuse_during_snapshot();
#endif
	} else if (IS_META_ADDR(ba_rev)) {
		uint32_t sa_rev = ma2sa(sc, (union meta_addr)ba_rev);
		return (sa_rev == sa);
	} else if (ba_rev == BLOCK_INVALID) {
		return false;
	} else {
		MY_PANIC();
		return false;
	}
}

// allocate a sector for writing
static uint32_t
sec_alloc_for_write(struct g_logstor_softc *sc, uint32_t ba)
{
	uint32_t sa =logstor_write(sc, ba, NULL);
	return sa;
}

/*
Description:
  write metadata block to disk

Return:
  the sector address where the data/metadata is written
*/
static uint32_t
logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data)
{
	static bool is_called = false;
	int i;
	struct _seg_sum *seg_sum = &sc->seg_sum;
#if defined(MY_DEBUG)
	union meta_addr ma __unused;
	union meta_addr ma_rev __unused;

	ma.uint32 = ba;
#endif
	MY_ASSERT(IS_META_ADDR(ba) ? data != NULL : data == NULL);
	MY_ASSERT(ba < sc->superblock.block_cnt || IS_META_ADDR(ba));
	if (is_called) // recursive call is not allowed
		MY_PANIC();
	is_called = true;

	// record the starting segment
	// if the search for free sector rolls over to the starting segment
	// it means that there is no free sector in this disk
	sc->seg_allocp_start = sc->superblock.seg_allocp;
again:
	for (i = seg_sum->ss_allocp; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t sa = sc->seg_allocp_sa + i;
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map
#if defined(MY_DEBUG)
		ma_rev.uint32 = ba_rev;
#endif
		if (is_sec_inuse(sc, ba_rev, sa))
			continue;

		if (IS_META_ADDR(ba)) {
			struct g_consumer *cp;
			cp = LIST_FIRST(&sc->sc_geom->consumer);
			md_write(cp, data, sa);
			++sc->other_write_count;
		}
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		sc->ss_modified = true;		// segment summary modified
		seg_sum->ss_allocp = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_allocp == SEG_SUM_OFFSET)
			seg_alloc(sc);

		if (!IS_META_ADDR(ba)) {
			++sc->data_write_count;
			// record the forward mapping for the %ba
			// the forward mapping must be recorded after
			// the segment summary block write
			file_write_4byte(sc, sc->superblock.fd_cur, ba, sa);
		}
		is_called = false;
		return sa;
	}
	seg_alloc(sc);
	goto again;
}

static void
logstor_init(struct g_logstor_softc *sc, struct _superblock *sb, uint32_t sb_sa)
{
	memcpy(&sc->superblock, sb, sizeof(sc->superblock));
	sc->sb_sa = sb_sa;
	sc->sb_modified = false;

	// the following is copied from logstor_open()
	// read the segment summary block
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	uint32_t sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	md_read(cp, &sc->seg_sum, sa);
	MY_ASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET);
	sc->ss_modified = false;

	fbuf_mod_init(sc);

	sc->data_write_count = sc->other_write_count = 0;
	sc->is_sec_inuse_fp = is_sec_inuse_normal;
	sc->ba2sa_fp = ba2sa_normal;
#if defined(MY_DEBUG)
	logstor_check(sc);
#endif
}

static void
logstor_close(struct g_logstor_softc *sc)
{

	fbuf_mod_fini(sc);
	seg_sum_write(sc);
	superblock_write(sc);
}

static void
logstor_snapshot(struct g_logstor_softc *sc)
{

	// lock metadata
	// move fd_cur to fd_prev
	sc->superblock.fd_prev = sc->superblock.fd_cur;
	// create new files fd_cur and fd_snap_new
	// fc_cur is either 0 or 2 and fd_snap always follows fd_cur
	sc->superblock.fd_cur = sc->superblock.fd_cur ^ 2;
	sc->superblock.fd_snap_new = sc->superblock.fd_cur + 1;
	sc->superblock.fh[sc->superblock.fd_cur].root = SECTOR_NULL;
	sc->superblock.fh[sc->superblock.fd_cur].written = 0;
	sc->superblock.fh[sc->superblock.fd_snap_new].root = SECTOR_NULL;
	sc->superblock.fh[sc->superblock.fd_snap_new].written = 0;

	sc->is_sec_inuse_fp = is_sec_inuse_during_snapshot;
	sc->ba2sa_fp = ba2sa_during_snapshot;
	// unlock metadata

	// merge fd_prev and fd_snap to fd_snap_new
	uint32_t block_cnt = sc->superblock.block_cnt;
	for (int ba = 0; ba < block_cnt; ++ba) {
		uint32_t sa;

		fbuf_clean_queue_check(sc);
		sa = file_read_4byte(sc, sc->superblock.fd_prev, ba);
		if (sa == SECTOR_NULL)
			sa = file_read_4byte(sc, sc->superblock.fd_snap, ba);
		else if (sa == SECTOR_DEL)
			sa = SECTOR_NULL;

		if (sa != SECTOR_NULL)
			file_write_4byte(sc, sc->superblock.fd_snap_new, ba, sa);
	}

	// lock metadata
	int fd_prev = sc->superblock.fd_prev;
	int fd_snap = sc->superblock.fd_snap;
	fbuf_cache_flush_and_invalidate_fd(sc, fd_prev, fd_snap);
	sc->superblock.fh[fd_prev].root = SECTOR_DEL;
	sc->superblock.fh[fd_snap].root = SECTOR_DEL;
	// move fd_snap_new to fd_snap
	sc->superblock.fd_snap = sc->superblock.fd_snap_new;
	// delete fd_prev and fd_snap
	sc->superblock.fd_prev = FD_INVALID;
	sc->superblock.fd_snap_new = FD_INVALID;
	sc->sb_modified = true;

	seg_sum_write(sc);
	superblock_write(sc);

	sc->is_sec_inuse_fp = is_sec_inuse_normal;
	sc->ba2sa_fp = ba2sa_normal;
	//unlock metadata
}

void
static logstor_rollback(struct g_logstor_softc *sc)
{

	fbuf_cache_flush_and_invalidate_fd(sc, sc->superblock.fd_cur, FD_INVALID);
	sc->superblock.fh[sc->superblock.fd_cur].root = SECTOR_NULL;
	sc->superblock.fh[sc->superblock.fd_cur].written = 0;
	sc->sb_modified = true;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
static void
logstor_delete(struct g_logstor_softc *sc, struct bio *bp)
{
#if 1
	printf("%s: BIO_DELETE not implemented yet\n", __func__);
	g_io_deliver(bp, EOPNOTSUPP);
#else
	off_t offset = bp->bio_offset;
	off_t length = bp->bio_length;
	uint32_t ba;	// block address
	int count;	// number of remaining sectors to process
	int i;

	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	count = length / SECTOR_SIZE;
	MY_ASSERT(ba < sc->superblock.block_cnt);

	fbuf_clean_queue_check(sc);
	for (i = 0; i < count; ++i) {
		uint32_t sa = file_read_4byte(sc, sc->superblock.fd_cur, ba + i);
		if (sa != SECTOR_NULL && sa != SECTOR_DEL) {
			--sc->superblock.fh[sc->superblock.fd_cur].written;
			sc->sb_modified = true;
		}
		file_write_4byte(sc, sc->superblock.fd_cur, ba + i, SECTOR_DEL);
	}
#endif
}

static uint32_t
ba2sa_comm(struct g_logstor_softc *sc, uint32_t ba, uint8_t fd[], int fd_cnt)
{
	uint32_t sa;

	MY_ASSERT(ba < sc->superblock.block_cnt);
	for (int i = 0; i < fd_cnt; ++i) {
		sa = file_read_4byte(sc, fd[i], ba);
		if (sa == SECTOR_DEL) { // don't need to check further
			sa = SECTOR_NULL;
			break;
		}
		if (sa != SECTOR_NULL)
			break;
	}
	MY_ASSERT(sa == SECTOR_NULL || sa >= SB_CNT);
	return sa;
}

/*
Description:
    Block address to sector address translation in normal state
*/
static uint32_t
ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

/*
Description:
    Block address to sector address translation in snapshot state
*/
static uint32_t __unused
ba2sa_during_snapshot(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

/*
  write out the segment summary
  segment summary is at the end of a segment
*/
static void
seg_sum_write(struct g_logstor_softc *sc)
{
	uint32_t sa;
	struct g_consumer *cp;

	if (!sc->ss_modified)
		return;
	MY_ASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET);
	cp = LIST_FIRST(&sc->sc_geom->consumer);
	sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	md_write(cp, (void *)&sc->seg_sum, sa);
	sc->ss_modified = false;
	sc->other_write_count++; // the write for the segment summary
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
static struct _superblock *
superblock_read(struct g_consumer *cp, uint32_t *sb_sa)
{
	struct _superblock *sb;
	typeof(sb->sb_gen) sb_gen;
	int i, error;
	char *buf[2];

	buf[0] = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK);
	buf[1] = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK);

	g_topology_assert();
	error = g_access(cp, 1, 0, 0);
	if (error) {
		printf("%s: Cannot access %s error %d",
			__func__, cp->provider->name, error);
		goto exit;
	}
	// get the superblock
	sb = (struct _superblock *)buf[0];
	g_read_datab(cp, 0, sb, SECTOR_SIZE);
	if (sb->magic != G_LOGSTOR_MAGIC ||
	    sb->seg_allocp >= sb->seg_cnt) {
		error = EINVAL;
		goto exit;
	}

	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SB_CNT; i++) {
		sb = (struct _superblock *)buf[i%2];
		g_read_datab(cp, (off_t)i * SECTOR_SIZE, sb, SECTOR_SIZE);
		if (sb->magic != G_LOGSTOR_MAGIC)
			break;
		if (sb->sb_gen != sb_gen + 1) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	g_access(cp, -1, 0, 0);
	if (i == SECTORS_PER_SEG) {
		error = EINVAL;
		goto exit;
	}
	*sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2]; // get the previous valid superblock
	if (sb->seg_allocp >= sb->seg_cnt) {
		error = EINVAL;
		goto exit;
	}
	free(buf[i%2], M_LOGSTOR);
	for (i=0; i<FD_COUNT; ++i)
		MY_ASSERT(sb->fh[i].root != SECTOR_CACHE);
	return sb;
exit:
	free(buf[1], M_LOGSTOR);
	free(buf[0], M_LOGSTOR);
	return NULL;
}

static void
superblock_write(struct g_logstor_softc *sc)
{
	const size_t sb_size = sizeof(sc->superblock);
	struct g_consumer *cp;
	char *buf = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK | M_ZERO);

	//if (!sc->sb_modified)
	//	return;

	for (int i = 0; i < 4; ++i) {
		MY_ASSERT(sc->superblock.fh[i].root != SECTOR_CACHE);
	}
	sc->superblock.sb_gen++;
	if (++sc->sb_sa == SB_CNT)
		sc->sb_sa = 0;
	memcpy(buf, &sc->superblock, sb_size);
	memset(buf + sb_size, 0, SECTOR_SIZE - sb_size);
	cp = LIST_FIRST(&sc->sc_geom->consumer);
	md_write(cp, buf, sc->sb_sa);
	sc->sb_modified = false;
	sc->other_write_count++;
	free(buf, M_LOGSTOR);
}

static void
md_read(struct g_consumer *cp, void *buf, uint32_t sa)
{
	int error;

	g_topology_assert();
	error = g_access(cp, 1, 0, 0);
	if (error) {
		printf("%s: Cannot access %s error %d",
			__func__, cp->provider->name, error);
		MY_PANIC();
	}
	error = g_read_datab(cp, (off_t)sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	g_access(cp, -1, 0, 0);
	MY_ASSERT(error == 0);
}

static void
md_write(struct g_consumer *cp, void *buf, uint32_t sa)
{
	int error;

	g_topology_assert();
	error = g_access(cp, 0, 1, 0);
	if (error) {
		printf("%s: Cannot store metadata on %s: %d",
		    __func__, cp->provider->name, error);
		MY_PANIC();
	}
	error = g_write_data(cp, (off_t)sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	(void)g_access(cp, 0, -1, 0);
	MY_ASSERT(error == 0);
}

/*
Description:
  Allocate a segment for writing

Output:
  Store the segment address into @seg_sum->sega
  Initialize @seg_sum->sum.alloc_p to 0
*/
static void
seg_alloc(struct g_logstor_softc *sc)
{
	uint32_t ss_allocp;

	// write the previous segment summary to disk if it has been modified
	sc->seg_sum.ss_allocp = 0;	// the allocation starts from 0 in the next time
	seg_sum_write(sc);

	MY_ASSERT(sc->superblock.seg_allocp < sc->superblock.seg_cnt);
	if (++sc->superblock.seg_allocp == sc->superblock.seg_cnt) {
		sc->superblock.seg_allocp = 0;
		ss_allocp = SB_CNT; // the first SB_CNT sectors are superblock
	} else
		ss_allocp = 0;

	if (sc->superblock.seg_allocp == sc->seg_allocp_start)
		// has accessed all the segment summary blocks
		MY_PANIC();
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	md_read(cp, &sc->seg_sum, sc->seg_allocp_sa + SEG_SUM_OFFSET);
	sc->seg_sum.ss_allocp = ss_allocp;
}

/*********************************************************
 * The file buffer and indirect block cache              *
 *   Cache the the block to sector address translation   *
 *********************************************************/

/*
Description:
	Get the sector address of the corresponding @ba in @file

Parameters:
	@fd: file descriptor
	@ba: block address

Return:
	The sector address of the @ba
*/
static uint32_t
file_read_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba)
{
	uint32_t eidx;	// entry index within the file data buffer
	uint32_t sa;
	struct _fbuf *fbuf;

	MY_ASSERT(fd < FD_COUNT);

	// the initialized reverse map in the segment summary is BLOCK_MAX
	// so it is possible that a caller might pass a ba that is BLOCK_MAX
	if (ba >= BLOCK_MAX) {
		MY_ASSERT(ba == BLOCK_INVALID);
		return SECTOR_NULL;
	}
	// this file is all 0
	if (sc->superblock.fh[fd].root == SECTOR_NULL ||
	    sc->superblock.fh[fd].root == SECTOR_DEL)
		return SECTOR_NULL;

	fbuf = file_access_4byte(sc, fd, ba, &eidx);
	if (fbuf)
		sa = fbuf->data[eidx];
	else
		sa = SECTOR_NULL;
	return sa;
}

/*
Description:
	Set the mapping of @ba to @sa in @file

Parameters:
	%fd: file descriptor
	%ba: block address
	%sa: sector address
*/
static void
file_write_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t sa)
{
	struct _fbuf *fbuf;
	uint32_t eidx;	// entry index within the file data buffer

	MY_ASSERT(fd < FD_COUNT);
	MY_ASSERT(ba < BLOCK_MAX);
	MY_ASSERT(sc->superblock.fh[fd].root != SECTOR_DEL);

	fbuf = file_access_4byte(sc, fd, ba, &eidx);
	MY_ASSERT(fbuf != NULL);
	uint32_t old_sa = fbuf->data[eidx];
	if (old_sa == SECTOR_NULL || old_sa ==  SECTOR_DEL) {
		++sc->superblock.fh[fd].written;
		sc->sb_modified = true;
	}
	fbuf->data[eidx] = sa;
	if (!fbuf->fc.modified) {
		// move to QUEUE_F0_DIRTY
		MY_ASSERT(fbuf->queue_which == QUEUE_F0_CLEAN);
		fbuf->fc.modified = true;
		if (fbuf == sc->fbuf_allocp)
			sc->fbuf_allocp = fbuf->fc.queue_next;
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, QUEUE_F0_DIRTY, fbuf);
	} else
		MY_ASSERT(fbuf->queue_which == QUEUE_F0_DIRTY);
}

/*
Description:
    The metadata is cached in memory. This function returns the address
    of the metadata in memory for the forward mapping of the block @ba

Parameters:
	%fd: file descriptor
	%ba: block address
	%eidx: entry index within the file data buffer

Return:
	the address of the file buffer data
*/
static struct _fbuf *
file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t *eidx)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *fbuf;

	// the sector address stored in file for this ba is 4 bytes
	*eidx = ((ba * 4) & (SECTOR_SIZE - 1)) / 4;

	// convert (%fd, %ba) to metadata address
	ma.index = (ba * 4) / SECTOR_SIZE;
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	ma.meta = 0xFF;	// for metadata address, bits 31:24 are all 1s
	fbuf = fbuf_access(sc, ma);
	return fbuf;
}

static inline unsigned
ma_index_get(union meta_addr ma, unsigned depth)
{
	switch (depth) {
	case 0:
		return ma.index0;
	case 1:
		return ma.index1;
	default:
		MY_PANIC();
		return 0;
	}
}

static union meta_addr
ma_index_set(union meta_addr ma, unsigned depth, unsigned index)
{
	MY_ASSERT(index < (2 << IDX_BITS));

	switch (depth) {
	case 0:
		ma.index0 = index;
		break;
	case 1:
		ma.index1 = index;
		break;
	default:
		MY_PANIC();
	}
	return ma;
}

/*
  to parent's metadata address

output:
  pindex_out: the index in parent's metadata

return:
  parent's metadata address
*/
static union meta_addr
ma2pma(union meta_addr ma, unsigned *pindex_out)
{
	switch (ma.depth)
	{
	case 1:
		*pindex_out = ma.index0;
		ma.index = 0;
		ma.depth = 0; // i.e. ma.depth - 1
		break;
	case 2:
		*pindex_out = ma.index1;
		ma.index1 = 0;
		ma.depth = 1; // i.e. ma.depth - 1
		break;
	default:
		MY_PANIC();
		break;
	}
	return ma;
}

// get the sector address where the metadata is stored on disk
static uint32_t
ma2sa(struct g_logstor_softc *sc, union meta_addr ma)
{
	uint32_t sa;

	switch (ma.depth)
	{
	case 0:
		sa = sc->superblock.fh[ma.fd].root;
		break;
	case 1:
	case 2:
		if (sc->superblock.fh[ma.fd].root == SECTOR_NULL ||
		    sc->superblock.fh[ma.fd].root == SECTOR_DEL)
			sa = SECTOR_NULL;
		else {
			struct _fbuf *parent;	// parent buffer
			union meta_addr pma;	// parent's metadata address
			unsigned pindex;	// index in the parent indirect block

			pma = ma2pma(ma, &pindex);
			parent = fbuf_access(sc, pma);
			MY_ASSERT(parent != NULL);
			sa = parent->data[pindex];
		}
		break;
	case 3: // it is an invalid metadata address
		sa = SECTOR_NULL;
		break;
	}
	return sa;
}

/*
  Initialize metadata file buffer
*/
static void
fbuf_mod_init(struct g_logstor_softc *sc)
{
	int fbuf_count;
	int i;

	//fbuf_count = sc.superblock.block_cnt / (SECTOR_SIZE / 4);
	fbuf_count = FBUF_MIN;
	if (fbuf_count < FBUF_MIN)
		fbuf_count = FBUF_MIN;
	if (fbuf_count > FBUF_MAX)
		fbuf_count = FBUF_MAX;
	sc->fbuf_count = fbuf_count;
	sc->fbufs = malloc(fbuf_count * sizeof(*sc->fbufs), M_LOGSTOR, M_WAITOK | M_ZERO);

	for (i = 0; i < FBUF_BUCKET_CNT; ++i) {
		fbuf_bucket_init(sc, i);
	}
	for (i = 0; i < QUEUE_CNT; ++i) {
		fbuf_queue_init(sc, i);
	}
	// insert fbuf to both QUEUE_F0_CLEAN and hash queue
	for (i = 0; i < fbuf_count; ++i) {
		struct _fbuf *fbuf = &sc->fbufs[i];
#if defined(MY_DEBUG)
		fbuf->index = i;
#endif
		fbuf->fc.is_sentinel = false;
		fbuf->fc.accessed = false;
		fbuf->fc.modified = false;
		fbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fbuf);
		// insert fbuf to the last fbuf bucket
		// this bucket is not used in hash search
		// init parent, child_cnt and ma before inserting into FBUF_BUCKET_LAST
		fbuf->parent = NULL;
		fbuf->child_cnt = 0;
		fbuf->ma.uint32 = META_INVALID; // ma must be invalid for fbuf in FBUF_BUCKET_LAST
		fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
	}
	sc->fbuf_allocp = &sc->fbufs[0];;
	sc->fbuf_hit = sc->fbuf_miss = 0;
}

// there are 3 kinds of metadata in the system, the fbuf cache, segment summary block and superblock
static void
md_flush(struct g_logstor_softc *sc)
{
	fbuf_cache_flush(sc);
	seg_sum_write(sc);
	superblock_write(sc);
}

static void
fbuf_mod_fini(struct g_logstor_softc *sc)
{
	md_flush(sc);
	free(sc->fbufs, M_LOGSTOR);
}

static inline bool
is_queue_empty(struct _fbuf_sentinel *sentinel)
{
	if (sentinel->fc.queue_next == (struct _fbuf *)sentinel) {
		MY_ASSERT(sentinel->fc.queue_prev == (struct _fbuf *)sentinel);
		return true;
	}
	return false;
}

static void
fbuf_clean_queue_check(struct g_logstor_softc *sc)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;

	if (sc->fbuf_queue_len[QUEUE_F0_CLEAN] > FBUF_CLEAN_THRESHOLD)
		return;

	md_flush(sc);

	// move all internal nodes with child_cnt 0 to clean queue and last bucket
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->queue_which == q);
			struct _fbuf *next = fbuf->fc.queue_next;
			if (fbuf->child_cnt == 0) {
				fbuf_queue_remove(sc, fbuf);
				fbuf->fc.accessed = false; // so that it can be replaced faster
				fbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fbuf);
				if (fbuf->parent) {
					MY_ASSERT(q != QUEUE_CNT-1);
					struct _fbuf *parent = fbuf->parent;
					fbuf->parent = NULL;
					--parent->child_cnt;
					MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
				}
				// move it to the last bucket so that it cannot be searched
				// fbufs on the last bucket will have the metadata address META_INVALID
				fbuf_bucket_remove(fbuf);
				fbuf->ma.uint32 = META_INVALID;
				fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			}
			fbuf = next;
		}
	}
}

// write back all the dirty fbufs to disk
static void
fbuf_cache_flush(struct g_logstor_softc *sc)
{
	struct _fbuf *fbuf;
	struct _fbuf *dirty_first, *dirty_last, *clean_first;
	struct _fbuf_sentinel *dirty_sentinel;
	struct _fbuf_sentinel *clean_sentinel;

	// write back all the modified nodes to disk
	for (int q = QUEUE_F0_DIRTY; q < QUEUE_CNT; ++q) {
		struct _fbuf_sentinel *queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->queue_which == q);
			MY_ASSERT(IS_META_ADDR(fbuf->ma.uint32));
			// QUEUE_F0_DIRTY nodes are always dirty
			MY_ASSERT(q != QUEUE_F0_DIRTY || fbuf->fc.modified);
			if (__predict_true(fbuf->fc.modified))
				fbuf_write(sc, fbuf);
			fbuf = fbuf->fc.queue_next;
		}
	}
	// move all fbufs in the dirty leaf queue to clean leaf queue
	dirty_sentinel = &sc->fbuf_queue[QUEUE_F0_DIRTY];
	if (is_queue_empty(dirty_sentinel))
		return;
	// first, set queue_which to QUEUE_F0_CLEAN for all fbufs on dirty leaf queue
	fbuf = dirty_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)dirty_sentinel) {
		fbuf->queue_which = QUEUE_F0_CLEAN;
		fbuf = fbuf->fc.queue_next;
	}
	// second, insert dirty leaf queue to the head of clean leaf queue
	clean_sentinel = &sc->fbuf_queue[QUEUE_F0_CLEAN];
	dirty_first = dirty_sentinel->fc.queue_next;
	dirty_last = dirty_sentinel->fc.queue_prev;
	clean_first = clean_sentinel->fc.queue_next;
	clean_sentinel->fc.queue_next = dirty_first;
	dirty_first->fc.queue_prev = (struct _fbuf *)clean_sentinel;
	dirty_last->fc.queue_next = clean_first;
	clean_first->fc.queue_prev = dirty_last;
	sc->fbuf_queue_len[QUEUE_F0_CLEAN] += sc->fbuf_queue_len[QUEUE_F0_DIRTY];

	fbuf_queue_init(sc, QUEUE_F0_DIRTY);
}

// flush the cache and invalid fbufs with file descriptors fd1 or fd2
static void
fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2)
{
	struct _fbuf *fbuf;

	md_flush(sc);

	for (int i = 0; i < sc->fbuf_count; ++i)
	{
		fbuf = &sc->fbufs[i];
		MY_ASSERT(!fbuf->fc.modified);
		if (fbuf->ma.uint32 == META_INVALID) {
			// the fbufs with metadata address META_INVALID are
			// linked in bucket FBUF_BUCKET_LAST
			MY_ASSERT(fbuf->bucket_which == FBUF_BUCKET_LAST);
			continue;
		}
		// move fbufs with fd equals to fd1 or fd2 to the last bucket
		if (fbuf->ma.fd == fd1 || fbuf->ma.fd == fd2) {
			MY_ASSERT(fbuf->bucket_which != FBUF_BUCKET_LAST);
			fbuf_bucket_remove(fbuf);
			// init parent, child_cnt and ma before inserting to bucket FBUF_BUCKET_LAST
			fbuf->parent = NULL;
			fbuf->child_cnt = 0;
			fbuf->ma.uint32 = META_INVALID;
			fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			fbuf->fc.accessed = false; // so it will be recycled sooner
			if (fbuf->queue_which != QUEUE_F0_CLEAN) {
				// it is an internal node, move it to QUEUE_F0_CLEAN
				MY_ASSERT(fbuf->queue_which != QUEUE_F0_DIRTY);
				fbuf_queue_remove(sc, fbuf);
				fbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fbuf);
			}
		}
	}
}

static void
fbuf_queue_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf_sentinel *queue_head;

	MY_ASSERT(which < QUEUE_CNT);
	sc->fbuf_queue_len[which] = 0;
	queue_head = &sc->fbuf_queue[which];
	queue_head->fc.queue_next = (struct _fbuf *)queue_head;
	queue_head->fc.queue_prev = (struct _fbuf *)queue_head;
	queue_head->fc.is_sentinel = true;
	queue_head->fc.accessed = true;
	queue_head->fc.modified = false;
}

static void
fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *queue_head;
	struct _fbuf *prev;

	MY_ASSERT(which < QUEUE_CNT);
	MY_ASSERT(which != QUEUE_F0_CLEAN || !fbuf->fc.modified);
	fbuf->queue_which = which;
	queue_head = &sc->fbuf_queue[which];
	prev = queue_head->fc.queue_prev;
	MY_ASSERT(prev->fc.is_sentinel || prev->queue_which == which);
	queue_head->fc.queue_prev = fbuf;
	fbuf->fc.queue_next = (struct _fbuf *)queue_head;
	fbuf->fc.queue_prev = prev;
	prev->fc.queue_next = fbuf;
	++sc->fbuf_queue_len[which];
}

static void
fbuf_queue_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;
	int which = fbuf->queue_which;

	MY_ASSERT(fbuf != (struct _fbuf *)&sc->fbuf_queue[which]);
	prev = fbuf->fc.queue_prev;
	next = fbuf->fc.queue_next;
	MY_ASSERT(prev->fc.is_sentinel || prev->queue_which == which);
	MY_ASSERT(next->fc.is_sentinel || next->queue_which == which);
	prev->fc.queue_next = next;
	next->fc.queue_prev = prev;
	--sc->fbuf_queue_len[which];
}

// insert to the head of the hashed bucket
static void
fbuf_hash_insert_head(struct g_logstor_softc *sc, struct _fbuf *fbuf, union meta_addr ma)
{
	unsigned hash;

	fbuf->ma = ma;
	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = ma.uint32 % FBUF_BUCKET_LAST;
	fbuf_bucket_insert_head(sc, hash, fbuf);
}

static void
fbuf_bucket_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf_sentinel *bucket_head;

#if defined(MY_DEBUG)
	MY_ASSERT(which < FBUF_BUCKET_CNT);
	sc->fbuf_bucket_len[which] = 0;
#endif
	bucket_head = &sc->fbuf_bucket[which];
	bucket_head->fc.queue_next = (struct _fbuf *)bucket_head;
	bucket_head->fc.queue_prev = (struct _fbuf *)bucket_head;
	bucket_head->fc.is_sentinel = true;
}

static void
fbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *bucket_head;
	struct _fbuf *next;

#if defined(MY_DEBUG)
	MY_ASSERT(which < FBUF_BUCKET_CNT);
	fbuf->bucket_which = which;
	++sc->fbuf_bucket_len[which];
#endif
	bucket_head = &sc->fbuf_bucket[which];
	next = bucket_head->fc.queue_next;
	bucket_head->fc.queue_next = fbuf;
	fbuf->bucket_next = next;
	fbuf->bucket_prev = (struct _fbuf *)bucket_head;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = fbuf;
	else
		next->bucket_prev = fbuf;
}

static void
fbuf_bucket_remove(struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;

	MY_ASSERT(!fbuf->fc.is_sentinel);
	prev = fbuf->bucket_prev;
	next = fbuf->bucket_next;
	if (prev->fc.is_sentinel)
		prev->fc.queue_next = next;
	else
		prev->bucket_next = next;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = prev;
	else
		next->bucket_prev = prev;
}

/*
Description:
    Search the file buffer with the tag value of @ma. Return NULL if not found
*/
static struct _fbuf *
fbuf_search(struct g_logstor_softc *sc, union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf	*fbuf;
	struct _fbuf_sentinel	*bucket_sentinel;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = ma.uint32 % FBUF_BUCKET_LAST;
	bucket_sentinel = &sc->fbuf_bucket[hash];
	fbuf = bucket_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)bucket_sentinel) {
		if (fbuf->ma.uint32 == ma.uint32) { // cache hit
			++sc->fbuf_hit;
			return fbuf;
		}
		fbuf = fbuf->bucket_next;
	}
	++sc->fbuf_miss;
	return NULL;	// cache miss
}

// convert from depth to queue number
static const int d2q[] = {QUEUE_F2, QUEUE_F1, QUEUE_F0_DIRTY};

/*
Description:
  using the second chance replace policy to choose a fbuf in QUEUE_F0_CLEAN
*/
struct _fbuf *
fbuf_alloc(struct g_logstor_softc *sc, union meta_addr ma, int depth)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf, *parent;

	MY_ASSERT(depth <= META_LEAF_DEPTH);
	queue_sentinel = &sc->fbuf_queue[QUEUE_F0_CLEAN];
	fbuf = sc->fbuf_allocp;
again:
	while (true) {
		if (!fbuf->fc.accessed)
			break;

		fbuf->fc.accessed = false;	// give this fbuf a second chance
		fbuf = fbuf->fc.queue_next;
	}
	if (fbuf == (struct _fbuf *)queue_sentinel) {
		fbuf->fc.accessed = true;
		fbuf = fbuf->fc.queue_next;
		MY_ASSERT(fbuf != (struct _fbuf *)queue_sentinel);
		goto again;
	}

	MY_ASSERT(!fbuf->fc.modified);
	MY_ASSERT(fbuf->child_cnt == 0);
	sc->fbuf_allocp = fbuf->fc.queue_next;
	if (depth != META_LEAF_DEPTH) {
		// for fbuf allocated for internal nodes insert it immediately
		// to its internal queue
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, d2q[depth], fbuf);
	}
	fbuf_bucket_remove(fbuf);
	fbuf_hash_insert_head(sc, fbuf, ma);
	parent = fbuf->parent;
	if (parent) {
		// parent with child_cnt == 0 will stay in its queue
		// it will only be moved to QUEUE_F0_CLEAN in fbuf_clean_queue_check()
		--parent->child_cnt;
		MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
		MY_ASSERT(parent->queue_which == d2q[parent->ma.depth]);
	}
	return fbuf;
}

/*
Description:
    Read or write the file buffer with metadata address @ma
*/
static struct _fbuf *
fbuf_access(struct g_logstor_softc *sc, union meta_addr ma)
{
	uint32_t sa;	// sector address where the metadata is stored
	unsigned index;
	union meta_addr	ima;	// the intermediate metadata address
	struct _fbuf *parent;	// parent buffer
	struct _fbuf *fbuf;
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);

	MY_ASSERT(IS_META_ADDR(ma.uint32));
	MY_ASSERT(ma.depth <= META_LEAF_DEPTH);

	// get the root sector address of the file %ma.fd
	sa = sc->superblock.fh[ma.fd].root;
	MY_ASSERT(sa != SECTOR_DEL);

	fbuf = fbuf_search(sc, ma);
	if (fbuf != NULL) // cache hit
		goto end;

	// cache miss
	parent = NULL;	// parent for root is NULL
	ima = (union meta_addr){.meta = 0xFF};	// set .meta to 0xFF and all others to 0
	ima.fd = ma.fd;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		ima.depth = i;
		fbuf = fbuf_search(sc, ima);
		if (fbuf == NULL) {
			fbuf = fbuf_alloc(sc, ima, i);	// allocate a fbuf from clean queue
			fbuf->parent = parent;
			if (parent) {
				// parent with child_cnt == 0 will stay in its queue
				// it will only be moved to QUEUE_F0_CLEAN in fbuf_clean_queue_check()
				++parent->child_cnt;
				MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
			} else {
				MY_ASSERT(i == 0);
			}
			if (sa == SECTOR_NULL) {
				bzero(fbuf->data, sizeof(fbuf->data));
				if (i == 0)
					sc->superblock.fh[ma.fd].root = SECTOR_CACHE;
			} else {
				MY_ASSERT(sa >= SECTORS_PER_SEG);
				md_read(cp, fbuf->data, sa);
			}
#if defined(MY_DEBUG)
			fbuf->sa = sa;
			if (parent)
				parent->child[index] = fbuf;
#endif
		} else {
			MY_ASSERT(fbuf->parent == parent);
			MY_ASSERT(fbuf->sa == sa ||
				(i == 0 && sa == SECTOR_CACHE));
		}
		if (i == ma.depth) // reach the intended depth
			break;

		parent = fbuf;		// %fbuf is the parent of next level indirect block
		index = ma_index_get(ma, i);// the index to next level's indirect block
		sa = parent->data[index];	// the sector address of the next level indirect block
		ima = ma_index_set(ima, i, index); // set the next level's index for @ima
	} // for
end:
	fbuf->fc.accessed = true;
	return fbuf;
}

static void
fbuf_write(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	struct _fbuf *parent;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address

	MY_ASSERT(fbuf->fc.modified);
	sa = logstor_write(sc, fbuf->ma.uint32, fbuf->data);
#if defined(MY_DEBUG)
	fbuf->sa = sa;
#endif
	fbuf->fc.modified = false;

	// update the sector address of this fbuf in its parent's fbuf
	parent = fbuf->parent;
	if (parent) {
		MY_ASSERT(fbuf->ma.depth != 0);
		MY_ASSERT(parent->ma.depth == fbuf->ma.depth - 1);
		pindex = ma_index_get(fbuf->ma, fbuf->ma.depth - 1);
		parent->data[pindex] = sa;
		parent->fc.modified = true;
	} else {
		MY_ASSERT(fbuf->ma.depth == 0);
		// store the root sector address to the corresponding file table in super block
		sc->superblock.fh[fbuf->ma.fd].root = sa;
		sc->sb_modified = true;
	}
}

#if defined(MY_DEBUG)
static void
logstor_hash_check(struct g_logstor_softc *sc)
{
	struct _fbuf *fbuf;
	struct _fbuf_sentinel *bucket_sentinel;
	int total = 0;

	for (int i = 0; i < FBUF_BUCKET_CNT; ++i)
	{
		bucket_sentinel = &sc->fbuf_bucket[i];
		fbuf = bucket_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)bucket_sentinel) {
			++total;
			MY_ASSERT(!fbuf->fc.is_sentinel);
			MY_ASSERT(fbuf->bucket_which == i);
			if (i == FBUF_BUCKET_LAST)
				MY_ASSERT(fbuf->ma.uint32 == META_INVALID);
			else
				MY_ASSERT(fbuf->ma.uint32 % FBUF_BUCKET_LAST == i);
			fbuf = fbuf->bucket_next;
		}
	}
	MY_ASSERT(total == sc->fbuf_count);
}

static void
logstor_queue_check(struct g_logstor_softc *sc)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;
	unsigned count[QUEUE_CNT];

	// set debug child count of internal nodes to 0
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(d2q[fbuf->ma.depth] == q);
			fbuf->dbg_child_cnt = 0; // set the child count to 0
			fbuf = fbuf->fc.queue_next;
		}
	}
	// check queue length and calculate the child count
	//int root_cnt = 0;
	for (int q = 0; q < QUEUE_CNT ; ++q) {
		count[q] = 0;
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			++count[q];
			MY_ASSERT(fbuf->queue_which == q);
			if (q == QUEUE_CNT-1) {
				MY_ASSERT(fbuf->parent == NULL);
				//++root_cnt;
			} else
				MY_ASSERT(fbuf->ma.uint32 == META_INVALID || fbuf->parent != NULL);
			if (fbuf->parent)
				++fbuf->parent->dbg_child_cnt; // increment parent's debug child count

			fbuf = fbuf->fc.queue_next;
		}
		MY_ASSERT(sc->fbuf_queue_len[q] == count[q]);
	}
	// check that the debug child count of internal nodes is correct
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->dbg_child_cnt == fbuf->child_cnt);
			fbuf = fbuf->fc.queue_next;
		}
	}
	int total = 0;
	for (int q = 0; q < QUEUE_CNT; ++q)
		total += count[q];

	MY_ASSERT(total == sc->fbuf_count);
}

static uint32_t
sa2ba(struct g_logstor_softc *sc, uint32_t sa)
{
	static uint32_t seg_sum_cache_sa;
	static struct _seg_sum seg_sum_cache;
	uint32_t seg_sa;
	unsigned seg_off;

	seg_sa = sa & ~(SECTORS_PER_SEG - 1);
	seg_off = sa & (SECTORS_PER_SEG - 1);
	MY_ASSERT(seg_sa != 0 || seg_off >= SB_CNT);
	MY_ASSERT(seg_off != SEG_SUM_OFFSET);
	if (seg_sa != seg_sum_cache_sa) {
		struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
		md_read(cp, &seg_sum_cache, seg_sa + SEG_SUM_OFFSET);
		seg_sum_cache_sa = seg_sa;
	}
	return (seg_sum_cache.ss_rm[seg_off]);
}

/*
Description:
  Check the integrity of the logstor
*/
void
logstor_check(struct g_logstor_softc *sc)
{
	uint32_t block_cnt;

	printf("%s ...\n", __func__);
	block_cnt = sc->superblock.block_cnt;
	MY_ASSERT(block_cnt < BLOCK_MAX);
	for (uint32_t ba = 0; ba < block_cnt; ++ba) {
		uint32_t sa = sc->ba2sa_fp(sc, ba);
#if defined(WYC)
		ba2sa_normal();
		ba2sa_during_snapshot();
#endif
		if (sa != SECTOR_NULL) {
			uint32_t ba_exp = sa2ba(sc, sa);
			if (ba_exp != ba) {
				printf("ERROR %s: ba %u sa %u ba_exp %u\n",
				    __func__, ba, sa, ba_exp);
				MY_PANIC();
			}
		}
	}
	printf("%s done.\n\n", __func__);
}
#endif


//==============================================
static void g_logstor_start(struct bio *bp);
static int g_logstor_access(struct g_provider *pp, int dr, int dw, int de);
static void g_logstor_orphan(struct g_consumer *cp);
static int g_logstor_destroy(struct g_logstor_softc *sc, boolean_t force);
static int g_logstor_destroy_geom(struct gctl_req *req, struct g_class *mp,
    struct g_geom *gp);
#if !defined(WYC)
static g_ctl_req_t g_logstor_config;
static g_taste_t g_logstor_taste;
static g_dumpconf_t g_logstor_dumpconf;
#endif

struct g_class g_logstor_class = {
	.name = G_LOGSTOR_CLASS_NAME,
	.version = G_VERSION,
	.ctlreq = g_logstor_config,
	.taste = g_logstor_taste,
	.destroy_geom = g_logstor_destroy_geom
};

static void
g_logstor_orphan(struct g_consumer *cp)
{
	struct g_logstor_softc *sc;
	//struct g_logstor_disk *disk;
	struct g_geom *gp;

	g_topology_assert();
	gp = cp->geom;
	sc = gp->softc;
	if (sc == NULL)
		return;

	//disk = cp->private;
	//if (disk == NULL)	/* Possible? */
	//	return;
	//g_logstor_remove_disk(disk);
}

static int
g_logstor_access(struct g_provider *pp, int dr, int dw, int de)
{
	struct g_geom *gp;
	//struct g_logstor_softc *sc;
	int error;

	g_topology_assert();
	gp = pp->geom;
	//sc = gp->softc;

	/* On first open, grab an extra "exclusive" bit */
	if (pp->acr == 0 && pp->acw == 0 && pp->ace == 0)
		de++;
	/* ... and let go of it on last close */
	if ((pp->acr + dr) == 0 && (pp->acw + dw) == 0 && (pp->ace + de) == 0)
		de--;

	struct g_consumer *cp = LIST_FIRST(&gp->consumer);
	error = g_access(cp, dr, dw, de);
	return (error);
}

static void
g_logstor_kernel_dump(struct bio *bp)
{
	struct g_logstor_softc *sc;
	struct bio *cbp;
	//struct g_kerneldump *gkd;

	sc = bp->bio_to->geom->softc;
	//gkd = (struct g_kerneldump *)bp->bio_data;

	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		g_io_deliver(bp, ENOMEM);
		return;
	}
	cbp->bio_done = g_std_done;
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	g_io_request(cbp, cp);
	G_LOGSTOR_DEBUG(1, "Kernel dump will go to %s.",
	    cp->provider->name);
#if 0
	struct g_logstor_softc *sc;
	struct g_logstor_disk *disk;
	struct bio *cbp;
	struct g_kerneldump *gkd;

	sc = bp->bio_to->geom->softc;
	gkd = (struct g_kerneldump *)bp->bio_data;
	TAILQ_FOREACH(disk, &sc->sc_disks, d_next) {
		if (disk->d_start <= gkd->offset &&
		    disk->d_end > gkd->offset)
			break;
	}
	if (disk == NULL) {
		g_io_deliver(bp, EOPNOTSUPP);
		return;
	}

	gkd->offset -= disk->d_start;
	if (gkd->length > disk->d_end - disk->d_start - gkd->offset)
		gkd->length = disk->d_end - disk->d_start - gkd->offset;
	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		g_io_deliver(bp, ENOMEM);
		return;
	}
	cbp->bio_done = g_std_done;
	g_io_request(cbp, disk->d_consumer);
	G_LOGSTOR_DEBUG(1, "Kernel dump will go to %s.",
	    disk->d_consumer->provider->name);
#endif
}

/*
 * Called for both BIO_FLUSH and BIO_SPEEDUP. Just pass the call down
 */
static void
g_logstor_passdown(struct g_logstor_softc *sc, struct bio *bp)
{
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	struct bio *cbp;

	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		if (bp->bio_error == 0)
			bp->bio_error = ENOMEM;
		g_io_deliver(bp, bp->bio_error);
		return;
	}
	cbp->bio_done = g_std_done;

	G_LOGSTOR_LOGREQ(cbp, "Sending request.");
	g_io_request(cbp, cp);
#if 0
	struct bio_queue_head queue;
	struct g_consumer *cp;
	struct bio *cbp;
	struct g_logstor_disk *disk;

	sx_assert(&sc->sc_disks_lock, SX_LOCKED);

	bioq_init(&queue);
	TAILQ_FOREACH(disk, &sc->sc_disks, d_next) {
		cbp = g_clone_bio(bp);
		if (cbp == NULL) {
			while ((cbp = bioq_takefirst(&queue)) != NULL)
				g_destroy_bio(cbp);
			if (bp->bio_error == 0)
				bp->bio_error = ENOMEM;
			g_io_deliver(bp, bp->bio_error);
			return;
		}
		bioq_insert_tail(&queue, cbp);
		cbp->bio_done = g_logstor_done;
		cbp->bio_caller1 = disk->d_consumer;
		cbp->bio_to = disk->d_consumer->provider;
	}
	while ((cbp = bioq_takefirst(&queue)) != NULL) {
		G_LOGSTOR_LOGREQ(cbp, "Sending request.");
		cp = cbp->bio_caller1;
		cbp->bio_caller1 = NULL;
		g_io_request(cbp, cp);
	}
#endif
}

static void
g_logstor_start(struct bio *bp)
{
	// function pointer for get sector address
	uint32_t (*get_sa_fp)(struct g_logstor_softc *sc, unsigned ba);

	struct g_provider *pp = bp->bio_to;
	struct g_logstor_softc *sc = pp->geom->softc;
	/*
	 * If sc == NULL, provider's error should be set and g_logstor_start()
	 * should not be called at all.
	 */
	KASSERT(sc != NULL,
	    ("Provider's error should be set (error=%d)(device=%s).",
	    pp->error, pp->name));

	G_LOGSTOR_LOGREQ(bp, "Request received.");

	switch (bp->bio_cmd) {
	case BIO_READ:
		get_sa_fp = sc->ba2sa_fp;
		break;
	case BIO_WRITE:
		get_sa_fp = sec_alloc_for_write;
		break;
	case BIO_DELETE:
		logstor_delete(sc, bp);
		goto exit;
	case BIO_SPEEDUP:
	case BIO_FLUSH:
		g_logstor_passdown(sc, bp);
		goto exit;
	case BIO_GETATTR:
		if (strcmp("GEOM::candelete", bp->bio_attribute) == 0) {
			int val = false;
			g_handleattr(bp, "GEOM::candelete", &val, sizeof(val));
			goto exit;
		} else if (strcmp("GEOM::kerneldump", bp->bio_attribute) == 0) {
			printf("kerneldump not supported\n");
		}
		/* To which provider it should be delivered? */
		/* FALLTHROUGH */
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		goto exit;
	}

	struct bio_queue_head queue;
	struct bio *cbp;
	char *addr;
	off_t offset = bp->bio_offset;
	off_t length = bp->bio_length;
	MY_ASSERT(offset % SECTOR_SIZE == 0);
	MY_ASSERT(length % SECTOR_SIZE == 0);

	if ((bp->bio_flags & BIO_UNMAPPED) != 0)
		addr = NULL;
	else
		addr = bp->bio_data;

	fbuf_clean_queue_check(sc);
	bioq_init(&queue);
	uint32_t ba_start = offset / SECTOR_SIZE;
	for (int i = 0; i < length / SECTOR_SIZE; ++i) {
		cbp = g_clone_bio(bp);
		if (cbp == NULL) {
			while ((cbp = bioq_takefirst(&queue)) != NULL)
				g_destroy_bio(cbp);
			if (bp->bio_error == 0)
				bp->bio_error = ENOMEM;
			g_io_deliver(bp, bp->bio_error);
			goto exit;
		}
		bioq_insert_tail(&queue, cbp);
		uint32_t sa = get_sa_fp(sc, ba_start + i);
#if defined(WYC)
		ba2sa_during_snapshot();
		ba2sa_normal();
		sec_alloc_for_write();
#endif
		/*
		 * Fill in the component buf structure.
		 */
		cbp->bio_done = g_std_done;
		cbp->bio_offset =  (off_t)sa * SECTOR_SIZE;
		cbp->bio_length = SECTOR_SIZE;
		if ((bp->bio_flags & BIO_UNMAPPED) != 0) {
			cbp->bio_ma_offset += (uintptr_t)addr;
			cbp->bio_ma += cbp->bio_ma_offset / PAGE_SIZE;
			cbp->bio_ma_offset %= PAGE_SIZE;
			cbp->bio_ma_n = round_page(cbp->bio_ma_offset +
			    cbp->bio_length) / PAGE_SIZE;
			MY_ASSERT(cbp->bio_ma_n == 1);
		} else
			cbp->bio_data = addr;
		addr += SECTOR_SIZE;
	}
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	while ((cbp = bioq_takefirst(&queue)) != NULL) {
		if (cbp->bio_offset == SECTOR_NULL) {
			MY_ASSERT(cbp->bio_cmd == BIO_READ);
			if ((cbp->bio_flags & BIO_UNMAPPED) != 0) {
				void pmap_zero_page_area(vm_page_t m, int off, int size);
				pmap_zero_page_area(*cbp->bio_ma,
				    cbp->bio_ma_offset, SECTOR_SIZE);
			} else {
				bzero(cbp->bio_data, SECTOR_SIZE);
			}
			cbp->bio_completed = SECTOR_SIZE;
			cbp->bio_error = 0;
			g_std_done(cbp);
		} else {
			G_LOGSTOR_LOGREQ(cbp, "Sending request.");
			g_io_request(cbp, cp);
		}
	}
exit:
	;
}

static struct g_geom *
g_logstor_create(struct g_class *mp, struct g_provider *pp, struct _superblock *sb, uint32_t sb_sa)
{
	struct g_logstor_softc *sc;
	struct g_geom *gp;
	char name[32];

	int n = snprintf(name, sizeof(name), "%s%s", pp->name, G_LOGSTOR_SUFFIX);
	if (n <= 0 || n >= sizeof(name)) {
		//gctl_error(req, "Invalid provider name.");
		return NULL;
	}
	G_LOGSTOR_DEBUG(1, "Creating device %s.", name);

	/* Check for duplicate unit */
	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc != NULL && strcmp(gp->name, name) == 0) {
			MY_ASSERT(sc->sc_geom == gp);
			G_LOGSTOR_DEBUG(0, "Device %s already configured.",
			    gp->name);
			return (NULL);
		}
	}
	gp = g_new_geom(mp, name);
	sc = malloc(sizeof(*sc), M_LOGSTOR, M_WAITOK | M_ZERO);
	sc->sc_geom = gp;
	gp->start = g_logstor_start;
	gp->spoiled = g_logstor_orphan;
	gp->orphan = g_logstor_orphan;
	gp->access = g_logstor_access;
	gp->dumpconf = g_logstor_dumpconf;

	struct g_provider *newpp = g_new_provider(gp, gp->name);
	newpp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE;
	newpp->flags |= (pp->flags & G_PF_ACCEPT_UNMAPPED);
	newpp->sectorsize = SECTOR_SIZE;
	newpp->mediasize = (off_t)sb->block_cnt * SECTOR_SIZE;

	struct g_consumer *cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	int error = g_attach(cp, pp);
	if (error) {
		//gctl_error(req, "Error %d: cannot attach to provider %s.",
		//    error, lowerpp->name);
		goto fail;
	}
	logstor_init(sc, sb, sb_sa);
	g_error_provider(newpp, 0);
	gp->softc = sc;
	G_LOGSTOR_DEBUG(0, "Device %s created.", gp->name);

	return (gp);
fail:
	g_destroy_consumer(cp);
	g_destroy_provider(newpp);
	free(sc, M_LOGSTOR);
	g_destroy_geom(gp);
	return NULL;
}

static int
g_logstor_destroy(struct g_logstor_softc *sc, boolean_t force)
{
	struct g_geom *gp;
	struct g_provider *pp;
	struct g_consumer *cp;

	g_topology_assert();

	if (sc == NULL)
		return (ENXIO);

	gp = sc->sc_geom;
	gp->softc = NULL;
	pp = LIST_FIRST(&gp->provider);
	if (pp != NULL && (pp->acr != 0 || pp->acw != 0 || pp->ace != 0)) {
		if (force) {
			G_LOGSTOR_DEBUG(0, "Device %s is still open, so it "
			    "can't be definitely removed.", pp->name);
		} else {
			G_LOGSTOR_DEBUG(1,
			    "Device %s is still open (r%dw%de%d).", pp->name,
			    pp->acr, pp->acw, pp->ace);
			return (EBUSY);
		}
	}
	G_LOGSTOR_DEBUG(0, "Device %s deactivated.", sc->sc_geom->name);
	g_wither_provider(pp, ENXIO);
	logstor_close(sc);
	free(sc, M_LOGSTOR);

	cp = LIST_FIRST(&gp->consumer);
	g_detach(cp);
	g_destroy_consumer(cp);

	G_LOGSTOR_DEBUG(0, "Device %s destroyed.", gp->name);
	g_wither_geom(gp, ENXIO);
	return (0);
}

static int
g_logstor_destroy_geom(struct gctl_req *req __unused,
    struct g_class *mp __unused, struct g_geom *gp)
{
	struct g_logstor_softc *sc;

	sc = gp->softc;
	return (g_logstor_destroy(sc, 0));
}

static struct g_geom *
g_logstor_taste(struct g_class *mp, struct g_provider *pp, int flags __unused)
{
	struct _superblock *sb;
	struct g_consumer *cp;
	struct g_geom *gp;
	int error;
	uint32_t sb_sa;

	g_trace(G_T_TOPOLOGY, "%s(%s, %s)", __func__, mp->name, pp->name);
	g_topology_assert();

	/* Skip providers that are already open for writing. */
	if (pp->acw > 0)
		return (NULL);

	G_LOGSTOR_DEBUG(3, "Tasting %s.", pp->name);

	gp = g_new_geom(mp, "logstor:taste");
	gp->start = g_logstor_start;
	gp->access = g_logstor_access;
	gp->orphan = g_logstor_orphan;
	cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	error = g_attach(cp, pp);
	if (!error) {
		sb = superblock_read(cp, &sb_sa);
		g_detach(cp);
	}
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	if (error || sb == NULL) {
		return (NULL);
	}
	if (sb->provsize != pp->mediasize) {
		gp = NULL;
		goto fail;
	}
	gp = g_logstor_create(mp, pp, sb, sb_sa);
	free(sb, M_LOGSTOR);
	if (gp == NULL) {
		G_LOGSTOR_DEBUG(0, "Cannot create device %s.",
		    sb->name);
		goto fail;
	}
#if defined(MY_DEBUG)
	//logstor_check(sc);
#endif

fail:
	free(sb, M_LOGSTOR);
	return (gp);
}

static struct g_logstor_softc *
g_logstor_find_device(struct g_class *mp, const char *name)
{
	struct g_logstor_softc *sc;
	struct g_geom *gp;

	if (strncmp(name, _PATH_DEV, strlen(_PATH_DEV)) == 0)
		name += strlen(_PATH_DEV);

	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc == NULL)
			continue;
		MY_ASSERT(sc->sc_geom == gp);
		if (strcmp(gp->name, name) == 0)
			return (sc);
	}
	return (NULL);
}

static void
g_logstor_ctl_create(struct gctl_req *req, struct g_class *mp)
{

	g_topology_assert();
	int *nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Only accept 1 parameter.");
		return;
	}
	struct g_provider *pp = gctl_get_provider(req, "arg0");
	if (pp == NULL)
		return;
	uint32_t sb_sa;
	struct _superblock *sb = disk_init(mp, pp, &sb_sa);
	if (sb == NULL)
		return;
	struct g_geom *gp = g_logstor_create(mp, pp, sb, sb_sa);
	free(sb, M_LOGSTOR);
	if (gp == NULL) {
		gctl_error(req, "Can't configure %s.", pp->name);
		return;
	}
	free(sb, M_LOGSTOR);
}

static void
g_logstor_ctl_destroy(struct gctl_req *req, struct g_class *mp)
{
	struct g_logstor_softc *sc;
	int *force, *nargs, error;
	const char *name;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Only accept 1 parameter.");
		return;
	}
	force = gctl_get_paraml(req, "force", sizeof(*force));
	if (force == NULL) {
		gctl_error(req, "No '%s' argument.", "force");
		return;
	}

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg0' argument.");
		return;
	}
	sc = g_logstor_find_device(mp, name);
	if (sc == NULL) {
		gctl_error(req, "No such device: %s.", name);
		return;
	}
	error = g_logstor_destroy(sc, *force);
	if (error != 0) {
		gctl_error(req, "Cannot destroy device %s (error=%d).",
		    sc->sc_geom->name, error);
		return;
	}
}

static void
g_logstor_ctl_snapshot(struct gctl_req *req, struct g_class *mp)
{
	struct g_logstor_softc *sc;
	int *nargs;
	const char *name;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Only accept 1 parameter.");
		return;
	}

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg0' argument.");
		return;
	}
	sc = g_logstor_find_device(mp, name);
	if (sc == NULL) {
		gctl_error(req, "No such device: %s.", name);
		return;
	}
	logstor_snapshot(sc);
}

static void
g_logstor_ctl_rollback(struct gctl_req *req, struct g_class *mp)
{
	struct g_logstor_softc *sc;
	int *nargs;
	const char *name;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Only accept 1 parameter.");
		return;
	}

	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg0' argument.");
		return;
	}
	sc = g_logstor_find_device(mp, name);
	if (sc == NULL) {
		gctl_error(req, "No such device: %s.", name);
		return;
	}
	logstor_rollback(sc);
}

static void
g_logstor_config(struct gctl_req *req, struct g_class *mp, const char *verb)
{
	uint32_t *version;

	g_topology_assert();

	version = gctl_get_paraml(req, "version", sizeof(*version));
	if (version == NULL) {
		gctl_error(req, "No '%s' argument.", "version");
		return;
	}
	if (*version != G_LOGSTOR_VERSION) {
		gctl_error(req, "Userland and kernel parts are out of sync.");
		return;
	}

	if (strcmp(verb, "create") == 0) {
		g_logstor_ctl_create(req, mp);
	} else if (strcmp(verb, "destroy") == 0 || strcmp(verb, "stop") == 0) {
		g_logstor_ctl_destroy(req, mp);
	} else if (strcmp(verb, "snapshot") == 0) {
		g_logstor_ctl_snapshot(req, mp);
	} else if (strcmp(verb, "rollback") == 0) {
		g_logstor_ctl_rollback(req, mp);
	} else
		gctl_error(req, "Unknown verb.");
}

static void
g_logstor_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
	struct g_logstor_softc *sc;

	g_topology_assert();
	sc = gp->softc;
	if (sc == NULL)
		return;
#if 0
	if (pp != NULL) {
		/* Nothing here. */
	} else if (cp != NULL) {
		struct g_logstor_disk *disk;

		disk = cp->private;
		if (disk == NULL)
			goto end;
		sbuf_printf(sb, "%s<End>%jd</End>\n", indent,
		    (intmax_t)disk->d_end);
		sbuf_printf(sb, "%s<Start>%jd</Start>\n", indent,
		    (intmax_t)disk->d_start);
	} else {
		sbuf_printf(sb, "%s<ID>%u</ID>\n", indent, (u_int)sc->sc_id);
		sbuf_printf(sb, "%s<Type>", indent);
		switch (sc->sc_type) {
		case G_LOGSTOR_TYPE_AUTOMATIC:
			sbuf_cat(sb, "AUTOMATIC");
			break;
		case G_LOGSTOR_TYPE_MANUAL:
			sbuf_cat(sb, "MANUAL");
			break;
		default:
			sbuf_cat(sb, "UNKNOWN");
			break;
		}
		sbuf_cat(sb, "</Type>\n");
		sbuf_printf(sb, "%s<Status>Total=%u, Online=%u</Status>\n",
		    indent, sc->sc_ndisks, g_logstor_nvalid(sc));
		sbuf_printf(sb, "%s<State>", indent);
		//if (sc->sc_provider != NULL && sc->sc_provider->error == 0)
		//	sbuf_cat(sb, "UP");
		//else
			sbuf_cat(sb, "DOWN");
		sbuf_cat(sb, "</State>\n");
	}
end:
	;
#endif
}

DECLARE_GEOM_CLASS(g_logstor_class, g_logstor);
MODULE_VERSION(geom_logstor, 0);
