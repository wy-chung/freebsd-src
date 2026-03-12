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

static
void my_break(void) //__attribute__((optnone))
{
}

#define MY_DEBUG
#define MY_PANIC()	panic("panic: %s %d %s\n", __FILE__, __LINE__, __func__)
#define MY_ASSERT(x)\
    do\
	if (!(x)) {\
	    my_break();\
	    panic("assert fail: %s %d %s\n", __FILE__, __LINE__, __func__);\
	}\
    while(0)

#define G_LOGSTOR_SUFFIX	".logstor"

//===========================================
#define	FMBUF_ADDR_START	(((union fmbuf_addr){.xFF = 0xFF}).uint32)	// fmbuf block address start
#define	IS_FMBUF_ADDR(x)	((x) >= FMBUF_ADDR_START)

#define FMBUF_CLEAN_THRESHOLD	32
#define FMBUF_MIN	1564
#define FMBUF_MAX	(FMBUF_MIN * 2)
// the last bucket is reserved for queuing fmbufs that will not be searched
#define FMBUF_BUCKET_LAST 953	// this should be a prime number
#define FMBUF_BUCKET_CNT	(FMBUF_BUCKET_LAST+1)

/*
  Forward map and its indirect blocks are also stored in the downstream disk.
  The sectors used to store the forward map and its indirect blocks are called metadata.

  Each metadata block (fmbuf) has a corresponding metadata address.
  Below is the format of the metadata address.

  For block address that is >= FMBUF_ADDR_START, it is actually a metadata address.
*/
#define FMBUF_LEAF_DEPTH	2	// leaf page depth of forward map
#define IDX_BITS	10	// number of index bits
union fmbuf_addr { // metadata address for fmbuf
	uint32_t	uint32;
	struct {
		uint32_t index1 :IDX_BITS;	// index for indirect block of depth 1
		uint32_t index0 :IDX_BITS;	// index for indirect block of depth 0
		uint32_t depth	:2;	// depth of the fmbuf
		uint32_t fm	:2;	// forward map number
		uint32_t xFF	:8;	// 0xFF for metadata address
	};
	struct {
		uint32_t index :IDX_BITS*2;	// index for indirect blocks
	};
};

_Static_assert(sizeof(union fmbuf_addr) == 4, "The size of emta_addr must be 4");

// when processing queues, we always process it from the leaf to root
// so leaf has lower queue number
enum queue_floor : uint8_t {
	QUEUE_F0_CLEAN,	// floor 0, clean queue
	QUEUE_F0_DIRTY,	// floor 0, dirty queue
	QUEUE_F1,	// floor 1
	QUEUE_F2,	// floor 2
	QUEUE_CNT,
};

struct fmbuf_comm {	// common part of fmbuf and fmbuf_sentinel
	struct _fmbuf *queue_next;
	struct _fmbuf *queue_prev;
	uint8_t is_sentinel:1;
	uint8_t accessed:1;	/* only used for fmbufs on circular queue */
	uint8_t modified:1;	/* the fmbuf is dirty */
};

struct fmbuf_sentinel {	// the sentinel for fmbuf queue or bucket
	// if this is a sentinel for bucket queue
	// fc.queue_next is actually fc.bucket_next
	// fc.queue_prev is actually fc.bucket_prev
	struct fmbuf_comm fc;
};

/*
  Metadata is cached in memory. The access unit of metadata is block so each cache line
  stores a block of metadata
*/
typedef struct _fmbuf { // file buffer
	struct fmbuf_comm fc;
	// for bucket sentinel bucket_next is stored in fc.queue_next
	// for bucket sentinel bucket_prev is stored in fc.queue_prev
	struct _fmbuf *bucket_next;
	struct _fmbuf *bucket_prev;
	struct _fmbuf *parent;
	uint16_t child_cnt; // number of children reference this fmbuf
	enum queue_floor queue_which;
	union fmbuf_addr	ba;	// the block address for this fmbuf
#if defined(MY_DEBUG)
	uint16_t bucket_which;
	uint16_t index; // the array index for this fmbuf
	uint16_t dbg_child_cnt;
	uint32_t sa;	// the sector address of the @data
	struct _fmbuf *child[SECTOR_SIZE/sizeof(uint32_t)];
#endif
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
}fmbuf_t;

/*
	logstor soft control
*/
struct g_logstor_softc {
	struct g_geom	*sc_geom;
	bool (*is_sec_inuse_fp)(struct g_logstor_softc *sc, uint32_t ba_rev, uint32_t sa);
	uint32_t (*ba2sa_fp)(struct g_logstor_softc *sc, uint32_t ba);

	uint32_t sb_sa; 	// superblock's sector address
	struct _superblock superblock;
	struct _inv_map inv_map;	// inverse map for the current segment
	uint32_t inv_allocp;
	uint8_t inv_modified:1;	// is segment summary modified
	uint8_t sb_modified:1;	// is the super block modified

	uint32_t seg_allocp_start;// the starting segment for doing g_logstor_write
	uint32_t seg_allocp_sa;	// the sector address of the segment for allocation

	int fmbuf_count;
	fmbuf_t *fmbufs;	// an array of fmbufs
	fmbuf_t *fmbuf_allocp; // point to the fmbuf candidate for replacement
	struct fmbuf_sentinel fmbuf_queue[QUEUE_CNT];
	struct fmbuf_sentinel fmbuf_bucket[FMBUF_BUCKET_CNT]; // buffer hash queue
	int fmbuf_queue_len[QUEUE_CNT];
#if defined(MY_DEBUG)
	int fmbuf_bucket_len[FMBUF_BUCKET_CNT];
#endif
	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fmbuf_hit;
	unsigned fmbuf_miss;
};

/*******************************
 *        logstor              *
 *******************************/
static uint32_t g_logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data);
static uint32_t sec_alloc_for_write(struct g_logstor_softc *sc, uint32_t ba);

static void seg_alloc(struct g_logstor_softc *sc);
static void seg_sum_write(struct g_logstor_softc *sc);

static struct _superblock *superblock_read(struct g_consumer *cp, uint32_t *sb_sa);
static void superblock_write(struct g_logstor_softc *sc);

static fmbuf_t *fm_access_4byte(struct g_logstor_softc *sc, uint8_t fm, uint32_t offset, uint32_t *off_4byte);
static uint32_t fm_read_4byte(struct g_logstor_softc *sc, uint8_t fm, uint32_t ba);
static void fm_write_4byte(struct g_logstor_softc *sc, uint8_t fm, uint32_t ba, uint32_t sa);

static void fmbuf_mod_init(struct g_logstor_softc *sc);
static void fmbuf_mod_fini(struct g_logstor_softc *sc);
static void fmbuf_queue_init(struct g_logstor_softc *sc, int which);
static void fmbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, fmbuf_t *fmbuf);
static void fmbuf_queue_remove(struct g_logstor_softc *sc, fmbuf_t *fmbuf);
static fmbuf_t *fmbuf_search(struct g_logstor_softc *sc, union fmbuf_addr ba);
static void fmbuf_hash_insert_head(struct g_logstor_softc *sc, fmbuf_t *fmbuf, union fmbuf_addr ba);
static void fmbuf_bucket_init(struct g_logstor_softc *sc, int which);
static void fmbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, fmbuf_t *fmbuf);
static void fmbuf_bucket_remove(fmbuf_t *fmbuf);
static void fmbuf_write(struct g_logstor_softc *sc, fmbuf_t *fmbuf);
static fmbuf_t *fmbuf_alloc(struct g_logstor_softc *sc, union fmbuf_addr ba, int depth);
static fmbuf_t *fmbuf_access(struct g_logstor_softc *sc, union fmbuf_addr ba);
static void fmbuf_cache_flush(struct g_logstor_softc *sc);
static void fmbuf_cache_flush_and_invalidate_fm(struct g_logstor_softc *sc, int fm1, int fm2);
static void fmbuf_clean_queue_check(struct g_logstor_softc *sc);

static union fmbuf_addr fmbuf_ba2pba(union fmbuf_addr ba, unsigned *pindex_out);
static uint32_t fmbuf_ba2sa(struct g_logstor_softc *sc, union fmbuf_addr ba);

static uint32_t ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba);
static uint32_t ba2sa_during_snapshot(struct g_logstor_softc *sc, uint32_t ba);
static bool is_sec_inuse_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_inuse_during_snapshot(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
#if defined(WYC)//MY_DEBUG)
static void logstor_check(struct g_logstor_softc *sc);
#endif
static void md_read(struct g_consumer *cp, void *buf, uint32_t sa);
static void md_write(struct g_consumer *cp, void *buf, uint32_t sa);

// DON'T allocate a buffer on the stack because the kernel stack is very small
// (The size of the kenel stack is only 4 pages)
// The %buf here should only accept a buffer from malloc
static int
g_read_datab(struct g_consumer *cp, off_t offset, void *buf, off_t length) //wyctodo
{
	struct bio *bp;
	int errorc;

	KASSERT(length > 0 && length >= cp->provider->sectorsize &&
	    length <= maxphys, ("%s(): invalid length %jd", __func__,
	    (intmax_t)length));

	bp = g_alloc_bio();
	bp->bio_cmd = BIO_READ;
	bp->bio_done = NULL;
	bp->bio_offset = offset;
	bp->bio_length = length;
	bp->bio_data = buf;
	g_io_request(bp, cp);
	errorc = biowait(bp, "gread");
	if (errorc == 0 && bp->bio_completed != length)
		errorc = EIO;
	g_destroy_bio(bp);
	return (errorc);
}

static void
invalid_g_start(struct bio *bp __unused)
{
	printf("error %s: something is wrong here.", __func__);
}

static int
invalid_g_access(struct g_provider *gp __unused, int dr __unused, int dw __unused, int de __unused)
{
	printf("error %s: something is wrong here.", __func__);
	return 1;
}

static void
invalid_g_orphan(struct g_consumer *gc __unused)
{
	printf("error %s: something is wrong here.", __func__);
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
	struct _inv_map *inv_map;
	int error;
	uint32_t sector_cnt;

	struct _superblock *sb = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK | M_ZERO);
	sb->magic = G_LOGSTOR_MAGIC;
	sb->version = G_LOGSTOR_VERSION;
	sb->sb_gen = arc4random();
	sb->provsize = pp->mediasize;
	sector_cnt = pp->mediasize / SECTOR_SIZE;
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	sb->block_cnt = sb->seg_cnt * BLOCKS_PER_SEG - SB_CNT -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FM_COUNT * 4;
	MY_ASSERT(sb->block_cnt < 0x40000000); // 1G
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u block_cnt %u\n",
	    __func__, sector_cnt, sb->block_cnt);
#endif
	sb->seg_allocp = 0;	// segment allocation starts from here

	sb->fm_cur = 0;			// current mapping is file 0
	sb->fm_snap = 1;		// snapshot mapping is file 1
	sb->fm_prev = FM_INVALID;	// previous mapping does not eixt
	sb->fm_new_snap = FM_INVALID;	// snap_new mapping does not eixt

	sb->fmt[0].root = SECTOR_NULL;	// file 0 is all 0
	sb->fmt[0].written = 0;
	// files 1, 2 and 3: read returns 0 and write not allowed
	for (int i = 1; i < FM_COUNT; i++) {
		sb->fmt[i].root = SECTOR_DEL;	// the file does not exit
	}
	memset((char *)sb + sizeof(*sb), 0, SECTOR_SIZE - sizeof(*sb));

	struct g_geom *gp = g_new_geomf(mp, "logstor:init");
	gp->start = invalid_g_start;
	gp->access = invalid_g_access;
	gp->orphan = invalid_g_orphan;
	struct g_consumer *cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	error = g_attach(cp, pp);
	if (error) {
		printf("%s: g_attach\n", __func__);
		goto fail0;
	}
	g_topology_assert();
	error = g_access(cp, 0, 1, 0);
	if (error) {
		printf("%s: Cannot store metadata on %s: %d",
		    __func__, cp->provider->name, error);
		goto fail1;
	}

	// write out the first super block
	*sb_sa = 0;
	error = g_write_data(cp, 0, sb, SECTOR_SIZE);
	if (error) {
		printf("%s(%d): g_write_data error %d\n", __func__, __LINE__, error);
		goto fail2;
	}

	// clear the rest of the supeblocks
	char *buf = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK | M_ZERO);
	for (int i = 1; i < SB_CNT; i++) {
		error = g_write_data(cp, i * SECTOR_SIZE, buf, SECTOR_SIZE);
		if (error) {
			printf("%s(%d): g_write_data error %d\n", __func__, __LINE__, error);
			goto fail3;
		}
	}
	// initialize the inverse map
	inv_map = (typeof(inv_map))buf;
	for (int i = 0; i < BLOCKS_PER_SEG; ++i)
		inv_map->ba[i] = BLOCK_INVALID;

	// write out the inverse map at the end of every segment
	for (int i = 0; i < sb->seg_cnt; ++i) {
		uint32_t sa = sega2sa(i) + INV_MAP_OFFSET;
		error = g_write_data(cp, (off_t)sa * SECTOR_SIZE, inv_map, SECTOR_SIZE);
		if (error) {
			printf("%s(%d): g_write_data error %d\n", __func__, __LINE__, error);
			goto fail3;
		}
	}
fail3:
	free(buf, M_LOGSTOR);
fail2:
	(void)g_access(cp, 0, -1, 0);
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
is_sec_inuse_comm(uint8_t fm[], int fm_cnt, struct g_logstor_softc *sc,
	uint32_t sa, uint32_t ba_rev)
{
	uint32_t sa_rev; // the sector address for ba_rev

	MY_ASSERT(ba_rev < BLOCK_MAX);
	for (int i = 0; i < fm_cnt; ++i) {
		sa_rev = fm_read_4byte(sc, fm[i], ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

// Is a sector with a inverse ba valid?
// This function is called normally
static bool
is_sec_inuse_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fm[] = {
	    sc->superblock.fm_cur,
	    sc->superblock.fm_snap,
	};

	return is_sec_inuse_comm(fm, NUM_OF_ELEMS(fm), sc, sa, ba_rev);
}

// Is a sector with a inverse ba valid?
// This function is called during snapshot
static bool
is_sec_inuse_during_snapshot(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fm[] = {
	    sc->superblock.fm_cur,
	    sc->superblock.fm_prev,
	    sc->superblock.fm_snap,
	};

	return is_sec_inuse_comm(fm, NUM_OF_ELEMS(fm), sc, sa, ba_rev);
}

// Is a sector with a inverse ba valid?
static bool
is_sec_inuse(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
#if defined(MY_DEBUG)
	union fmbuf_addr fa_rev __unused;
	fa_rev.uint32 = ba_rev;
#endif
	if (ba_rev < BLOCK_MAX) {
		return sc->is_sec_inuse_fp(sc, sa, ba_rev);
#if defined(WYC)
		is_sec_inuse_normal();
		is_sec_inuse_during_snapshot();
#endif
	} else if (IS_FMBUF_ADDR(ba_rev)) {
		uint32_t sa_rev = fmbuf_ba2sa(sc, (union fmbuf_addr)ba_rev);
		return (sa == sa_rev);
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
	MY_ASSERT(!IS_FMBUF_ADDR(ba));
	uint32_t sa = g_logstor_write(sc, ba, NULL);
	return sa;
}

/*
Description:
  write metadata block to disk

Return:
  the sector address where the data/metadata is written
*/
static uint32_t
g_logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data)
{
	bool is_fmbuf_addr = IS_FMBUF_ADDR(ba);
	int i;
	struct _inv_map *inv_map = &sc->inv_map;
#if defined(MY_DEBUG)
	union fmbuf_addr dba __unused;
	union fmbuf_addr dba_rev __unused;

	dba.uint32 = ba;
#endif
	MY_ASSERT(is_fmbuf_addr ? data != NULL : data == NULL);
	MY_ASSERT(ba < sc->superblock.block_cnt || is_fmbuf_addr);

	// record the starting segment
	// if the search for free sector rolls over to the starting segment
	// it means that there is no free sector in this disk
	sc->seg_allocp_start = sc->superblock.seg_allocp;
again:
	for (i = sc->inv_allocp; i < INV_MAP_OFFSET; ++i)
	{
		uint32_t sa = sc->seg_allocp_sa + i;
		uint32_t ba_rev = inv_map->ba[i]; // ba from the inverse map
#if defined(MY_DEBUG)
		dba_rev.uint32 = ba_rev;
#endif
		if (is_sec_inuse(sc, sa, ba_rev))
			continue;

		if (is_fmbuf_addr) {
			struct g_consumer *cp;
			cp = LIST_FIRST(&sc->sc_geom->consumer);
			md_write(cp, data, sa);
			++sc->other_write_count;
		}
		inv_map->ba[i] = ba;		// record inverse mapping
		sc->inv_modified = true;		// segment summary modified
		sc->inv_allocp = i + 1;	// advnace the alloc pointer
		if (sc->inv_allocp == INV_MAP_OFFSET)
			seg_alloc(sc);

		if (!is_fmbuf_addr) {
			++sc->data_write_count;
			// record the forward mapping for the %ba
			// the forward mapping must be recorded after
			// the segment summary block write
			fm_write_4byte(sc, sc->superblock.fm_cur, ba, sa);
		}
		return sa;
	}
	seg_alloc(sc);
	goto again;
}

static void
g_logstor_init(struct g_logstor_softc *sc, struct _superblock *sb, uint32_t sb_sa)
{
	memcpy(&sc->superblock, sb, sizeof(sc->superblock));
	sc->sb_sa = sb_sa;
	sc->sb_modified = false;

	sc->is_sec_inuse_fp = is_sec_inuse_normal;
	sc->ba2sa_fp = ba2sa_normal;

	// the following is copied from logstor_open()
	// read the segment summary block
	if (sc->superblock.seg_allocp == 0)
		sc->inv_allocp = SB_CNT;
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	uint32_t sa = sc->seg_allocp_sa + INV_MAP_OFFSET;
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	md_read(cp, &sc->inv_map, sa);
	sc->inv_modified = false;

	fmbuf_mod_init(sc);

	sc->data_write_count = sc->other_write_count = 0;
#if defined(WYC)//MY_DEBUG)
	logstor_check(sc);
#endif
}

static void
g_logstor_close(struct g_logstor_softc *sc)
{

	seg_sum_write(sc);
	fmbuf_mod_fini(sc);
	superblock_write(sc);
}

static void
g_logstor_snapshot(struct g_logstor_softc *sc)
{

	// lock metadata
	// move fm_cur to fm_prev
	sc->superblock.fm_prev = sc->superblock.fm_cur;
	// create new files fm_cur and fm_new_snap
	// fc_cur is either 0 or 2 and fm_new_snap always follows fm_cur
	sc->superblock.fm_cur = sc->superblock.fm_cur ^ 2;
	sc->superblock.fm_new_snap = sc->superblock.fm_cur + 1;
	sc->superblock.fmt[sc->superblock.fm_cur].root = SECTOR_NULL;
	sc->superblock.fmt[sc->superblock.fm_cur].written = 0;
	sc->superblock.fmt[sc->superblock.fm_new_snap].root = SECTOR_NULL;
	sc->superblock.fmt[sc->superblock.fm_new_snap].written = 0;

	sc->is_sec_inuse_fp = is_sec_inuse_during_snapshot;
	sc->ba2sa_fp = ba2sa_during_snapshot;
	// unlock metadata

	// merge fm_prev and fm_snap to fm_new_snap
	uint32_t block_cnt = sc->superblock.block_cnt;
	for (int ba = 0; ba < block_cnt; ++ba) {
		uint32_t sa;

		fmbuf_clean_queue_check(sc);
		sa = fm_read_4byte(sc, sc->superblock.fm_prev, ba);
		if (sa == SECTOR_NULL)
			sa = fm_read_4byte(sc, sc->superblock.fm_snap, ba);
		else if (sa == SECTOR_DEL)
			sa = SECTOR_NULL;

		if (sa != SECTOR_NULL)
			fm_write_4byte(sc, sc->superblock.fm_new_snap, ba, sa);
	}

	// lock metadata
	int fm_prev = sc->superblock.fm_prev;
	int fm_snap = sc->superblock.fm_snap;
	fmbuf_cache_flush_and_invalidate_fm(sc, fm_prev, fm_snap);
	sc->superblock.fmt[fm_prev].root = SECTOR_DEL;
	sc->superblock.fmt[fm_snap].root = SECTOR_DEL;
	// move fm_new_snap to fm_snap
	sc->superblock.fm_snap = sc->superblock.fm_new_snap;
	// delete fm_prev and fm_snap
	sc->superblock.fm_prev = FM_INVALID;
	sc->superblock.fm_new_snap = FM_INVALID;
	sc->sb_modified = true;

	seg_sum_write(sc);
	superblock_write(sc);

	sc->is_sec_inuse_fp = is_sec_inuse_normal;
	sc->ba2sa_fp = ba2sa_normal;
	//unlock metadata
}

static void
g_logstor_rollback(struct g_logstor_softc *sc)
{

	fmbuf_cache_flush_and_invalidate_fm(sc, sc->superblock.fm_cur, FM_INVALID);
	sc->superblock.fmt[sc->superblock.fm_cur].root = SECTOR_NULL;
	sc->superblock.fmt[sc->superblock.fm_cur].written = 0;
	sc->sb_modified = true;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
static void
g_logstor_delete(struct g_logstor_softc *sc, struct bio *bp)
{
	uint32_t ba;	// block address
	int count;	// number of remaining sectors to process

	off_t offset = bp->bio_offset;
	off_t length = bp->bio_length;
	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	count = length / SECTOR_SIZE;
	MY_ASSERT(ba < sc->superblock.block_cnt);

	printf("%s: ba %d count %d\n", __func__, ba, count);
	fmbuf_clean_queue_check(sc);
	for (int i = 0; i < count; ++i) {
		uint32_t sa = fm_read_4byte(sc, sc->superblock.fm_cur, ba + i);
		if (sa != SECTOR_NULL && sa != SECTOR_DEL) {
			fm_write_4byte(sc, sc->superblock.fm_cur, ba + i, SECTOR_DEL);
			--sc->superblock.fmt[sc->superblock.fm_cur].written;
			sc->sb_modified = true;
		}
	}
	g_io_deliver(bp, 0);
}

static uint32_t
ba2sa_comm(struct g_logstor_softc *sc, uint32_t ba, uint8_t fm[], int fm_cnt)
{
	uint32_t sa;

	MY_ASSERT(ba < sc->superblock.block_cnt);
	for (int i = 0; i < fm_cnt; ++i) {
		sa = fm_read_4byte(sc, fm[i], ba);
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
	uint8_t fm[] = {
	    sc->superblock.fm_cur,
	    sc->superblock.fm_snap,
	};

	return ba2sa_comm(sc, ba, fm, NUM_OF_ELEMS(fm));
}

/*
Description:
    Block address to sector address translation in snapshot state
*/
static uint32_t __unused
ba2sa_during_snapshot(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fm[] = {
	    sc->superblock.fm_cur,
	    sc->superblock.fm_prev,
	    sc->superblock.fm_snap,
	};

	return ba2sa_comm(sc, ba, fm, NUM_OF_ELEMS(fm));
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

	if (!sc->inv_modified)
		return;
	cp = LIST_FIRST(&sc->sc_geom->consumer);
	sa = sc->seg_allocp_sa + INV_MAP_OFFSET;
	md_write(cp, (void *)&sc->inv_map, sa);
	sc->inv_modified = false;
	sc->other_write_count++; // the write for the segment summary
}

/*
  Segment 0 is used to store superblock and there are SB_CNT sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs SB_CNT, it wraps around
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
		error = 1;
		goto fail;
	}
	// get the superblock
	sb = (struct _superblock *)buf[0];
	g_read_datab(cp, 0, sb, SECTOR_SIZE);
	g_access(cp, -1, 0, 0);
	if (sb->magic != G_LOGSTOR_MAGIC ||
	    sb->seg_allocp >= sb->seg_cnt) {
		error = 2;//EINVAL;
		goto fail;
	}

	printf("%s(%d): sb->seg_cnt %u\n", __func__, __LINE__, sb->seg_cnt);
	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SB_CNT; i++) {
		sb = (struct _superblock *)buf[i%2];
		g_read_datab(cp, (off_t)i * SECTOR_SIZE, sb, SECTOR_SIZE);
		if (sb->sb_gen != sb_gen + i) {
			printf("%s(%d): %d, sb->sb_gen %u sb_gen %u\n",
				__func__, __LINE__, i, sb->sb_gen, sb_gen);
			break;
		}
		if (sb->magic != G_LOGSTOR_MAGIC) {
			printf("%s(%d): %X\n", __func__, __LINE__, sb->magic);
			break;
		}
	}
	if (i == SB_CNT) {
		error = 3;//EINVAL;
		goto fail;
	}
	*sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2]; // get the previous valid superblock
	if (sb->seg_allocp >= sb->seg_cnt) {
		printf("%s(%d): i %d, seg_allocp %u, seg_cnt %u\n",
			__func__, __LINE__, i, sb->seg_allocp, sb->seg_cnt);
		error = 4;//EINVAL;
		goto fail;
	}
	free(buf[i%2], M_LOGSTOR);
	for (i=0; i<FM_COUNT; ++i)
		MY_ASSERT(sb->fmt[i].root != SECTOR_CACHE);
	return sb;
fail:
	printf("%s(%d): Cannot access %s error %d\n", __func__, __LINE__, cp->provider->name, error);
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

	for (int i = 0; i < FM_COUNT; ++i) {
		MY_ASSERT(sc->superblock.fmt[i].root != SECTOR_CACHE);
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
	uint32_t inv_allocp;

	// write the previous segment summary to disk if it has been modified
	seg_sum_write(sc);

	MY_ASSERT(sc->superblock.seg_allocp < sc->superblock.seg_cnt);
	if (++sc->superblock.seg_allocp == sc->superblock.seg_cnt) {
		sc->superblock.seg_allocp = 0;
		inv_allocp = SB_CNT; // the first SB_CNT sectors are superblock
	} else
		inv_allocp = 0;

	if (sc->superblock.seg_allocp == sc->seg_allocp_start)
		// has accessed all the segment summary blocks
		MY_PANIC();
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	md_read(cp, &sc->inv_map, sc->seg_allocp_sa + INV_MAP_OFFSET);
	sc->inv_allocp = inv_allocp;
}

/*********************************************************
 * The file buffer and indirect block cache              *
 *   Cache the the block to sector address translation   *
 *********************************************************/

/*
Description:
	Get the sector address of the corresponding @ba in @file

Parameters:
	@fm: file descriptor
	@ba: block address

Return:
	The sector address of the @ba
*/
static uint32_t
fm_read_4byte(struct g_logstor_softc *sc, uint8_t fm, uint32_t ba)
{
	uint32_t eidx;	// entry index within the file data buffer
	uint32_t sa;
	fmbuf_t *fmbuf;

	MY_ASSERT(fm < FM_COUNT);

	// the initialized inverse map in the segment summary is BLOCK_INVALID
	// so it is possible that a caller might pass a ba that is BLOCK_INVALID
	if (ba >= BLOCK_MAX) {
		MY_ASSERT(ba == BLOCK_INVALID);
		return SECTOR_NULL;
	}
	// this file is all 0
	if (sc->superblock.fmt[fm].root == SECTOR_NULL ||
	    sc->superblock.fmt[fm].root == SECTOR_DEL)
		return SECTOR_NULL;

	fmbuf = fm_access_4byte(sc, fm, ba, &eidx);
	if (fmbuf)
		sa = fmbuf->data[eidx];
	else
		sa = SECTOR_NULL;
	return sa;
}

/*
Description:
	Set the mapping of @ba to @sa in @file

Parameters:
	%fm: forward map
	%ba: block address
	%sa: sector address
*/
static void
fm_write_4byte(struct g_logstor_softc *sc, uint8_t fm, uint32_t ba, uint32_t sa)
{
	fmbuf_t *fmbuf;
	uint32_t eidx;	// entry index within the file data buffer

	MY_ASSERT(fm < FM_COUNT);
	MY_ASSERT(ba < BLOCK_MAX);
	MY_ASSERT(sc->superblock.fmt[fm].root != SECTOR_DEL);

	fmbuf = fm_access_4byte(sc, fm, ba, &eidx);
	MY_ASSERT(fmbuf != NULL);
	uint32_t old_sa = fmbuf->data[eidx];
	if (old_sa == SECTOR_NULL || old_sa ==  SECTOR_DEL) {
		++sc->superblock.fmt[fm].written;
		sc->sb_modified = true;
	}
	fmbuf->data[eidx] = sa;
	if (!fmbuf->fc.modified) {
		// move to QUEUE_F0_DIRTY
		MY_ASSERT(fmbuf->queue_which == QUEUE_F0_CLEAN);
		fmbuf->fc.modified = true;
		if (fmbuf == sc->fmbuf_allocp)
			sc->fmbuf_allocp = fmbuf->fc.queue_next;
		fmbuf_queue_remove(sc, fmbuf);
		fmbuf_queue_insert_tail(sc, QUEUE_F0_DIRTY, fmbuf);
	} else
		MY_ASSERT(fmbuf->queue_which == QUEUE_F0_DIRTY);
}

/*
Description:
    The metadata is cached in memory. This function returns the address
    of the metadata in memory for the forward mapping of the block @ba

Parameters:
	%fm: forward map
	%ba: block address
	%eidx: entry index within the file data buffer

Return:
	the address of the file buffer data
*/
static fmbuf_t *
fm_access_4byte(struct g_logstor_softc *sc, uint8_t fm, uint32_t ba, uint32_t *eidx)
{
	union fmbuf_addr	fa;		// fmbuf block address
	fmbuf_t *fmbuf;

	// the sector address stored in file for this ba is 4 bytes
	*eidx = ((ba * 4) & (SECTOR_SIZE - 1)) / 4;

	// convert (%fm, %ba) to metadata address
	fa.index = (ba * 4) / SECTOR_SIZE;
	fa.depth = FMBUF_LEAF_DEPTH;
	fa.fm = fm;
	fa.xFF = 0xFF;	// for fmbuf block address, bits 31:24 are all 1s
	fmbuf = fmbuf_access(sc, fa);
	return fmbuf;
}

static inline unsigned
fmbuf_ba_index_get(union fmbuf_addr ba, unsigned depth)
{
	switch (depth) {
	case 0:
		return ba.index0;
	case 1:
		return ba.index1;
	default:
		MY_PANIC();
		return 0;
	}
}

static inline union fmbuf_addr
fmbuf_ba_index_set(union fmbuf_addr ba, unsigned depth, unsigned index)
{
	MY_ASSERT(index < (2 << IDX_BITS));

	switch (depth) {
	case 0:
		ba.index0 = index;
		break;
	case 1:
		ba.index1 = index;
		break;
	default:
		MY_PANIC();
	}
	return ba;
}

/*
  to parent's metadata address

output:
  pindex_out: the index in parent's metadata

return:
  parent's metadata address
*/
static union fmbuf_addr
fmbuf_ba2pba(union fmbuf_addr ba, unsigned *pindex_out)
{
	switch (ba.depth)
	{
	case 1:
		*pindex_out = ba.index0;
		ba.index = 0;
		ba.depth = 0; // i.e. ba.depth - 1
		break;
	case 2:
		*pindex_out = ba.index1;
		ba.index1 = 0;
		ba.depth = 1; // i.e. ba.depth - 1
		break;
	default:
		MY_PANIC();
		break;
	}
	return ba;
}

// get the sector address where the metadata is stored on disk
static uint32_t
fmbuf_ba2sa(struct g_logstor_softc *sc, union fmbuf_addr ba)
{
	uint32_t sa;

	switch (ba.depth)
	{
	case 0:
		sa = sc->superblock.fmt[ba.fm].root;
		break;
	case 1:
	case 2:
		if (sc->superblock.fmt[ba.fm].root == SECTOR_NULL ||
		    sc->superblock.fmt[ba.fm].root == SECTOR_DEL)
			sa = SECTOR_NULL;
		else {
			fmbuf_t *parent;	// parent buffer
			union fmbuf_addr pba;	// parent's fmbuf address
			unsigned pindex;	// index in the parent indirect block

			pba = fmbuf_ba2pba(ba, &pindex);
			parent = fmbuf_access(sc, pba);
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
fmbuf_mod_init(struct g_logstor_softc *sc)
{
	int fmbuf_count;
	int i;

	//fmbuf_count = sc.superblock.block_cnt / (SECTOR_SIZE / 4);
	fmbuf_count = FMBUF_MIN;
	if (fmbuf_count < FMBUF_MIN)
		fmbuf_count = FMBUF_MIN;
	if (fmbuf_count > FMBUF_MAX)
		fmbuf_count = FMBUF_MAX;
	sc->fmbuf_count = fmbuf_count;
	sc->fmbufs = malloc(fmbuf_count * sizeof(*sc->fmbufs), M_LOGSTOR, M_WAITOK | M_ZERO);

	for (i = 0; i < FMBUF_BUCKET_CNT; ++i) {
		fmbuf_bucket_init(sc, i);
	}
	for (i = 0; i < QUEUE_CNT; ++i) {
		fmbuf_queue_init(sc, i);
	}
	// insert fmbuf to both QUEUE_F0_CLEAN and hash queue
	for (i = 0; i < fmbuf_count; ++i) {
		fmbuf_t *fmbuf = &sc->fmbufs[i];
#if defined(MY_DEBUG)
		fmbuf->index = i;
#endif
		fmbuf->fc.is_sentinel = false;
		fmbuf->fc.accessed = false;
		fmbuf->fc.modified = false;
		fmbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fmbuf);
		// insert fmbuf to the last fmbuf bucket
		// this bucket is not used in hash search
		// init ba, parent and child_cnt before inserting into FMBUF_BUCKET_LAST
		fmbuf->ba.uint32 = BLOCK_INVALID; // ba must be invalid for fmbuf in FMBUF_BUCKET_LAST
		fmbuf->parent = NULL;
		fmbuf->child_cnt = 0;
		fmbuf_bucket_insert_head(sc, FMBUF_BUCKET_LAST, fmbuf);
	}
	sc->fmbuf_allocp = &sc->fmbufs[0];;
	sc->fmbuf_hit = sc->fmbuf_miss = 0;
}

// there are 3 kinds of metadata in the system, the fmbuf cache, segment summary block and superblock
static void
md_flush(struct g_logstor_softc *sc)
{
	seg_sum_write(sc);
	fmbuf_cache_flush(sc);
	superblock_write(sc);
}

static void
fmbuf_mod_fini(struct g_logstor_softc *sc)
{
	md_flush(sc);
	free(sc->fmbufs, M_LOGSTOR);
}

static inline bool
is_queue_empty(struct fmbuf_sentinel *sentinel)
{
	if (sentinel->fc.queue_next == (fmbuf_t *)sentinel) {
		MY_ASSERT(sentinel->fc.queue_prev == (fmbuf_t *)sentinel);
		return true;
	}
	return false;
}

static void
fmbuf_clean_queue_check(struct g_logstor_softc *sc)
{
	struct fmbuf_sentinel *queue_sentinel;
	fmbuf_t *fmbuf;

	if (sc->fmbuf_queue_len[QUEUE_F0_CLEAN] > FMBUF_CLEAN_THRESHOLD)
		return;

	md_flush(sc);

	// move all internal nodes with child_cnt 0 to clean queue and last bucket
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fmbuf_queue[q];
		fmbuf = queue_sentinel->fc.queue_next;
		while (fmbuf != (fmbuf_t *)queue_sentinel) {
			MY_ASSERT(fmbuf->queue_which == q);
			fmbuf_t *next = fmbuf->fc.queue_next;
			if (fmbuf->child_cnt == 0) {
				fmbuf_queue_remove(sc, fmbuf);
				fmbuf->fc.accessed = false; // so that it can be replaced faster
				fmbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fmbuf);
				if (fmbuf->parent) {
					MY_ASSERT(q != QUEUE_CNT-1);
					fmbuf_t *parent = fmbuf->parent;
					fmbuf->parent = NULL;
					--parent->child_cnt;
					MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
				}
				// move it to the last bucket so that it cannot be searched
				// fmbufs on the last bucket will have the metadata address BLOCK_INVALID
				fmbuf_bucket_remove(fmbuf);
				fmbuf->ba.uint32 = BLOCK_INVALID;
				fmbuf_bucket_insert_head(sc, FMBUF_BUCKET_LAST, fmbuf);
			}
			fmbuf = next;
		}
	}
}

// write back all the dirty fmbufs to disk
static void
fmbuf_cache_flush(struct g_logstor_softc *sc)
{
	fmbuf_t *fmbuf;
	fmbuf_t *dirty_first, *dirty_last, *clean_first;
	struct fmbuf_sentinel *dirty_sentinel;
	struct fmbuf_sentinel *clean_sentinel;

	// write back all the modified nodes to disk
	for (int q = QUEUE_F0_DIRTY; q < QUEUE_CNT; ++q) {
		struct fmbuf_sentinel *queue_sentinel = &sc->fmbuf_queue[q];
		fmbuf = queue_sentinel->fc.queue_next;
		while (fmbuf != (fmbuf_t *)queue_sentinel) {
			MY_ASSERT(fmbuf->queue_which == q);
			MY_ASSERT(IS_FMBUF_ADDR(fmbuf->ba.uint32));
			// QUEUE_F0_DIRTY nodes are always dirty
			MY_ASSERT(q != QUEUE_F0_DIRTY || fmbuf->fc.modified);
			if (__predict_true(fmbuf->fc.modified))
				fmbuf_write(sc, fmbuf);
			fmbuf = fmbuf->fc.queue_next;
		}
	}
	// move all fmbufs in the dirty leaf queue to clean leaf queue
	dirty_sentinel = &sc->fmbuf_queue[QUEUE_F0_DIRTY];
	if (is_queue_empty(dirty_sentinel))
		return;
	// first, set queue_which to QUEUE_F0_CLEAN for all fmbufs on dirty leaf queue
	fmbuf = dirty_sentinel->fc.queue_next;
	while (fmbuf != (fmbuf_t *)dirty_sentinel) {
		fmbuf->queue_which = QUEUE_F0_CLEAN;
		fmbuf = fmbuf->fc.queue_next;
	}
	// second, insert dirty leaf queue to the head of clean leaf queue
	clean_sentinel = &sc->fmbuf_queue[QUEUE_F0_CLEAN];
	dirty_first = dirty_sentinel->fc.queue_next;
	dirty_last = dirty_sentinel->fc.queue_prev;
	clean_first = clean_sentinel->fc.queue_next;
	clean_sentinel->fc.queue_next = dirty_first;
	dirty_first->fc.queue_prev = (fmbuf_t *)clean_sentinel;
	dirty_last->fc.queue_next = clean_first;
	clean_first->fc.queue_prev = dirty_last;
	sc->fmbuf_queue_len[QUEUE_F0_CLEAN] += sc->fmbuf_queue_len[QUEUE_F0_DIRTY];

	fmbuf_queue_init(sc, QUEUE_F0_DIRTY);
}

// flush the cache and invalid fmbufs with file descriptors fm1 or fm2
static void
fmbuf_cache_flush_and_invalidate_fm(struct g_logstor_softc *sc, int fm1, int fm2)
{
	fmbuf_t *fmbuf;

	md_flush(sc);

	for (int i = 0; i < sc->fmbuf_count; ++i)
	{
		fmbuf = &sc->fmbufs[i];
		MY_ASSERT(!fmbuf->fc.modified);
		if (fmbuf->ba.uint32 == BLOCK_INVALID) {
			// the fmbufs with metadata address BLOCK_INVALID are
			// linked in bucket FMBUF_BUCKET_LAST
			MY_ASSERT(fmbuf->bucket_which == FMBUF_BUCKET_LAST);
			continue;
		}
		// move fmbufs with fm equals to fm1 or fm2 to the last bucket
		if (fmbuf->ba.fm == fm1 || fmbuf->ba.fm == fm2) {
			MY_ASSERT(fmbuf->bucket_which != FMBUF_BUCKET_LAST);
			fmbuf_bucket_remove(fmbuf);
			// init ba, parent and child_cnt before inserting to bucket FMBUF_BUCKET_LAST
			fmbuf->ba.uint32 = BLOCK_INVALID;
			fmbuf->parent = NULL;
			fmbuf->child_cnt = 0;
			fmbuf_bucket_insert_head(sc, FMBUF_BUCKET_LAST, fmbuf);
			fmbuf->fc.accessed = false; // so it will be recycled sooner
			if (fmbuf->queue_which != QUEUE_F0_CLEAN) {
				// it is an internal node, move it to QUEUE_F0_CLEAN
				MY_ASSERT(fmbuf->queue_which != QUEUE_F0_DIRTY);
				fmbuf_queue_remove(sc, fmbuf);
				fmbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fmbuf);
			}
		}
	}
}

static void
fmbuf_queue_init(struct g_logstor_softc *sc, int which)
{
	struct fmbuf_sentinel *queue_head;

	MY_ASSERT(which < QUEUE_CNT);
	sc->fmbuf_queue_len[which] = 0;
	queue_head = &sc->fmbuf_queue[which];
	queue_head->fc.queue_next = (fmbuf_t *)queue_head;
	queue_head->fc.queue_prev = (fmbuf_t *)queue_head;
	queue_head->fc.is_sentinel = true;
	queue_head->fc.accessed = true;
	queue_head->fc.modified = false;
}

static void
fmbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, fmbuf_t *fmbuf)
{
	struct fmbuf_sentinel *queue_head;
	fmbuf_t *prev;

	MY_ASSERT(which < QUEUE_CNT);
	MY_ASSERT(which != QUEUE_F0_CLEAN || !fmbuf->fc.modified);
	fmbuf->queue_which = which;
	queue_head = &sc->fmbuf_queue[which];
	prev = queue_head->fc.queue_prev;
	MY_ASSERT(prev->fc.is_sentinel || prev->queue_which == which);
	queue_head->fc.queue_prev = fmbuf;
	fmbuf->fc.queue_next = (fmbuf_t *)queue_head;
	fmbuf->fc.queue_prev = prev;
	prev->fc.queue_next = fmbuf;
	++sc->fmbuf_queue_len[which];
}

static void
fmbuf_queue_remove(struct g_logstor_softc *sc, fmbuf_t *fmbuf)
{
	fmbuf_t *prev;
	fmbuf_t *next;
	int which = fmbuf->queue_which;

	MY_ASSERT(fmbuf != (fmbuf_t *)&sc->fmbuf_queue[which]);
	prev = fmbuf->fc.queue_prev;
	next = fmbuf->fc.queue_next;
	MY_ASSERT(prev->fc.is_sentinel || prev->queue_which == which);
	MY_ASSERT(next->fc.is_sentinel || next->queue_which == which);
	prev->fc.queue_next = next;
	next->fc.queue_prev = prev;
	--sc->fmbuf_queue_len[which];
}

// insert to the head of the hashed bucket
static void
fmbuf_hash_insert_head(struct g_logstor_softc *sc, fmbuf_t *fmbuf, union fmbuf_addr ba)
{
	unsigned hash;

	fmbuf->ba = ba;
	// the bucket FMBUF_BUCKET_LAST is reserved for storing unused fmbufs
	// so %hash will be [0..FMBUF_BUCKET_LAST)
	hash = ba.uint32 % FMBUF_BUCKET_LAST;
	fmbuf_bucket_insert_head(sc, hash, fmbuf);
}

static void
fmbuf_bucket_init(struct g_logstor_softc *sc, int which)
{
	struct fmbuf_sentinel *bucket_head;

#if defined(MY_DEBUG)
	MY_ASSERT(which < FMBUF_BUCKET_CNT);
	sc->fmbuf_bucket_len[which] = 0;
#endif
	bucket_head = &sc->fmbuf_bucket[which];
	bucket_head->fc.queue_next = (fmbuf_t *)bucket_head;
	bucket_head->fc.queue_prev = (fmbuf_t *)bucket_head;
	bucket_head->fc.is_sentinel = true;
}

static void
fmbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, fmbuf_t *fmbuf)
{
	struct fmbuf_sentinel *bucket_head;
	fmbuf_t *next;

#if defined(MY_DEBUG)
	MY_ASSERT(which < FMBUF_BUCKET_CNT);
	fmbuf->bucket_which = which;
	++sc->fmbuf_bucket_len[which];
#endif
	bucket_head = &sc->fmbuf_bucket[which];
	next = bucket_head->fc.queue_next;
	bucket_head->fc.queue_next = fmbuf;
	fmbuf->bucket_next = next;
	fmbuf->bucket_prev = (fmbuf_t *)bucket_head;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = fmbuf;
	else
		next->bucket_prev = fmbuf;
}

static void
fmbuf_bucket_remove(fmbuf_t *fmbuf)
{
	fmbuf_t *prev;
	fmbuf_t *next;

	MY_ASSERT(!fmbuf->fc.is_sentinel);
	prev = fmbuf->bucket_prev;
	next = fmbuf->bucket_next;
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
    Search the fmbuf with block address %ba. Return NULL if not found
*/
static fmbuf_t *
fmbuf_search(struct g_logstor_softc *sc, union fmbuf_addr ba)
{
	unsigned	hash;	// hash value
	fmbuf_t	*fmbuf;
	struct fmbuf_sentinel	*bucket_sentinel;

	// the bucket FMBUF_BUCKET_LAST is reserved for storing unused fmbufs
	// so %hash will be [0..FMBUF_BUCKET_LAST)
	hash = ba.uint32 % FMBUF_BUCKET_LAST;
	bucket_sentinel = &sc->fmbuf_bucket[hash];
	fmbuf = bucket_sentinel->fc.queue_next;
	while (fmbuf != (fmbuf_t *)bucket_sentinel) {
		if (fmbuf->ba.uint32 == ba.uint32) { // cache hit
			++sc->fmbuf_hit;
			return fmbuf;
		}
		fmbuf = fmbuf->bucket_next;
	}
	++sc->fmbuf_miss;
	return NULL;	// cache miss
}

// convert from fmbuf depth to queue number
static const int d2q[] = {QUEUE_F2, QUEUE_F1, QUEUE_F0_DIRTY};

/*
Description:
  using the second chance replacement policy to choose a fmbuf in QUEUE_F0_CLEAN
*/
fmbuf_t *
fmbuf_alloc(struct g_logstor_softc *sc, union fmbuf_addr ba, int depth)
{
	struct fmbuf_sentinel *queue_sentinel;
	fmbuf_t *fmbuf, *parent;

	MY_ASSERT(depth <= FMBUF_LEAF_DEPTH);
	queue_sentinel = &sc->fmbuf_queue[QUEUE_F0_CLEAN];
	fmbuf = sc->fmbuf_allocp;
again:
	while (true) {
		if (!fmbuf->fc.accessed)
			break;

		fmbuf->fc.accessed = false;	// give this fmbuf a second chance
		fmbuf = fmbuf->fc.queue_next;
	}
	if (fmbuf == (fmbuf_t *)queue_sentinel) {
		fmbuf->fc.accessed = true;
		fmbuf = fmbuf->fc.queue_next;
		MY_ASSERT(fmbuf != (fmbuf_t *)queue_sentinel);
		goto again;
	}

	MY_ASSERT(!fmbuf->fc.modified);
	MY_ASSERT(fmbuf->child_cnt == 0);
	sc->fmbuf_allocp = fmbuf->fc.queue_next;
	if (depth != FMBUF_LEAF_DEPTH) {
		// for fmbuf allocated for internal nodes insert it immediately
		// to its internal queue
		fmbuf_queue_remove(sc, fmbuf);
		fmbuf_queue_insert_tail(sc, d2q[depth], fmbuf);
	}
	fmbuf_bucket_remove(fmbuf);
	fmbuf_hash_insert_head(sc, fmbuf, ba);
	parent = fmbuf->parent;
	if (parent) {
		// parent with child_cnt == 0 will be moved to
		// QUEUE_F0_CLEAN in fmbuf_clean_queue_check()
		--parent->child_cnt;
		MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
		MY_ASSERT(parent->queue_which == d2q[parent->ba.depth]);
	}
	return fmbuf;
}

/*
Description:
    Read or write the file buffer with metadata address @ba
*/
static fmbuf_t *
fmbuf_access(struct g_logstor_softc *sc, union fmbuf_addr ba)
{
	uint32_t sa;	// sector address where the metadata is stored
	unsigned index;
	union fmbuf_addr	iba;	// the intermediate fmbuf block address
	fmbuf_t *parent;	// parent buffer
	fmbuf_t *fmbuf;
	struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);

	MY_ASSERT(IS_FMBUF_ADDR(ba.uint32));
	MY_ASSERT(ba.depth <= FMBUF_LEAF_DEPTH);

	// get the root sector address of the file %ba.fm
	sa = sc->superblock.fmt[ba.fm].root;
	MY_ASSERT(sa != SECTOR_DEL);

	fmbuf = fmbuf_search(sc, ba);
	if (fmbuf != NULL) // cache hit
		goto end;

	// cache miss
	parent = NULL;	// parent for root is NULL
	iba = (union fmbuf_addr){.xFF = 0xFF};	// set .xFF to 0xFF and all others to 0
	iba.fm = ba.fm;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		iba.depth = i;
		fmbuf = fmbuf_search(sc, iba);
		if (fmbuf == NULL) {
			fmbuf = fmbuf_alloc(sc, iba, i);	// allocate a fmbuf from clean queue
			fmbuf->parent = parent;
			if (parent) {
				// parent with child_cnt == 0 will stay in its queue
				// it will only be moved to QUEUE_F0_CLEAN in fmbuf_clean_queue_check()
				++parent->child_cnt;
				MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
			} else {
				MY_ASSERT(i == 0);
			}
			if (sa == SECTOR_NULL) {
				bzero(fmbuf->data, sizeof(fmbuf->data));
				if (i == 0)
					sc->superblock.fmt[ba.fm].root = SECTOR_CACHE;
			} else {
				MY_ASSERT(sa >= SB_CNT);
				md_read(cp, fmbuf->data, sa);
			}
#if defined(MY_DEBUG)
			fmbuf->sa = sa;
			if (parent)
				parent->child[index] = fmbuf;
#endif
		} else {
			MY_ASSERT(fmbuf->parent == parent);
			MY_ASSERT(fmbuf->sa == sa ||
				(i == 0 && sa == SECTOR_CACHE));
		}
		if (i == ba.depth) // reach the intended depth
			break;

		parent = fmbuf;		// %fmbuf is the parent of next level indirect block
		index = fmbuf_ba_index_get(ba, i);// the index to next level's indirect block
		sa = parent->data[index];	// the sector address of the next level indirect block
		iba = fmbuf_ba_index_set(iba, i, index); // set the next level's index for @iba
	} // for
end:
	fmbuf->fc.accessed = true;
	return fmbuf;
}

static void
fmbuf_write(struct g_logstor_softc *sc, fmbuf_t *fmbuf)
{
	fmbuf_t *parent;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address

	MY_ASSERT(fmbuf->fc.modified);
	sa = g_logstor_write(sc, fmbuf->ba.uint32, fmbuf->data);
#if defined(MY_DEBUG)
	fmbuf->sa = sa;
#endif
	fmbuf->fc.modified = false;

	// update the sector address of this fmbuf in its parent's fmbuf
	parent = fmbuf->parent;
	if (parent) {
		MY_ASSERT(fmbuf->ba.depth != 0);
		MY_ASSERT(parent->ba.depth == fmbuf->ba.depth - 1);
		pindex = fmbuf_ba_index_get(fmbuf->ba, fmbuf->ba.depth - 1);
		parent->data[pindex] = sa;
		parent->fc.modified = true;
	} else {
		MY_ASSERT(fmbuf->ba.depth == 0);
		// store the root sector address to the corresponding file table in super block
		sc->superblock.fmt[fmbuf->ba.fm].root = sa;
		sc->sb_modified = true;
	}
}

#if defined(WYC) //MY_DEBUG)
static void
logstor_hash_check(struct g_logstor_softc *sc)
{
	fmbuf_t *fmbuf;
	struct fmbuf_sentinel *bucket_sentinel;
	int total = 0;

	for (int i = 0; i < FMBUF_BUCKET_CNT; ++i)
	{
		bucket_sentinel = &sc->fmbuf_bucket[i];
		fmbuf = bucket_sentinel->fc.queue_next;
		while (fmbuf != (fmbuf_t *)bucket_sentinel) {
			++total;
			MY_ASSERT(!fmbuf->fc.is_sentinel);
			MY_ASSERT(fmbuf->bucket_which == i);
			if (i == FMBUF_BUCKET_LAST)
				MY_ASSERT(fmbuf->ba.uint32 == BLOCK_INVALID);
			else
				MY_ASSERT(fmbuf->ba.uint32 % FMBUF_BUCKET_LAST == i);
			fmbuf = fmbuf->bucket_next;
		}
	}
	MY_ASSERT(total == sc->fmbuf_count);
}

static void
logstor_queue_check(struct g_logstor_softc *sc)
{
	struct fmbuf_sentinel *queue_sentinel;
	fmbuf_t *fmbuf;
	unsigned count[QUEUE_CNT];

	// set debug child count of internal nodes to 0
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fmbuf_queue[q];
		fmbuf = queue_sentinel->fc.queue_next;
		while (fmbuf != (fmbuf_t *)queue_sentinel) {
			MY_ASSERT(d2q[fmbuf->ba.depth] == q);
			fmbuf->dbg_child_cnt = 0; // set the child count to 0
			fmbuf = fmbuf->fc.queue_next;
		}
	}
	// check queue length and calculate the child count
	//int root_cnt = 0;
	for (int q = 0; q < QUEUE_CNT ; ++q) {
		count[q] = 0;
		queue_sentinel = &sc->fmbuf_queue[q];
		fmbuf = queue_sentinel->fc.queue_next;
		while (fmbuf != (fmbuf_t *)queue_sentinel) {
			++count[q];
			MY_ASSERT(fmbuf->queue_which == q);
			if (q == QUEUE_CNT-1) {
				MY_ASSERT(fmbuf->parent == NULL);
				//++root_cnt;
			} else
				MY_ASSERT(fmbuf->ba.uint32 == BLOCK_INVALID || fmbuf->parent != NULL);
			if (fmbuf->parent)
				++fmbuf->parent->dbg_child_cnt; // increment parent's debug child count

			fmbuf = fmbuf->fc.queue_next;
		}
		MY_ASSERT(sc->fmbuf_queue_len[q] == count[q]);
	}
	// check that the debug child count of internal nodes is correct
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fmbuf_queue[q];
		fmbuf = queue_sentinel->fc.queue_next;
		while (fmbuf != (fmbuf_t *)queue_sentinel) {
			MY_ASSERT(fmbuf->dbg_child_cnt == fmbuf->child_cnt);
			fmbuf = fmbuf->fc.queue_next;
		}
	}
	int total = 0;
	for (int q = 0; q < QUEUE_CNT; ++q)
		total += count[q];

	MY_ASSERT(total == sc->fmbuf_count);
}

static uint32_t
sa2ba(struct g_logstor_softc *sc, uint32_t sa)
{
	static uint32_t inv_map_cache_sa;
	static uint32_t inv_map_cache[SECTORS_PER_SEG];
	uint32_t seg_sa;
	unsigned seg_off;

	seg_sa = sa & ~(SECTORS_PER_SEG - 1);
	seg_off = sa & (SECTORS_PER_SEG - 1);
	MY_ASSERT(seg_sa != 0 || seg_off >= SB_CNT);
	MY_ASSERT(seg_off != INV_MAP_OFFSET);
	if (seg_sa != inv_map_cache_sa) {
		struct g_consumer *cp = LIST_FIRST(&sc->sc_geom->consumer);
		md_read(cp, &inv_map_cache, seg_sa + INV_MAP_OFFSET);
		inv_map_cache_sa = seg_sa;
	}
	return (inv_map_cache[seg_off]);
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
#endif // MY_DEBUG

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

#if defined(WYC)
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
}
#endif

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
		g_logstor_delete(sc, bp);
		return;
	case BIO_SPEEDUP:
	case BIO_FLUSH:
		g_logstor_passdown(sc, bp);
		return;
	case BIO_GETATTR:
		if (g_handleattr_int(bp, "GEOM::candelete", 1))
			return;
		if (strcmp("GEOM::kerneldump", bp->bio_attribute) == 0) {
			printf("kerneldump not supported\n");
		}
		/* To which provider it should be delivered? */
		/* FALLTHROUGH */
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		return;
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

	fmbuf_clean_queue_check(sc);
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
			return;
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
			cbp->bio_ma_n = round_page(cbp->bio_ma_offset + SECTOR_SIZE) / PAGE_SIZE;
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
}

static struct g_geom *
g_logstor_create(struct g_class *mp, struct g_provider *pp,
	struct _superblock *sb, uint32_t sb_sa)
{
	struct g_logstor_softc *sc;
	struct g_geom *gp;
	char name[32];

	int n = snprintf(name, sizeof(name), "%s%s", pp->name, G_LOGSTOR_SUFFIX);
	if (n <= 0 || n >= sizeof(name)) {
		G_LOGSTOR_DEBUG(0, "%s(%d): Invalid provider name.", __func__, __LINE__);
		return NULL;
	}
	G_LOGSTOR_DEBUG(1, "Creating device %s.", name);

	/* Check for duplicate unit */
	LIST_FOREACH(gp, &mp->geom, geom) {
		if (strcmp(gp->name, name) == 0) {
			G_LOGSTOR_DEBUG(0, "Device %s already configured.", name);
			return (NULL);
		}
	}
	gp = g_new_geomf(mp, "%s", name);
	gp->start = g_logstor_start;
	gp->spoiled = g_logstor_orphan;
	gp->orphan = g_logstor_orphan;
	gp->access = g_logstor_access;
	gp->dumpconf = g_logstor_dumpconf;

	struct g_provider *newpp = g_new_providerf(gp, "%s", gp->name);
	newpp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE;
	newpp->flags |= (pp->flags & G_PF_ACCEPT_UNMAPPED);
	newpp->sectorsize = SECTOR_SIZE;
	newpp->mediasize = (off_t)sb->block_cnt * SECTOR_SIZE;

	struct g_consumer *cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	int error = g_attach(cp, pp);
	if (error) {
		G_LOGSTOR_DEBUG(0, "%s: Error %d: cannot attach to provider %s.",
		    __func__, error, name);
		goto fail;
	}
	sc = malloc(sizeof(*sc), M_LOGSTOR, M_WAITOK | M_ZERO);
	sc->sc_geom = gp;
	g_logstor_init(sc, sb, sb_sa);
	gp->softc = sc;
	g_error_provider(newpp, 0);
	G_LOGSTOR_DEBUG(0, "%s: Device %s created.", __func__, gp->name);

	return (gp);
fail:
	g_destroy_consumer(cp);
	g_destroy_provider(newpp);
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
	g_logstor_close(sc);
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
	struct g_geom *gp;
	int error;
	uint32_t sb_sa;

	g_trace(G_T_TOPOLOGY, "%s(%s, %s)", __func__, mp->name, pp->name);
	g_topology_assert();

	/* Skip providers that are already open for writing. */
	if (pp->acw > 0)
		return (NULL);

	G_LOGSTOR_DEBUG(3, "Tasting %s.", pp->name);

	gp = g_new_geomf(mp, "logstor:taste");
	gp->start = invalid_g_start;
	gp->access = invalid_g_access;
	gp->orphan = invalid_g_orphan;
	struct g_consumer *cp = g_new_consumer(gp);
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
	if (pp == NULL) {
		printf("%s: cannot get provider\n", __func__);
		return;
	}
	uint32_t sb_sa;
	struct _superblock *sb = disk_init(mp, pp, &sb_sa);
	if (sb == NULL) {
		printf("%s: cannot init disk\n", __func__);
		return;
	}
	struct g_geom *gp = g_logstor_create(mp, pp, sb, sb_sa);
	free(sb, M_LOGSTOR);
	if (gp == NULL) {
		printf("%s: g_logstor_create failed\n", __func__);
		gctl_error(req, "Can't configure %s.", pp->name);
		return;
	}
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
	g_logstor_snapshot(sc);
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
	g_logstor_rollback(sc);
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
