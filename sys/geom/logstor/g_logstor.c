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
#include <vm/pmap.h> //wyc
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
	/*
	   The segments are treated as circular buffer
	 */
	uint32_t seg_cnt;	// total number of segments
	// since the max meta file size is 4G (1K*1K*4K) and the entry size is 4
	// block_max must be < (4G/4)
	uint32_t block_max;	// max block number for the virtual disk

	uint32_t sb_gen;	// the generation number. Used for redo after system crash
	uint32_t seg_allocp;	// allocate this segment
	uint32_t sectors_free;
	/*
	   The files for forward mapping

	   New mapping is written to %fd_cur. When commit command is issued
	   %fd_cur is movied to %fd_prev, %fd_prev and %fd_snap are merged to %fd_snap_new
	   After the commit command is complete, %fd_snap_new is movied to %fd_snap
	   and %fd_prev is deleted.

	   So the actual mapping in normal state is
	       %fd_cur || %fd_snap
	   and during commit it is
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
	struct _superblock superblock; // one of the metadata for logstor
	struct _seg_sum seg_sum;// segment summary for the current segment

	struct g_geom	*sc_geom;

	bool (*is_sec_valid_fp)(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
	uint32_t (*ba2sa_fp)(struct g_logstor_softc *sc, uint32_t ba);

	uint32_t seg_allocp_start;// the starting segment for _logstor_write
	uint32_t seg_allocp_sa;	// the sector address of the segment for allocation
	uint32_t sb_sa; 	// superblock's sector address
	bool sb_modified;	// is the super block modified
	bool ss_modified;	// is segment summary modified

	int fbuf_count;
	struct _fbuf *fbufs;	// an array of fbufs
	struct _fbuf *fbuf_allocp; // point to the fbuf candidate for replacement
	struct _fbuf_sentinel fbuf_queue[QUEUE_CNT];
	int fbuf_queue_len[QUEUE_CNT];

	// buffer hash queue
	struct _fbuf_sentinel fbuf_bucket[FBUF_BUCKET_CNT];
#if defined(MY_DEBUG)
	int fbuf_bucket_len[FBUF_BUCKET_CNT];
#endif
	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;
};

/*
Description:
    segment address to sector address
*/
static inline uint32_t
sega2sa(uint32_t sega)
{
	return sega << SEC_PER_SEG_SHIFT;
}

/*
Description:
    Write the initialized supeblock to the downstream disk

Return:
    The max number of blocks for this disk
*/
static uint32_t
disk_init(struct g_logstor_softc *sc, struct g_provider *pp)
{
	int32_t seg_cnt;
	uint32_t sector_cnt;
	struct _superblock *sb;
	struct _seg_sum *seg_sum;
	char *buf;

	sector_cnt = pp->mediasize / SECTOR_SIZE;
	buf = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK | M_ZERO);
	sb = (struct _superblock *)buf;
	sb->magic = G_LOGSTOR_MAGIC;
	sb->version = G_LOGSTOR_VERSION;
	sb->sb_gen = arc4random();
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	if (sizeof(struct _superblock) + sb->seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct _superblock), (int)sb->seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct _superblock)) * (long long)SEG_SIZE);
		MY_PANIC();
	}
	seg_cnt = sb->seg_cnt;
	uint32_t max_block =
	    seg_cnt * BLOCKS_PER_SEG - SB_CNT -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT * 4;
	MY_ASSERT(max_block < 0x40000000); // 1G
	sb->block_max = max_block;
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u block_max %u\n",
	    __func__, sector_cnt, sb->block_max);
#endif
	sb->seg_allocp = 0;	// start allocate from here

	sb->fd_cur = 0;			// current mapping is file 0
	sb->fd_snap = 1;
	sb->fd_prev = FD_INVALID;	// mapping does not exist
	sb->fd_snap_new = FD_INVALID;
	sb->fh[0].root = SECTOR_NULL;	// file 0 is all 0
	// the root sector address for the files 1, 2 and 3
	for (int i = 1; i < FD_COUNT; i++) {
		sb->fh[i].root = SECTOR_DEL;	// the file does not exit
	}

	// write out the first super block
	memset(buf + sizeof(*sb), 0, sizeof(buf) - sizeof(*sb));
	md_write(sc, buf, 0);

	// clear the rest of the supeblocks
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SB_CNT; i++) {
		md_write(sc, buf, i);
	}
	// initialize the segment summary block
	seg_sum = (struct _seg_sum *)buf;
	for (int i = 0; i < BLOCKS_PER_SEG; ++i)
		seg_sum->ss_rm[i] = BLOCK_INVALID;

	// write out the first segment summary block
	seg_sum->ss_allocp = SB_CNT;
	md_write(NULL, seg_sum, SEG_SUM_OFFSET);

	// write out the rest of the segment summary blocks
	seg_sum->ss_allocp = 0;
	for (int i = 1; i < seg_cnt; ++i) {
		uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		md_write(sc, seg_sum, sa);
	}
	return max_block;
}

/*******************************
 *        logstor              *
 *******************************/
static uint32_t logstor_read(struct g_logstor_softc *sc, uint32_t ba);
static uint32_t logstor_write(struct g_logstor_softc *sc, uint32_t ba);

static void seg_alloc(struct g_logstor_softc *sc);
static void seg_sum_write(struct g_logstor_softc *sc);

static int  superblock_read(struct g_logstor_softc *sc);
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
static uint32_t ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba);
static bool is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
#if defined(MY_DEBUG)
static void logstor_check(struct g_logstor_softc *sc);
#endif
md_read(struct g_logstor_softc *sc, void *buf, uint32_t sa);
md_write(struct g_logstor_softc *sc, const void *buf, uint32_t sa);

int
logstor_open(struct g_logstor_softc *sc)
{

	bzero(sc, sizeof(*sc));
	int error __unused;

	error = superblock_read(sc);
	MY_ASSERT(error == 0);

	// read the segment summary block
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	uint32_t sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	md_read(sc, &sc->seg_sum, sa);
	MY_ASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET);
	sc->ss_modified = false;

	fbuf_mod_init(sc);

	sc->data_write_count = sc->other_write_count = 0;
	sc->is_sec_valid_fp = is_sec_valid_normal;
	sc->ba2sa_fp = ba2sa_normal;
#if defined(MY_DEBUG)
	logstor_check(sc);
#endif
	return 0;
}

void
logstor_close(struct g_logstor_softc *sc)
{

	fbuf_mod_fini(sc);
	seg_sum_write(sc);
	superblock_write(sc);
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
int logstor_delete(struct g_logstor_softc *sc, off_t offset, void *data __unused, off_t length)
{
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process
	int i;

	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;
	MY_ASSERT(ba < sc->superblock.block_max);

	for (i = 0; i < size; ++i) {
		fbuf_clean_queue_check(sc);
		file_write_4byte(sc, sc->superblock.fd_cur, ba + i, SECTOR_DEL);
	}

	return (0);
}

void
logstor_commit(struct g_logstor_softc *sc)
{

	// lock metadata
	// move fd_cur to fd_prev
	sc->superblock.fd_prev = sc->superblock.fd_cur;
	// create new files fd_cur and fd_snap_new
	// fc_cur is either 0 or 2 and fd_snap always follows fd_cur
	sc->superblock.fd_cur = sc->superblock.fd_cur ^ 2;
	sc->superblock.fd_snap_new = sc->superblock.fd_cur + 1;
	sc->superblock.fh[sc->superblock.fd_cur].root = SECTOR_NULL;
	sc->superblock.fh[sc->superblock.fd_snap_new].root = SECTOR_NULL;

	sc->is_sec_valid_fp = is_sec_valid_during_commit;
	sc->ba2sa_fp = ba2sa_during_commit;
	// unlock metadata

	uint32_t block_max = sc->superblock.block_max;
	for (int ba = 0; ba < block_max; ++ba) {
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

	sc->is_sec_valid_fp = is_sec_valid_normal;
	sc->ba2sa_fp = ba2sa_normal;
	//unlock metadata
}

void
logstor_revert(struct g_logstor_softc *sc)
{

	fbuf_cache_flush_and_invalidate_fd(sc, sc->superblock.fd_cur, FD_INVALID);
	sc->superblock.fh[sc->superblock.fd_cur].root = SECTOR_NULL;
}

uint32_t
logstor_read(struct g_logstor_softc *sc, unsigned ba)
{
	uint32_t sa;	// sector address

	sa = sc->ba2sa_fp(sc, ba);
#if defined(WYC)
	ba2sa_normal();
	ba2sa_during_commit();
#endif
	return sa;
}

// The common part of is_sec_valid
static bool
is_sec_valid_comm(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev, uint8_t fd[], int fd_cnt)
{
	uint32_t sa_rev; // the sector address for ba_rev

	MY_ASSERT(ba_rev < BLOCK_MAX);
	for (int i = 0; i < fd_cnt; ++i) {
		sa_rev = file_read_4byte(sc, fd[i], ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

// Is a sector with a reverse ba valid?
// This function is called normally
static bool
is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return is_sec_valid_comm(sc, sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
// This function is called during commit
static bool
is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return is_sec_valid_comm(sc, sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
static bool
is_sec_valid(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
#if defined(MY_DEBUG)
	union meta_addr ma_rev __unused;
	ma_rev.uint32 = ba_rev;
#endif
	if (ba_rev < BLOCK_MAX) {
		return sc->is_sec_valid_fp(sc, sa, ba_rev);
#if defined(WYC)
		is_sec_valid_normal();
		is_sec_valid_during_commit();
#endif
	} else if (IS_META_ADDR(ba_rev)) {
		uint32_t sa_rev = ma2sa(sc, (union meta_addr)ba_rev);
		return (sa == sa_rev);
	} else if (ba_rev == BLOCK_INVALID) {
		return false;
	} else {
		MY_PANIC();
		return false;
	}
}

/*
Description:
  write data/metadata block to disk

Return:
  the sector address where the data is written
*/
static uint32_t
_logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data)
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
	MY_ASSERT(ba < sc->superblock.block_max || IS_META_ADDR(ba));
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
		if (is_sec_valid(sc, sa, ba_rev))
			continue;

		if (IS_META_ADDR(ba)) {
			md_write(sc, data, sa);
		}
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		sc->ss_modified = true;
		seg_sum->ss_allocp = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_allocp == SEG_SUM_OFFSET)
			seg_alloc(sc);

		if (IS_META_ADDR(ba))
			++sc->other_write_count;
		else {
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

static uint32_t
logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data)
{
	return _logstor_write(sc, ba, NULL);
}

static uint32_t
ba2sa_comm(struct g_logstor_softc *sc, uint32_t ba, uint8_t fd[], int fd_cnt)
{
	uint32_t sa;

	MY_ASSERT(ba < sc->superblock.block_max);
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
    Block address to sector address translation in commit state
*/
static uint32_t __unused
ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

uint32_t
logstor_get_block_cnt(void)
{
	struct g_logstor_softc *sc = &softc;

	return sc->superblock.block_max;
}

/*
  write out the segment summary
  segment summary is at the end of a segment
*/
static void
seg_sum_write(struct g_logstor_softc *sc)
{
	uint32_t sa;

	if (!sc->ss_modified)
		return;
	MY_ASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET);
	sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	md_write(sc, (void *)&sc->seg_sum, sa);
	sc->ss_modified = false;
	sc->other_write_count++; // the write for the segment summary
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
static int
superblock_read(struct g_consumer *cp, struct g_logstor_softc *sc)
{
	typeof(sc->superblock.sb_gen) sb_gen;
	int i, error;
	struct _superblock *sb;
	char *buf[2];

	buf[0] = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK);
	buf[1] = malloc(SECTOR_SIZE, M_LOGSTOR, M_WAITOK);

	// get the superblock
	sb = (struct _superblock *)buf[0];
	md_read(sc, sb, 0);
	if (sb->magic != G_LOGSTOR_MAGIC ||
	    sb->seg_allocp >= sb->seg_cnt) {
		error = EINVAL;
		goto exit:
	}

	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SB_CNT; i++) {
		sb = (struct _superblock *)buf[i%2];
		md_read(sc, sb, i);
		if (sb->magic != G_LOGSTOR_MAGIC)
			break;
		if (sb->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	if (i == SECTORS_PER_SEG) {
		error = EINVAL;
		goto exit;
	}
	sc->sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2]; // get the previous valid superblock
	if (sb->seg_allocp >= sb->seg_cnt) {
		error = EINVAL;
		goto exit;
	}
	for (i=0; i<FD_COUNT; ++i)
		MY_ASSERT(sb->fh[i].root != SECTOR_CACHE);
	memcpy(&sc->superblock, sb, sizeof(sc->superblock));
	sc->sb_modified = false;
	error = 0;
exit:
	free(buf[1], M_LOGSTOR);
	free(buf[0], M_LOGSTOR);
	return error;
}

static void
superblock_write(struct g_consumer *cp, struct g_logstor_softc *sc)
{
	size_t sb_size = sizeof(sc->superblock);
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
	md_write(sc, buf, sc->sb_sa);
	sc->sb_modified = false;
	sc->other_write_count++;
	free(buf, M_LOGSTOR);
}

static void
md_read(struct g_logstor_softc *sc, void *buf, uint32_t sa)
{
	int error;
	struct g_consumer *cp = LIST_FIRST(sc->sc_geom->consumer);

	MY_ASSERT(sc == NULL || sa < sc->superblock.seg_cnt * SECTORS_PER_SEG);
	g_topology_assert();
	error = g_access(cp, 1, 0, 0);
	if (error != 0) {
		printf("%s: Cannot access %s error %d",
			__func__, cp->provider->name, error);
		return (error);
	}
	error = g_read_datab(cp, (off_t)sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	g_access(cp, -1, 0, 0);
}

static void
md_write(struct g_logstor_softc *sc, const void *buf, uint32_t sa)
{
	int error;
	struct g_consumer *cp = LIST_FIRST(sc->sc_geom->consumer);

	MY_ASSERT(sc == NULL || sa < sc->superblock.seg_cnt * SECTORS_PER_SEG);
	g_topology_assert();
	error = g_access(cp, 0, 1, 0);
	if (!error) {
		printf("%s: Cannot store metadata on %s: %d",
		    __func__, cp->provider->name, error);
		return;
	}
	error = g_write_data(cp, (off_t)sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	(void)g_access(cp, 0, -1, 0);
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
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	md_read(sc, &sc->seg_sum, sc->seg_allocp_sa + SEG_SUM_OFFSET);
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
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data
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

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
	if (fbuf)
		sa = fbuf->data[off_4byte];
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
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data

	MY_ASSERT(fd < FD_COUNT);
	MY_ASSERT(ba < BLOCK_MAX);
	MY_ASSERT(sc->superblock.fh[fd].root != SECTOR_DEL);

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
	MY_ASSERT(fbuf != NULL);
	fbuf->data[off_4byte] = sa;
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
	%off_4byte: the offset (in unit of 4 bytes) within the file buffer data

Return:
	the address of the file buffer data
*/
static struct _fbuf *
file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t *off_4byte)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *fbuf;

	// the sector address stored in file for this ba is 4 bytes
	*off_4byte = ((ba * 4) & (SECTOR_SIZE - 1)) / 4;

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

	//fbuf_count = sc.superblock.block_max / (SECTOR_SIZE / 4);
	fbuf_count = FBUF_MIN;
	if (fbuf_count < FBUF_MIN)
		fbuf_count = FBUF_MIN;
	if (fbuf_count > FBUF_MAX)
		fbuf_count = FBUF_MAX;
	sc->fbuf_count = fbuf_count;
	sc->fbufs = malloc(fbuf_count * sizeof(*sc->fbufs));
	MY_ASSERT(sc->fbufs != NULL);

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
	free(sc->fbufs);
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
				md_read(sc, fbuf->data, sa);
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
	sa = _logstor_write(sc, fbuf->ma.uint32, fbuf->data);
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
void
logstor_hash_check(void)
{
	struct g_logstor_softc *sc = &softc;
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

void
logstor_queue_check(void)
{
	struct g_logstor_softc *sc = &softc;
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
	int root_cnt = 0;
	for (int q = 0; q < QUEUE_CNT ; ++q) {
		count[q] = 0;
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			++count[q];
			MY_ASSERT(fbuf->queue_which == q);
			if (q == QUEUE_CNT-1) {
				MY_ASSERT(fbuf->parent == NULL);
				++root_cnt;
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
		md_read(sc, &seg_sum_cache, seg_sa + SEG_SUM_OFFSET);
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
	block_cnt = logstor_get_block_cnt();
	MY_ASSERT(block_cnt < BLOCK_MAX);
	for (uint32_t ba = 0; ba < block_cnt; ++ba) {
		uint32_t sa = sc->ba2sa_fp(sc, ba);
#if defined(WYC)
		ba2sa_normal();
		ba2sa_during_commit();
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

static int g_logstor_destroy(struct g_logstor_softc *sc, boolean_t force);
static int g_logstor_destroy_geom(struct gctl_req *req, struct g_class *mp,
    struct g_geom *gp);
#if !defined(WYC)
static g_taste_t g_logstor_taste;
static g_ctl_req_t g_logstor_config;
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
g_logstor_remove_disk(struct g_logstor_disk *disk)
{
	struct g_consumer *cp;
	struct g_logstor_softc *sc;

	g_topology_assert();
	KASSERT(disk->d_consumer != NULL, ("Non-valid disk in %s.", __func__));
	sc = disk->d_softc;
	cp = disk->d_consumer;

	if (!disk->d_removed) {
		G_LOGSTOR_DEBUG(0, "Disk %s removed from %s.",
		    cp->provider->name, sc->sc_geom->name);
		disk->d_removed = true;
	}

	if (sc->sc_provider != NULL) {
		G_LOGSTOR_DEBUG(0, "Device %s deactivated.",
		    sc->sc_provider->name);
		g_wither_provider(sc->sc_provider, ENXIO);
		sc->sc_provider = NULL;
	}

	if (cp->acr > 0 || cp->acw > 0 || cp->ace > 0)
		return;
	disk->d_consumer = NULL;
	g_detach(cp);
	g_destroy_consumer(cp);
	/* If there are no valid disks anymore, remove device. */
	if (LIST_EMPTY(&sc->sc_geom->consumer))
		g_logstor_destroy(sc, 1);
}

static void
g_logstor_orphan(struct g_consumer *cp)
{
	struct g_logstor_softc *sc;
	struct g_logstor_disk *disk;
	struct g_geom *gp;

	g_topology_assert();
	gp = cp->geom;
	sc = gp->softc;
	if (sc == NULL)
		return;

	disk = cp->private;
	if (disk == NULL)	/* Possible? */
		return;
	g_logstor_remove_disk(disk);
}

static int
g_logstor_access(struct g_provider *pp, int dr, int dw, int de)
{
	struct g_consumer *cp1, *cp2, *tmp;
	struct g_logstor_disk *disk;
	struct g_geom *gp;
	struct g_logstor_softc *sc;
	int error;

	g_topology_assert();
	gp = pp->geom;
	sc = gp->softc;

	/* On first open, grab an extra "exclusive" bit */
	if (pp->acr == 0 && pp->acw == 0 && pp->ace == 0)
		de++;
	/* ... and let go of it on last close */
	if ((pp->acr + dr) == 0 && (pp->acw + dw) == 0 && (pp->ace + de) == 0)
		de--;

	sx_slock(&sc->sc_disks_lock);
	LIST_FOREACH_SAFE(cp1, &gp->consumer, consumer, tmp) {
		error = g_access(cp1, dr, dw, de);
		if (error != 0)
			goto fail;
		disk = cp1->private;
		if (cp1->acr == 0 && cp1->acw == 0 && cp1->ace == 0 &&
		    disk->d_removed) {
			g_logstor_remove_disk(disk); /* May destroy geom. */
		}
	}
	sx_sunlock(&sc->sc_disks_lock);
	return (0);

fail:
	sx_sunlock(&sc->sc_disks_lock);
	LIST_FOREACH(cp2, &gp->consumer, consumer) {
		if (cp1 == cp2)
			break;
		g_access(cp2, -dr, -dw, -de);
	}
	return (error);
}

static void
g_logstor_kernel_dump(struct bio *bp)
{
	struct g_logstor_softc *sc;
	struct bio *cbp;
	struct g_kerneldump *gkd;

	sc = bp->bio_to->geom->softc;
	gkd = (struct g_kerneldump *)bp->bio_data;

	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		g_io_deliver(bp, ENOMEM);
		return;
	}
	cbp->bio_done = g_std_done;
	g_consumer *cp = LIST_FIRST(sc->sc_geom->consumer);
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

static void
g_logstor_done(struct bio *bp)
{
	struct g_logstor_softc *sc;
	struct bio *pbp;

	pbp = bp->bio_parent;
	sc = pbp->bio_to->geom->softc;
	mtx_lock(&sc->sc_completion_lock);
	if (pbp->bio_error == 0)
		pbp->bio_error = bp->bio_error;
	pbp->bio_completed += bp->bio_completed;
	pbp->bio_inbed++;
	if (pbp->bio_children == pbp->bio_inbed) {
		mtx_unlock(&sc->sc_completion_lock);
		g_io_deliver(pbp, pbp->bio_error);
	} else
		mtx_unlock(&sc->sc_completion_lock);
	g_destroy_bio(bp);
}

/*
 * Called for both BIO_FLUSH and BIO_SPEEDUP. Just pass the call down
 */
static void
g_logstor_passdown(struct g_logstor_softc *sc, struct bio *bp)
{
	struct g_consumer *cp = LIST_FIRST(sc->sc_geom->consumer);
	struct bio *cbp;

		cbp = g_clone_bio(bp);
		if (cbp == NULL) {
			if (bp->bio_error == 0)
				bp->bio_error = ENOMEM;
			g_io_deliver(bp, bp->bio_error);
			return;
		}
		cbp->bio_done = g_std_done;
		cbp->bio_to = cp->provider;

		G_LOGSTOR_LOGREQ(cbp, "Sending request.");
		g_io_request(cbp, cp);
	}
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
	struct bio_queue_head queue;
	struct g_logstor_softc *sc;
	struct g_consumer *cp;
	struct g_provider *pp;
	off_t offset, length;
	struct bio *cbp;
	char *addr;
	uint32_t (*logstor_access)(struct g_logstor_softc *sc, unsigned ba);


	pp = bp->bio_to;
	sc = pp->geom->softc;
	cp = LIST_FIRST(sc->sc_geom->consumer);
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
		logstor_access = logstor_read;
		break;
	case BIO_WRITE:
		logstor_access = logstor_write;
		break;
	case BIO_SPEEDUP:
	case BIO_FLUSH:
		g_logstor_passdown(sc, bp);
		goto exit;
	//case BIO_DELETE:
	//	break;
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

	offset = bp->bio_offset;
	length = bp->bio_length;
	MY_ASSERT(offset % SECTOR_SIZE == 0);
	MY_ASSERT(length % SECTOR_SIZE == 0);

	if ((bp->bio_flags & BIO_UNMAPPED) != 0)
		addr = NULL;
	else
		addr = bp->bio_data;

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
		uint32_t sa = logstor_access(sc, ba_start + i);
#if defined(WYC)
		logstor_read();
		logstor_write();
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
		//cbp->bio_to = cp->provider;
	}
	while ((cbp = bioq_takefirst(&queue)) != NULL) {
		if (cbp->offset == SECTOR_NULL) {
			if ((cbp->bio_flags & BIO_UNMAPPED) != 0) {
				pmap_zero_page_area(cbp->bio_ma,
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

static void
g_logstor_check_and_run(struct g_logstor_softc *sc)
{
	struct g_logstor_disk *disk;
	struct g_provider *dp, *pp;
	u_int sectorsize = 0;
	off_t start;
	int error;

	g_topology_assert();
	if (g_logstor_nvalid(sc) != sc->sc_ndisks)
		return;

	pp = g_new_providerf(sc->sc_geom, "logstor/%s", sc->sc_geom->name);
	pp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE |
	    G_PF_ACCEPT_UNMAPPED;
	start = 0;
	sectorsize = 1;
	TAILQ_FOREACH(disk, &sc->sc_disks, d_next) {
		dp = disk->d_consumer->provider;
		disk->d_start = start;
		disk->d_end = disk->d_start + dp->mediasize;
		if (sc->sc_type == G_LOGSTOR_TYPE_AUTOMATIC)
			disk->d_end -= dp->sectorsize;
		start = disk->d_end;
		error = g_access(disk->d_consumer, 1, 0, 0);
		if (error == 0) {
			int disk_candelete;
			//g_getattr();
			error = g_getattr__("GEOM::candelete", disk->d_consumer,
			    &disk_candelete, sizeof(disk_candelete));
			if (error != 0)
				disk_candelete = 0;
			disk->d_candelete = disk_candelete;
			(void)g_access(disk->d_consumer, -1, 0, 0);
		} else
			G_LOGSTOR_DEBUG(1, "Failed to access disk %s, error %d.",
			    dp->name, error);
		//if (disk == TAILQ_FIRST(&sc->sc_disks))
		//	sectorsize = dp->sectorsize;
		//else
			sectorsize = lcm(dp->sectorsize, sectorsize);

		/* A provider underneath us doesn't support unmapped */
		if ((dp->flags & G_PF_ACCEPT_UNMAPPED) == 0) {
			G_LOGSTOR_DEBUG(1, "Cancelling unmapped "
			    "because of %s.", dp->name);
			pp->flags &= ~G_PF_ACCEPT_UNMAPPED;
		}
	}
	pp->sectorsize = sectorsize;
	/* We have sc->sc_disks[sc->sc_ndisks - 1].d_end in 'start'. */
	pp->mediasize = start;
	dp = TAILQ_FIRST(&sc->sc_disks)->d_consumer->provider;
	pp->stripesize = dp->stripesize;
	pp->stripeoffset = dp->stripeoffset;
	sc->sc_provider = pp;
	g_error_provider(pp, 0);

	G_LOGSTOR_DEBUG(0, "Device %s activated.", sc->sc_provider->name);
}

static int
g_logstor_read_metadata(struct g_consumer *cp, struct g_logstor_metadata *md)
{
	struct g_provider *pp;
	u_char *buf;
	int error;

	g_topology_assert();

	error = g_access(cp, 1, 0, 0);
	if (error != 0)
		return (error);
	pp = cp->provider;
	g_topology_unlock();
	buf = g_read_data(cp, pp->mediasize - pp->sectorsize, pp->sectorsize,
	    &error);
	g_topology_lock();
	g_access(cp, -1, 0, 0);
	if (buf == NULL)
		return (error);

	/* Decode metadata. */
	logstor_metadata_decode(buf, md);
	g_free(buf);

	return (0);
}

static void
g_logstor_write_metadata(struct gctl_req *req, struct g_logstor_softc *sc)
{
	u_int no = 0;
	struct g_logstor_disk *disk;
	struct g_logstor_metadata md;
	struct g_provider *pp;
	u_char *sector;
	int error;

	g_topology_assert(); //wyc

	bzero(&md, sizeof(md));
	strlcpy(md.md_magic, G_LOGSTOR_MAGIC, sizeof(md.md_magic));
	md.md_version = G_LOGSTOR_VERSION;
	strlcpy(md.md_name, sc->sc_geom->name, sizeof(md.md_name));
	md.md_id = sc->sc_id;
	md.md_all = sc->sc_ndisks;
	TAILQ_FOREACH(disk, &sc->sc_disks, d_next) {
		pp = disk->d_consumer->provider;

		md.md_no = no;
		if (disk->d_hardcoded)
			strlcpy(md.md_provider, pp->name,
			    sizeof(md.md_provider));
		md.md_provsize = disk->d_consumer->provider->mediasize;

		sector = g_malloc(pp->sectorsize, M_WAITOK | M_ZERO);
		logstor_metadata_encode(&md, sector);
		error = g_access(disk->d_consumer, 0, 1, 0);
		if (error == 0) {
			error = g_write_data(disk->d_consumer,
			    pp->mediasize - pp->sectorsize, sector,
			    pp->sectorsize);
			(void)g_access(disk->d_consumer, 0, -1, 0);
		}
		g_free(sector);
		if (error != 0)
			gctl_error(req, "Cannot store metadata on %s: %d",
			    pp->name, error);

		no++;
	}
}

/*
 * Add disk to given device.
 */
static int
g_logstor_add_disk(struct g_logstor_softc *sc, struct g_provider *pp, u_int no)
{
	struct g_logstor_disk *disk;
	struct g_consumer *cp, *fcp; // first consumer
	struct g_geom *gp;
	int error;

	g_topology_assert();

	sx_slock(&sc->sc_disks_lock);

	/* Metadata corrupted? */
	if (no >= sc->sc_ndisks) {
		sx_sunlock(&sc->sc_disks_lock);
		return (EINVAL);
	}
	// find the nth disk (n starts from 0)
	for (disk = TAILQ_FIRST(&sc->sc_disks); no > 0; no--) {
		disk = TAILQ_NEXT(disk, d_next);
	}

	/* Check if disk is not already attached. */
	if (disk->d_consumer != NULL) {
		sx_sunlock(&sc->sc_disks_lock);
		return (EEXIST);
	}

	gp = sc->sc_geom;
	fcp = LIST_FIRST(&gp->consumer);

	cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	error = g_attach(cp, pp);
	if (error != 0) {
		sx_sunlock(&sc->sc_disks_lock);
		goto fail2;
		//g_destroy_consumer(cp);
		//return (error);
	}

	if (fcp != NULL && (fcp->acr > 0 || fcp->acw > 0 || fcp->ace > 0)) {
		error = g_access(cp, fcp->acr, fcp->acw, fcp->ace);
		if (error != 0) {
			sx_sunlock(&sc->sc_disks_lock);
			goto fail1;
			//g_detach(cp);
			//g_destroy_consumer(cp);
			//return (error);
		}
	}
	if (sc->sc_type == G_LOGSTOR_TYPE_AUTOMATIC) {
		struct g_logstor_metadata md __attribute__((aligned));

		// temporarily give up the lock to avoid lock order violation
		// due to topology unlock in g_logstor_read_metadata
		sx_sunlock(&sc->sc_disks_lock);
		/* Re-read metadata. */
		error = g_logstor_read_metadata(cp, &md);
		sx_slock(&sc->sc_disks_lock);

		if (error != 0)
			goto fail0;

		if (strcmp(md.md_magic, G_LOGSTOR_MAGIC) != 0 ||
		    strcmp(md.md_name, gp->name) != 0 ||
		    md.md_id != sc->sc_id) {
			G_LOGSTOR_DEBUG(0, "Metadata on %s changed.", pp->name);
			error = EINVAL; //wycpull should set error to something?
			goto fail0;
		}

		disk->d_hardcoded = md.md_provider[0] != '\0';
	} else {
		disk->d_hardcoded = false;
	}

	cp->private = disk;
	disk->d_consumer = cp;
	disk->d_softc = sc;
	disk->d_start = 0;	/* set in g_logstor_check_and_run */
	disk->d_end = 0;	/* set in g_logstor_check_and_run */
	disk->d_removed = false;

	G_LOGSTOR_DEBUG(0, "Disk %s attached to %s.", pp->name, gp->name);

	g_logstor_check_and_run(sc);
	sx_sunlock(&sc->sc_disks_lock); // need lock for check_and_run

	return (ESUCCESS);
fail0:
	sx_sunlock(&sc->sc_disks_lock);
	if (fcp != NULL && (fcp->acr > 0 || fcp->acw > 0 || fcp->ace > 0))
		g_access(cp, -fcp->acr, -fcp->acw, -fcp->ace);
fail1:
	g_detach(cp);
fail2:
	g_destroy_consumer(cp);
	return (error);
}

static struct g_geom *
g_logstor_create(struct g_class *mp, const struct g_logstor_metadata *md,
    u_int type)
{
	struct g_logstor_softc *sc;
	struct g_geom *gp;

	G_LOGSTOR_DEBUG(1, "Creating device %s (id=%u).", md->md_name,
	    md->md_id);

	/* One disks is minimum. */
	if (md->md_all < 1)
		return (NULL);

	/* Check for duplicate unit */
	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc != NULL && strcmp(gp->name, md->md_name) == 0) {
			MY_ASSERT(sc->sc_geom == gp);
			G_LOGSTOR_DEBUG(0, "Device %s already configured.",
			    gp->name);
			return (NULL);
		}
	}
	gp = g_new_geom(mp, md->md_name);
	sc = malloc(sizeof(*sc), M_LOGSTOR, M_WAITOK | M_ZERO);
	gp->start = g_logstor_start;
	gp->spoiled = g_logstor_orphan;
	gp->orphan = g_logstor_orphan;
	gp->access = g_logstor_access;
	gp->dumpconf = g_logstor_dumpconf;

	sc->sc_id = md->md_id;
	sc->sc_type = type;
	mtx_init(&sc->sc_completion_lock, "glogstor lock", NULL, MTX_DEF);
	sx_init(&sc->sc_disks_lock, "glogstor append lock");

	gp->softc = sc;
	sc->sc_geom = gp;
	sc->sc_provider = NULL;

	G_LOGSTOR_DEBUG(0, "Device %s created (id=%u).", gp->name, sc->sc_id);

	return (gp);
}

static int
g_logstor_destroy(struct g_logstor_softc *sc, boolean_t force)
{
	struct g_provider *pp;
	struct g_consumer *cp, *cp1;
	struct g_geom *gp;
	struct g_logstor_disk *disk;

	g_topology_assert();

	if (sc == NULL)
		return (ENXIO);

	pp = sc->sc_provider;
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

	gp = sc->sc_geom;
	LIST_FOREACH_SAFE(cp, &gp->consumer, consumer, cp1) {
		g_logstor_remove_disk(cp->private);
		if (cp1 == NULL)
			return (0);	/* Recursion happened. */
	}
	if (!LIST_EMPTY(&gp->consumer))
		return (EINPROGRESS);

	gp->softc = NULL;
	KASSERT(sc->sc_provider == NULL, ("Provider still exists? (device=%s)",
	    gp->name));
	while ((disk = TAILQ_FIRST(&sc->sc_disks)) != NULL) {
		TAILQ_REMOVE(&sc->sc_disks, disk, d_next);
		free(disk, M_LOGSTOR);
	}
	mtx_destroy(&sc->sc_completion_lock);
	sx_destroy(&sc->sc_disks_lock);
	free(sc, M_LOGSTOR);

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
	struct g_logstor_metadata md;
	struct g_logstor_softc *sc;
	struct g_consumer *cp;
	struct g_geom *gp;
	int error;

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
	if (error == 0) {
		struct _superblock
		error = superblock_read(cp, &md);
		g_detach(cp);
	}
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	if (error != 0) {
		return (NULL);
	}
	gp = NULL;

	if (strcmp(md.md_magic, G_LOGSTOR_MAGIC) != 0)
		return (NULL);
	if (md.md_version > G_LOGSTOR_VERSION) {
		printf("geom_logstor.ko module is too old to handle %s.\n",
		    pp->name);
		return (NULL);
	}
	/*
	 * Backward compatibility:
	 */
	/* There was no md_provider field in earlier versions of metadata. */
	if (md.md_version < 3)
		bzero(md.md_provider, sizeof(md.md_provider));
	/* There was no md_provsize field in earlier versions of metadata. */
	if (md.md_version < 4)
		md.md_provsize = pp->mediasize;

	if (md.md_provider[0] != '\0' &&
	    !g_compare_names(md.md_provider, pp->name))
		return (NULL);
	if (md.md_provsize != pp->mediasize)
		return (NULL);

	/*
	 * Let's check if device already exists.
	 */
	//wyc sc = NULL;
	LIST_FOREACH(gp, &mp->geom, geom) {
		struct g_logstor_softc *sc = gp->softc;
		if (sc == NULL)
			continue;
		if (sc->sc_type != G_LOGSTOR_TYPE_AUTOMATIC)
			continue;
		if (strcmp(md.md_name, gp->name) != 0)
			continue;
		if (md.md_id != sc->sc_id)
			continue;
		break;
	}
	bool gp_created = false;
	if (gp != NULL) {
		MY_ASSERT(sc->sc_ndisks == md.md_all);
		if (sc->sc_ndisks != md.md_all) {
			error = EINVAL;
			goto fail;
		}
	} else {
		gp = g_logstor_create(mp, &md, G_LOGSTOR_TYPE_AUTOMATIC);
		if (gp == NULL) {
			G_LOGSTOR_DEBUG(0, "Cannot create device %s.",
			    md.md_name);
			return (NULL);
		}
		gp_created = true;
		sc = gp->softc;
	}
	G_LOGSTOR_DEBUG(1, "Adding disk %s to %s.", pp->name, gp->name);
	error = g_logstor_add_disk(sc, pp, md.md_no);
	if (error != 0) {
fail:
		G_LOGSTOR_DEBUG(0,
		    "Cannot add disk %s to %s (error=%d).", pp->name,
		    gp->name, error);
		if (gp_created)
			g_logstor_destroy(sc, 1);
		return (NULL);
	}

	return (gp);
}

static void
g_logstor_ctl_create(struct gctl_req *req, struct g_class *mp)
{
	u_int attached, no;
	struct g_logstor_metadata md;
	struct g_provider *pp;
	struct g_logstor_softc *sc;
	struct g_geom *gp;
	struct sbuf *sb;
	const char *name;
	char param[16];
	int *nargs;

	g_topology_assert();
	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 2) {
		gctl_error(req, "Only accept 2 parameters.");
		return;
	}
	disk_init()
	bzero(&md, sizeof(md));
	strlcpy(md.md_magic, G_LOGSTOR_MAGIC, sizeof(md.md_magic));
	md.md_version = G_LOGSTOR_VERSION;
	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	strlcpy(md.md_name, name, sizeof(md.md_name));
	md.md_id = arc4random();
	md.md_no = 0;
	md.md_all = *nargs - 1;
	/* This field is not important here. */
	md.md_provsize = 0;

	gp = g_logstor_create(mp, &md, G_LOGSTOR_TYPE_MANUAL);
	if (gp == NULL) {
		gctl_error(req, "Can't configure %s.", md.md_name);
		return;
	}

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
g_logstor_ctl_destroy(struct gctl_req *req, struct g_class *mp)
{
	struct g_logstor_softc *sc;
	int *force, *nargs, error;
	const char *name;
	char param[16];
	u_int i;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}
	force = gctl_get_paraml(req, "force", sizeof(*force));
	if (force == NULL) {
		gctl_error(req, "No '%s' argument.", "force");
		return;
	}

	for (i = 0; i < (u_int)*nargs; i++) {
		snprintf(param, sizeof(param), "arg%u", i);
		name = gctl_get_asciiparam(req, param);
		if (name == NULL) {
			gctl_error(req, "No 'arg%u' argument.", i);
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
}

static struct g_logstor_disk *
g_logstor_find_disk(struct g_logstor_softc *sc, const char *name)
{
	struct g_logstor_disk *disk;

	sx_assert(&sc->sc_disks_lock, SX_LOCKED);
	if (strncmp(name, "/dev/", 5) == 0)
		name += 5;
	TAILQ_FOREACH(disk, &sc->sc_disks, d_next) {
		if (disk->d_consumer == NULL)
			continue;
		if (disk->d_consumer->provider == NULL)
			continue;
		if (strcmp(disk->d_consumer->provider->name, name) == 0)
			return (disk);
	}
	return (NULL);
}

static void
g_logstor_ctl_append(struct gctl_req *req, struct g_class *mp)
{
	struct g_logstor_softc *sc;
	struct g_consumer *cp, *fcp;
	struct g_provider *pp;
	struct g_geom *gp;
	const char *name, *cname;
	struct g_logstor_disk *disk;
	int *nargs, *hardcode;
	int error;
	int disk_candelete;

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 2) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	hardcode = gctl_get_paraml(req, "hardcode", sizeof(*hardcode));
	if (hardcode == NULL) {
		gctl_error(req, "No '%s' argument.", "hardcode");
		return;
	}

	cname = gctl_get_asciiparam(req, "arg0");
	if (cname == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	sc = g_logstor_find_device(mp, cname);
	if (sc == NULL) {
		gctl_error(req, "No such device: %s.", cname);
		return;
	}
	if (sc->sc_provider == NULL) {
		/*
		 * this won't race with g_logstor_remove_disk as both
		 * are holding the topology lock
		 */
		gctl_error(req, "Device not active, can't append: %s.", cname);
		return;
	}
	G_LOGSTOR_DEBUG(1, "Appending to %s:", cname);
	sx_xlock(&sc->sc_disks_lock);
	gp = sc->sc_geom;
	fcp = LIST_FIRST(&gp->consumer);

	name = gctl_get_asciiparam(req, "arg1");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 1);
		goto fail;
	}
//wycpull this will be done in g_provider_by_name
//	if (strncmp(name, "/dev/", strlen("/dev/")) == 0)
//		name += strlen("/dev/");
	pp = g_provider_by_name(name);
	if (pp == NULL) {
		G_LOGSTOR_DEBUG(1, "Disk %s is invalid.", name);
		gctl_error(req, "Disk %s is invalid.", name);
		goto fail;
	}
	G_LOGSTOR_DEBUG(1, "Appending %s to this", name);

	if (g_logstor_find_disk(sc, name) != NULL) {
		gctl_error(req, "Disk %s already appended.", name);
		goto fail;
	}

	if ((sc->sc_provider->sectorsize % pp->sectorsize) != 0) {
		gctl_error(req, "Providers sectorsize mismatch: %u vs %u",
			   sc->sc_provider->sectorsize, pp->sectorsize);
		goto fail;
	}

	cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	error = g_attach(cp, pp);
	if (error != 0) {
		g_destroy_consumer(cp);
		gctl_error(req, "Cannot open device %s (error=%d).",
		    name, error);
		goto fail;
	}

	error = g_access(cp, 1, 0, 0);
	if (error == 0) {
		error = g_getattr("GEOM::candelete", cp, &disk_candelete);
		if (error != 0)
			disk_candelete = 0;
		(void)g_access(cp, -1, 0, 0);
	} else
		G_LOGSTOR_DEBUG(1, "Failed to access disk %s, error %d.", name, error);

	/* invoke g_access exactly as deep as all the other members currently are */
	if (fcp != NULL && (fcp->acr > 0 || fcp->acw > 0 || fcp->ace > 0)) {
		error = g_access(cp, fcp->acr, fcp->acw, fcp->ace);
		if (error != 0) {
			g_detach(cp);
			g_destroy_consumer(cp);
			gctl_error(req, "Failed to access disk %s (error=%d).", name, error);
			goto fail;
		}
	}

	disk = malloc(sizeof(*disk), M_LOGSTOR, M_WAITOK | M_ZERO);
	disk->d_consumer = cp;
	disk->d_softc = sc;
	disk->d_start = TAILQ_LAST(&sc->sc_disks, g_logstor_disks)->d_end;
	disk->d_end = disk->d_start + cp->provider->mediasize;
	disk->d_candelete = disk_candelete;
	disk->d_removed = false;
	disk->d_hardcoded = *hardcode;
	cp->private = disk;
	TAILQ_INSERT_TAIL(&sc->sc_disks, disk, d_next);
	sc->sc_ndisks++;

	if (sc->sc_type == G_LOGSTOR_TYPE_AUTOMATIC) {
		/* last sector is for metadata */
		disk->d_end -= cp->provider->sectorsize;

		/* update metadata on all parts */
		g_logstor_write_metadata(req, sc);
	}

	g_resize_provider(sc->sc_provider, disk->d_end);

fail:
	sx_xunlock(&sc->sc_disks_lock);
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
		return;
	} else if (strcmp(verb, "destroy") == 0 ||
	    strcmp(verb, "stop") == 0) {
		g_logstor_ctl_destroy(req, mp);
		return;
	} else if (strcmp(verb, "append") == 0) {
		g_logstor_ctl_append(req, mp);
		return;
	}
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

	sx_slock(&sc->sc_disks_lock);
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
		if (sc->sc_provider != NULL && sc->sc_provider->error == 0)
			sbuf_cat(sb, "UP");
		else
			sbuf_cat(sb, "DOWN");
		sbuf_cat(sb, "</State>\n");
	}
end:
	sx_sunlock(&sc->sc_disks_lock);
}

DECLARE_GEOM_CLASS(g_logstor_class, g_logstor);
MODULE_VERSION(geom_logstor, 0);
