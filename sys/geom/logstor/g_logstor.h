/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Marshall Kirk McKusick <mckusick@mckusick.com>
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

#ifndef	_G_LOGSTOR_H_
#define	_G_LOGSTOR_H_

#define	G_LOGSTOR_CLASS_NAME	"LOGSTOR"
#define	G_LOGSTOR_VERSION		1
#define	G_LOGSTOR_SUFFIX		".logstor"
/*
 * Special flag to instruct glogstor to passthrough the underlying provider's
 * physical path
 */
#define G_LOGSTOR_PHYSPATH_PASSTHROUGH "\255"

#ifdef _KERNEL
#define	G_LOGSTOR_DEBUG(lvl, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, (lvl), NULL, __VA_ARGS__)
#define G_LOGSTOR_LOGREQLVL(lvl, bp, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, (lvl), (bp), __VA_ARGS__)
#define	G_LOGSTOR_LOGREQ(bp, ...)	G_LOGSTOR_LOGREQLVL(3, (bp), __VA_ARGS__)

TAILQ_HEAD(wiplist, g_logstor_wip);

#define	SIG_LOGSTOR	0x4C4F4753	// "LOGS": Log-Structured Storage
#define	VER_MAJOR	0
#define	VER_MINOR	1

#define SEG_DATA_START	1	// the data segment starts here
#define SEG_SUM_OFFSET	(SECTORS_PER_SEG - 1) // segment summary offset in segment
#define	SEG_SIZE	0x400000		// 4M
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE) // 1024
#define SA2SEGA_SHIFT	10
#define BLOCKS_PER_SEG	(SEG_SIZE/SECTOR_SIZE - 1)

/*
  The max file size is 1K*1K*4K=4G, each entry is 4 bytes
  so the max block number is 4G/4 = 1G
*/
#define BLOCK_MAX	0x40000000	// 1G
#define	META_START	(((union meta_addr){.meta = 0xFF}).uint32)	// metadata block address start
#define	IS_META_ADDR(x)	((x) >= META_START)
// the address [BLOCK_MAX..META_STAR) are invalid block/metadata address
#define BLOCK_INVALID	BLOCK_MAX
#define META_INVALID	BLOCK_MAX
#define	SECTOR_SIZE	0x1000	// 4K

enum {
	SECTOR_NULL,	// the metadata are all NULL
	SECTOR_DEL,	// the file does not exist or don't look the mapping further, it is NULL
	SECTOR_CACHE,	// the root sector of the file is still in the cache
};

#define FBUF_CLEAN_THRESHOLD	32
#define FBUF_MIN	1564
#define FBUF_MAX	(FBUF_MIN * 2)
// the last bucket is reserved for queuing fbufs that will not be searched
#define FBUF_BUCKET_LAST 953	// this should be a prime number
#define FBUF_BUCKET_CNT	(FBUF_BUCKET_LAST+1)

#define FD_COUNT	4		// max number of metadata files supported
#define FD_INVALID	FD_COUNT	// the valid file descriptor are 0 to 3

struct _superblock {
	uint32_t sig;		// signature
	uint8_t  ver_major;
	uint8_t  ver_minor;
	uint16_t sb_gen;	// the generation number. Used for redo after system crash
	/*
	   The segments are treated as circular buffer
	 */
	uint32_t seg_cnt;	// total number of segments
	uint32_t seg_alloc;	// allocate this segment
	uint32_t sector_cnt_free;
	// since the max meta file size is 4G (1K*1K*4K) and the entry size is 4
	// block_cnt_max must be < (4G/4)
	uint32_t block_cnt_max;	// max number of blocks supported
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
	uint32_t fd_root[FD_COUNT];	// the root sector of the file
	uint8_t fd_prev;	// the file descriptor for previous current mapping
	uint8_t fd_snap;	// the file descriptor for snapshot mapping
	uint8_t fd_cur;		// the file descriptor for current mapping
	uint8_t fd_snap_new;	// the file descriptor for new snapshot mapping
};

#if !defined(WYC)
_Static_assert(sizeof(struct _superblock) < SECTOR_SIZE, "The size of the super block must be smaller than SECTOR_SIZE");
#endif

/*
  The last sector in a segment is the segment summary. It stores the reverse mapping table
*/
struct _seg_sum {
	uint32_t ss_rm[SECTORS_PER_SEG - 1];	// reverse map
	// reverse map SECTORS_PER_SEG - 1 is not used so we store something here
	uint32_t ss_alloc;	// the sector for allocation in the segment
	//uint32_t ss_gen;  // sequence number. used for redo after system crash
};

_Static_assert(sizeof(struct _seg_sum) == SECTOR_SIZE,
    "The size of segment summary must be equal to SECTOR_SIZE");

/*
  Forward map and its indirect blocks are also stored in the downstream disk.
  The sectors used to store the forward map and its indirect blocks are called metadata.

  Each metadata block has a corresponding metadata address.
  Below is the format of the metadata address.

  The metadata address occupies a small portion of block address space.
  For block address that is >= META_START, it is actually a metadata address.
*/
union meta_addr { // metadata address for file data and its indirect blocks
	uint32_t	uint32;
	struct {
		uint32_t index1 :10;	// index for indirect block of depth 1
		uint32_t index0 :10;	// index for indirect block of depth 0
		uint32_t depth	:2;	// depth of the node
		uint32_t fd	:2;	// file descriptor
		uint32_t meta	:8;	// 0xFF for metadata address
	};
	struct {
		uint32_t index :20;	// index for indirect blocks
	};
};

_Static_assert(sizeof(union meta_addr) == 4, "The size of emta_addr must be 4");

enum {
	QUEUE_IND0,	// for level 0 indirect blocks
	QUEUE_IND1,	// for level 1 indirect blocks
	QUEUE_LEAF_DIRTY,	// the modified part of the leaf nodes
	QUEUE_LEAF_CLEAN,	// the clean part of the leaf nodes
	QUEUE_CNT,
};
#define META_LEAF_DEPTH	QUEUE_LEAF_DIRTY

_Static_assert(QUEUE_IND0 == 0, "QUEUE_IND0 must be 0");
_Static_assert(QUEUE_IND1 == 1, "QUEUE_IND1 must be 1");

struct _fbuf_comm {
	struct _fbuf *queue_next;
	struct _fbuf *queue_prev;
	bool is_sentinel;
	bool accessed;	/* only used for fbufs on circular queue */
	bool modified;	/* the fbuf is dirty */
};

struct _fbuf_sentinel {
	struct _fbuf_comm fc;
};

/*
  Metadata is cached in memory. The access unit of metadata is block so each cache line
  stores a block of metadata
*/
struct _fbuf { // file buffer
	struct _fbuf_comm fc;
	struct _fbuf *bucket_next;
	struct _fbuf *bucket_prev;
	struct _fbuf *parent;
	uint16_t child_cnt; // number of children reference this fbuf

	union meta_addr	ma;	// the metadata address
	uint16_t queue_which;
#if defined(INVARIANTS)
	uint16_t bucket_which;
	uint32_t sa;	// the sector address of the @data
#endif
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
};

/*
 * State maintained by each instance of a LOGSTOR GEOM.
 */
struct g_logstor_softc {
	uint32_t seg_alloc_start;// the starting segment for _logstor_write
	uint32_t seg_alloc_sa;	// the sector address of the segment for allocation
	struct _seg_sum seg_sum;// segment summary for the hot segment
	uint32_t sb_sa; 	// superblock's sector address
	bool sb_modified;	// is the super block modified
	bool ss_modified;	// is segment summary modified

	int fbuf_count;
	struct _fbuf *fbufs;	// an array of fbufs
	struct _fbuf *fbuf_alloc; // point to the fbuf candidate for replacement
	struct _fbuf_sentinel fbuf_queue[QUEUE_CNT];
	int fbuf_queue_len[QUEUE_CNT];

	// buffer hash queue
	struct _fbuf_sentinel fbuf_bucket[FBUF_BUCKET_CNT];
#if defined(INVARIANTS)
	int fbuf_bucket_len[FBUF_BUCKET_CNT];
#endif
	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;
	struct _superblock superblock;

	struct rwlock	   sc_rwlock;		/* writemap lock */
	uint64_t	 **sc_writemap_root;	/* root of write map */
	uint64_t	  *sc_leafused;		/* 1 => leaf has allocation */
	uint64_t	   sc_map_size;		/* size of write map */
	long		   sc_root_size;	/* entries in root node */
	long		   sc_leaf_size;	/* entries in leaf node */
	long		   sc_bits_per_leaf;	/* bits per leaf node entry */
	long		   sc_writemap_memory;	/* memory used by writemap */
	off_t		   sc_offset;		/* starting offset in lower */
	off_t		   sc_size;		/* size of logstor geom */
	off_t		   sc_sectorsize;	/* sector size of geom */
	struct g_consumer *sc_uppercp;		/* upper-level provider */
	struct g_consumer *sc_lowercp;		/* lower-level provider */
	struct wiplist	   sc_wiplist;		/* I/O work-in-progress list */
	long		   sc_flags;		/* see flags below */
	long		   sc_reads;		/* number of reads done */
	long		   sc_wrotebytes;	/* number of bytes written */
	long		   sc_writes;		/* number of writes done */
	long		   sc_readbytes;	/* number of bytes read */
	long		   sc_deletes;		/* number of deletes done */
	long		   sc_getattrs;		/* number of getattrs done */
	long		   sc_flushes;		/* number of flushes done */
	long		   sc_cmd0s;		/* number of cmd0's done */
	long		   sc_cmd1s;		/* number of cmd1's done */
	long		   sc_cmd2s;		/* number of cmd2's done */
	long		   sc_speedups;		/* number of speedups done */
	long		   sc_readcurrentread;	/* reads current with read */
	long		   sc_readblockwrite;	/* writes blocked by read */
	long		   sc_writeblockread;	/* reads blocked by write */
	long		   sc_writeblockwrite;	/* writes blocked by write */
};

/*
 * Structure to track work-in-progress I/O operations.
 *
 * Used to prevent overlapping I/O operations from running concurrently.
 * Created for each I/O operation.
 *
 * In usual case of no overlap it is linked to sc_wiplist and started.
 * If found to overlap an I/O on sc_wiplist, it is not started and is
 * linked to wip_waiting list of the I/O that it overlaps. When an I/O
 * completes, it restarts all the I/O operations on its wip_waiting list.
 */
struct g_logstor_wip {
	struct wiplist		 wip_waiting;	/* list of I/Os waiting on me */
	TAILQ_ENTRY(g_logstor_wip) wip_next;	/* pending or active I/O list */
	struct bio		*wip_bp;	/* bio for this I/O */
	struct g_logstor_softc	*wip_sc;	/* g_logstor's softc */
	off_t			 wip_start;	/* starting offset of I/O */
	off_t			 wip_end;	/* ending offset of I/O */
	long			 wip_numios;	/* BIO_READs in progress */
	long			 wip_error;	/* merged I/O errors */
};

/*
 * LOGSTOR flags
 */
#define DOING_COMMIT	0x00000001	/* a commit command is in progress */

#define DOING_COMMIT_BITNUM	 0	/* a commit command is in progress */

#define BITS_PER_ENTRY	(sizeof(uint64_t) * NBBY)
#define GL_RLOCK(sc)	rw_rlock(&(sc)->sc_rwlock)
#define GL_RUNLOCK(sc)	rw_runlock(&(sc)->sc_rwlock)
#define GL_WLOCK(sc)	rw_wlock(&(sc)->sc_rwlock)
#define GL_WUNLOCK(sc)	rw_wunlock(&(sc)->sc_rwlock)
#define GL_WLOCKOWNED(sc) rw_assert(&(sc)->sc_rwlock, RA_WLOCKED)

/*
 * The writelock is held while a commit operation is in progress.
 * While held logstor device may not be used or in use.
 * Returns == 0 if lock was successfully obtained.
 */
static inline int
g_logstor_get_writelock(struct g_logstor_softc *sc)
{

	return (atomic_testandset_long(&sc->sc_flags, DOING_COMMIT_BITNUM)); // set bit DOING_COMMIT_BITNUM
}

static inline void
g_logstor_rel_writelock(struct g_logstor_softc *sc)
{
	long ret __diagused; // is used only when KASSERT is defined

	ret = atomic_testandclear_long(&sc->sc_flags, DOING_COMMIT_BITNUM); // clear bit DOING_COMMIT_BITNUM
	KASSERT(ret != 0, ("LOGSTOR GEOM releasing unheld lock"));
}

#endif	/* _KERNEL */

#endif	/* _G_LOGSTOR_H_ */
