/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2006-2007 Ivan Voras <ivoras@freebsd.org>
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

#ifndef _G_LOGSTOR_H_
#define _G_LOGSTOR_H_

#define	G_LOGSTOR_CLASS_NAME "LOGSTOR"

#define LOGSTOR_MAP_ALLOCATED 1
struct logstor_map_entry {
	uint16_t	flags;
	uint16_t	provider_no;
	uint32_t	provider_chunk;
};

#define	LOGSTOR_MAP_ENTRY_SIZE (sizeof(struct logstor_map_entry))
#define	LOGSTOR_MAP_BLOCK_ENTRIES (maxphys / LOGSTOR_MAP_ENTRY_SIZE)
/* Struct size is guarded by MPASS in main source */

#ifdef _KERNEL

#define	LOG_MSG(lvl, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, (lvl), NULL, __VA_ARGS__)
#define	LOG_MESSAGE LOG_MSG

#define	LOG_REQ(lvl, bp, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, (lvl), (bp), __VA_ARGS__)
#define	LOG_REQUEST LOG_REQ

/* "critical" system announcements (e.g. "geom is up") */
#define	LVL_ANNOUNCE	0
/* errors */
#define	LVL_ERROR	1
/* warnings */
#define	LVL_WARNING	2
/* info, noncritical for system operation (user doesn't have to see it */
#define	LVL_INFO	5
/* debug info */
#define	LVL_DEBUG	10
/* more debug info */
#define	LVL_DEBUG2	12
/* superfluous debug info (large volumes of data) */
#define	LVL_MOREDEBUG	15

/* Component data */
struct g_logstor_component {
	struct g_consumer	*gcons;
	struct g_logstor_softc	*sc;
	unsigned int		 index;		/* Component index in array */
	unsigned int		 chunk_count;
	unsigned int		 chunk_next;
	unsigned int		 chunk_reserved;
	unsigned int		 flags;
};

/* "delayed BIOs" Queue element */
struct g_logstor_bio_q {
	struct bio		*bio;
	STAILQ_ENTRY(g_logstor_bio_q) linkage;
};

#define	SECTOR_SIZE	0x1000	// 4K

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
#endif
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
};

/* Internal geom instance data */
struct g_logstor_softc {
	struct g_geom		*geom;
	struct g_provider	*provider;
	struct g_logstor_component *components;
	u_int			 n_components;
	u_int			 curr_component; /* Component currently used */
	uint32_t		 id;		/* Unique ID of this geom */
	off_t			 virsize;	/* Total size of logstor */
	off_t			 sectorsize;
	size_t			 chunk_size;
	size_t			 chunk_count;	/* governs map_size */
	struct logstor_map_entry *map;
	size_t			 map_size;	/* (in bytes) */
	size_t			 map_sectors;	/* Size of map in sectors */
	size_t			 me_per_sector;	/* # map entries in a sector */
	STAILQ_HEAD(, g_logstor_bio_q)	 delayed_bio_q;	/* Queue of delayed BIOs */
	struct mtx		 delayed_bio_q_mtx;
//=========================
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
	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;

	/*
	  The macro RAM_DISK_SIZE is used for debug.
	  By using RAM as the storage device, the test can run way much faster.
	*/
	struct _superblock superblock;
};

uint32_t logstor_init(void);
void logstor_fini(void);
int  logstor_open(const char *disk_file);
void logstor_close(void);
uint32_t logstor_read(uint32_t ba, void *data);
uint32_t logstor_write(uint32_t ba, void *data);
void logstor_commit(void);
int logstor_delete(off_t offset, void *data, off_t length);
uint32_t logstor_get_block_cnt(void);
unsigned logstor_get_data_write_count(void);
unsigned logstor_get_other_write_count(void);
unsigned logstor_get_fbuf_hit(void);
unsigned logstor_get_fbuf_miss(void);

#endif	/* _KERNEL */

#endif	/* !_G_LOGSTOR_H_ */
