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

#ifndef	_G_LOGSTOR_H_
#define	_G_LOGSTOR_H_

#define	G_LOGSTOR_CLASS_NAME	"LOGSTOR"
#define	G_LOGSTOR_MAGIC		0x4C4F4753	// "LOGS": Log-Structured Storage
/*
 * Version history:
 * 0 - prove of concept
 */
#define	G_LOGSTOR_VERSION	0

#ifdef _KERNEL
#define G_LOGSTOR_DEBUG(lvl, fmt, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, (lvl), NULL, fmt, ## __VA_ARGS__)
#define G_LOGSTOR_LOGREQ(bp, fmt, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, 2, (bp), fmt, ## __VA_ARGS__)
#endif	/* _KERNEL */

#define	SEG_SIZE	0x400000	// 4M
#define	SECTOR_SIZE	0x1000		// 4K
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE)	// 1024
#define SEG_SUM_OFFSET	(SECTORS_PER_SEG - 1)	// segment summary offset
#define BLOCKS_PER_SEG	(SECTORS_PER_SEG - 1)
#define SB_CNT	8	// number of superblock sectors

#define FD_COUNT	4		// max number of metadata files supported
#define FD_INVALID	FD_COUNT	// the valid file descriptor are 0 to 3

struct _superblock {
	uint32_t magic;
	uint32_t version;
	uint64_t provsize;	// Provider's size
	uint32_t sb_gen;	// the generation number. Used for redo after system crash
	/*
	   The segments are treated as circular buffer
	 */
	uint32_t seg_cnt;	// total number of segments
	// since the max file size is 4G (1K*1K*4K) and the entry size is 4
	// block_cnt must be < (4G/4)
	uint32_t block_cnt;	// max block number for the virtual disk

	uint32_t seg_allocp;	// allocate from this segment
	//uint32_t sectors_free;// not implemented yet
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
	struct { // file table
		uint32_t root;	// the root sector of the file
		uint32_t written;// number of blocks written to this virtual disk
	} ft[FD_COUNT];
	uint8_t fd_prev;	// the file descriptor for previous current mapping
	uint8_t fd_snap;	// the file descriptor for snapshot mapping
	uint8_t fd_cur;		// the file descriptor for current mapping
	uint8_t fd_snap_new;	// the file descriptor for new snapshot mapping
} __packed;

_Static_assert(sizeof(struct _superblock) < SECTOR_SIZE,
	"The size of the super block must be smaller than SECTOR_SIZE");

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

#endif	/* _G_LOGSTOR_H_ */
