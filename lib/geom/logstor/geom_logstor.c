/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005 Ivan Voras <ivoras@freebsd.org>
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
#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgeom.h>
#include <err.h>
#include <assert.h>

#include <core/geom.h>
#include <misc/subr.h>

//#include <geom/logstor/g_logstor.h>
#include "../../../sys/geom/logstor/g_logstor.h"

uint32_t lib_version = G_LIB_VERSION;
uint32_t version = G_LOGSTOR_VERSION;

#define	GLOGSTOR_CHUNK_SIZE	"4M"
#define	GLOGSTOR_VIR_SIZE	"2T"

#if G_LIB_VERSION == 1
/* Support RELENG_6 */
#define G_TYPE_BOOL G_TYPE_NONE
#endif

/*
 * logstor_main gets called by the geom(8) utility
 */
static void logstor_main(struct gctl_req *req, unsigned flags);

struct g_command class_commands[] = {
	{ "dump", 0, logstor_main, G_NULL_OPTS,
	    "prov ..."
	},
	{ "label", G_FLAG_VERBOSE | G_FLAG_LOADKLD, logstor_main,
	    {
		{ 'h', "hardcode", NULL, G_TYPE_BOOL},
		{ 'm', "chunk_size", GLOGSTOR_CHUNK_SIZE, G_TYPE_NUMBER},
		{ 's', "vir_size", GLOGSTOR_VIR_SIZE, G_TYPE_NUMBER},
		G_OPT_SENTINEL
	    },
	    "[-h] [-v] [-m chunk_size] [-s vir_size] name provider0 [provider1 ...]"
	},
	{ "destroy", G_FLAG_VERBOSE, NULL,
	    {
		{ 'f', "force", NULL, G_TYPE_BOOL},
		G_OPT_SENTINEL
	    },
	    "[-fv] name ..."
	},
	{ "commit", 0, NULL,
	    {
		{ 'f', "force", NULL, G_TYPE_BOOL },
		{ 'r', "reboot", NULL, G_TYPE_BOOL },
		{ 'v', "verbose", NULL, G_TYPE_BOOL },
		G_OPT_SENTINEL
	    },
	    "[-frv] prov ..."
	},
	{ "revert", 0, NULL,
	    {
		{ 'v', "verbose", NULL, G_TYPE_BOOL },
		G_OPT_SENTINEL
	    },
	    "[-v] prov ..."
	},
	G_CMD_SENTINEL
};

static int verbose = 0;

/* Helper functions' declarations */
static void logstor_dump(struct gctl_req *req);
static void logstor_label(struct gctl_req *req);

/* Dispatcher function (no real work done here, only verbose flag recorder) */
static void
logstor_main(struct gctl_req *req, unsigned flags)
{
	const char *name;

	if ((flags & G_FLAG_VERBOSE) != 0)
		verbose = 1;

	name = gctl_get_ascii(req, "verb");
	if (name == NULL) {
		gctl_error(req, "No '%s' argument.", "verb");
		return;
	}
	if (strcmp(name, "label") == 0)
		logstor_label(req);
	else if (strcmp(name, "dump") == 0)
		logstor_dump(req);
	else
		gctl_error(req, "%s: Unknown command: %s.", __func__, name);
}

/*
 * Labels a new geom Meaning: parses and checks the parameters, calculates &
 * writes metadata to the relevant providers so when the next round of
 * "tasting" comes (which will be just after the provider(s) are closed) geom
 * can be instantiated with the tasted metadata.
 */
static void
logstor_label(struct gctl_req *req)
{
	int nargs;
	const char *name;
	int dev_fd;
	int32_t seg_cnt;
	uint32_t sector_cnt;
	off_t media_size;
	struct logstor_superblock *sb;
	char buf[SECTOR_SIZE] __attribute__((aligned(4)));

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "nargs (%d): expecting: name provider", nargs);
		return;
	}
	name = gctl_get_ascii(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "No 'arg%u' argument.", 0);
		return;
	}
	snprintf(buf, sizeof(buf), "%s%s", _PATH_DEV, name);
	dev_fd = open(buf, O_RDWR);
	if (dev_fd < 0) {
		printf("%s open\n", __func__);
		return;
	}
	media_size = g_mediasize(dev_fd);
	if (media_size < 0) {
		printf("%s g_mediasize\n", __func__);
		return;
	}
	sector_cnt = media_size / SECTOR_SIZE;
	sb = (struct logstor_superblock *)buf;
	sb->magic = G_LOGSTOR_MAGIC;
	sb->ver_major = G_LOGSTOR_VERSION;
	snprintf(sb->name, sizeof(sb->name), "%s%s", name, G_LOGSTOR_SUFFIX);
	sb->sb_gen = arc4random();
	seg_cnt = sector_cnt / SECTORS_PER_SEG;
	// the rest of the superblock is used to store the age of the segments
	if (sizeof(struct logstor_superblock) + seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct logstor_superblock), (int)seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct logstor_superblock)) * (long long)SEG_SIZE);
		exit(1);
	}
	sb->seg_cnt = seg_cnt;
	uint32_t max_block =
	    (seg_cnt - SEG_DATA_START) * BLOCKS_PER_SEG -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT * 4;
	assert(max_block < 0x40000000); // 1G
	sb->block_cnt_max = max_block;

	sb->seg_allocp = SEG_DATA_START;	// start allocate from here

	sb->fd_cur = 0;			// current mapping is file 0
	sb->fd_snap = 1;
	sb->fd_prev = FD_INVALID;	// mapping does not exist
	sb->fd_snap_new = FD_INVALID;
	sb->fd_root[0] = SECTOR_NULL;	// file 0 is all 0
	// the root sector address for files 1, 2 and 3
	for (int i = 1; i < FD_COUNT; i++) {
		sb->fd_root[i] = SECTOR_DEL;	// the file does not exit
	}

	// write out super block
	pwrite(dev_fd, sb, SECTOR_SIZE, 0);

	// clear the rest of the superblock's segment
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SECTORS_PER_SEG; ++i) {
		pwrite(dev_fd, buf, SECTOR_SIZE, i * SECTOR_SIZE);
	}

	// initialize all segment summary blocks
	struct _seg_sum ss;
	for (int i = 0; i < SECTORS_PER_SEG - 1; ++i)
		ss.ss_rm[i] = BLOCK_INVALID;
	for (int i = SEG_DATA_START; i < seg_cnt; ++i)
	{	uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		pwrite(dev_fd, &ss, SECTOR_SIZE, sa);
	}
	close(dev_fd);
}

/* Called by geom(8) via glogstor_main() to dump metadata information */
static void
logstor_dump(struct gctl_req *req __unused)
{
	printf("%s: not implemented yet\n", __func__);
}
