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

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <libgeom.h>
#include <geom/logstor/g_logstor.h>

#include "core/geom.h"
#include "misc/subr.h"

uint32_t lib_version = G_LIB_VERSION;
uint32_t version = G_LOGSTOR_VERSION;

static void logstor_main(struct gctl_req *req, unsigned flags);
static void logstor_label(struct gctl_req *req);

struct g_command class_commands[] = {
	{ "label", G_FLAG_LOADKLD, logstor_main,
	    {
		G_OPT_SENTINEL
	    },
	    "name"
	},
	{ "create", G_FLAG_LOADKLD, NULL,
	    {
		G_OPT_SENTINEL
	    },
	    "dev"
	},
	{ "snapshot", 0, NULL,
	    {
		G_OPT_SENTINEL
	    },
	    "prov"
	},
	{ "rollback", 0, NULL,
	    {
		G_OPT_SENTINEL
	    },
	    "prov"
	},
	{ "destroy", 0, NULL,
	    {
		{ 'f', "force", NULL, G_TYPE_BOOL },
		G_OPT_SENTINEL
	    },
	    "[-f] prov ..."
	},
	G_CMD_SENTINEL
};

static void
logstor_main(struct gctl_req *req, unsigned flags __unused)
{
	const char *name;

	name = gctl_get_ascii(req, "verb");
	if (name == NULL) {
		gctl_error(req, "No '%s' argument.", "verb");
		return;
	}
	if (strcmp(name, "label") == 0) {
		logstor_label(req);
	} else
		gctl_error(req, "Unknown command: %s.", name);
}

static void
logstor_label(struct gctl_req *req)
{
	struct _inv_map *inv_map;
	int error;
	uint32_t sector_cnt;

	const char *name = gctl_get_ascii(req, "arg0");
	int fd = g_open(name, 1);
	if (fd == -1) {
		return;
	}
	off_t provsize = g_mediasize(fd);
	if (provsize == -1) {
		fprintf(stderr, "Can't get mediasize of %s: %s.\n",
		    name, strerror(errno));
		gctl_error(req, "Not fully done.");
		return;
	}
	char *buf = malloc(SECTOR_SIZE);
	struct _superblock *sb = (struct _superblock *)buf;
	sb->magic = G_LOGSTOR_MAGIC;
	sb->version = G_LOGSTOR_VERSION;
	sb->sb_gen = arc4random();
	sb->provsize = provsize;
	sector_cnt = sb->provsize / SECTOR_SIZE;
	uint32_t seg_cnt = sector_cnt / SECTORS_PER_SEG;
	sb->seg_cnt = seg_cnt;
	sb->block_cnt = sb->seg_cnt * BLOCKS_PER_SEG - SB_CNT -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FM_COUNT * 4;
	assert(sb->block_cnt < 0x40000000); // 1G
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
	for (int i = 1; i < FM_COUNT; i++) {
		sb->fmt[i].root = SECTOR_DEL;	// read returns 0 and write not allowed
		sb->fmt[i].written = 0;
	}
	memset((char *)sb + sizeof(*sb), 0, SECTOR_SIZE - sizeof(*sb));

	// write out the first super block
	if (pwrite(fd, sb, SECTOR_SIZE, 0) != SECTOR_SIZE) {
		error = errno;
		fprintf(stderr, "Can't store metadata[0] on %s: %s.\n",
		    name, strerror(error));
		gctl_error(req, "Not fully done.");
		goto fail;
	}

	// clear the rest of the supeblocks
	memset(buf, 0, SECTOR_SIZE);
	for (int i = 1; i < SB_CNT; i++) {
		if (pwrite(fd, buf, SECTOR_SIZE, i * SECTOR_SIZE) != SECTOR_SIZE) {
			error = errno;
			fprintf(stderr, "Can't store metadata[%d] on %s: %s.\n",
			    i, name, strerror(error));
			gctl_error(req, "Not fully done.");
			goto fail;
		}
	}
	// initialize the inverse map
	inv_map = (typeof(inv_map))buf;
	for (int i = 0; i < BLOCKS_PER_SEG; ++i)
		inv_map->ba[i] = BLOCK_INVALID;

	// write out the inverse map at the end of every segment
	for (uint32_t i = 0; i < seg_cnt; ++i) {
		uint32_t sa = sega2sa(i) + INV_MAP_OFFSET;
		if (pwrite(fd, inv_map, SECTOR_SIZE, (off_t)sa * SECTOR_SIZE) != SECTOR_SIZE) {
			error = errno;
			fprintf(stderr, "Can't store metadata on %s: %s.\n",
			    name, strerror(error));
			gctl_error(req, "Not fully done.");
			goto fail;
		}
	}
	(void)g_flush(fd);
fail:
	free(buf);
	(void)g_close(fd);
}
