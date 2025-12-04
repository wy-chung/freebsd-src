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
//#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <libgeom.h>
#include <geom/logstor/g_logstor.h>

#include "core/geom.h"
#include "misc/subr.h"

uint32_t lib_version = G_LIB_VERSION;
uint32_t version = G_LOGSTOR_VERSION;

static void logstor_main(struct gctl_req *req, unsigned flags);

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

static void __unused
logstor_label(struct gctl_req *req __unused)
{
#if 0
	struct _seg_sum *seg_sum;
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

	sb->ft[0].root = SECTOR_NULL;	// file 0 is all 0
	sb->ft[0].written = 0;
	// files 1, 2 and 3: read returns 0 and write not allowed
	for (int i = 1; i < FD_COUNT; i++) {
		sb->ft[i].root = SECTOR_DEL;	// the file does not exit
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
	// initialize the segment summary block
	seg_sum = (struct _seg_sum *)buf;
	for (int i = 0; i < BLOCKS_PER_SEG; ++i)
		seg_sum->ss_rm[i] = BLOCK_INVALID;

	// write out the segment summary blocks
	for (int i = 0; i < sb->seg_cnt; ++i) {
		uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		error = g_write_data(cp, (off_t)sa * SECTOR_SIZE, seg_sum, SECTOR_SIZE);
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
#endif
#if 0
	u_char sector[SECTOR_SIZE];
	struct g_concat_metadata md;
	const char *name;
	int error, i, hardcode, nargs;

	bzero(sector, sizeof(sector));
	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Incorrect number of arguments.");
		return;
	}
	hardcode = gctl_get_int(req, "hardcode");

	/*
	 * Clear last sector first to spoil all components if device exists.
	 */
	for (i = 1; i < nargs; i++) {
		name = gctl_get_ascii(req, "arg%d", i);
		error = g_metadata_clear(name, NULL);
		if (error != 0) {
			gctl_error(req, "Can't store metadata on %s: %s.", name,
			    strerror(error));
			return;
		}
	}

	strlcpy(md.md_magic, G_CONCAT_MAGIC, sizeof(md.md_magic));
	md.md_version = G_CONCAT_VERSION;
	name = gctl_get_ascii(req, "arg0");
	strlcpy(md.md_name, name, sizeof(md.md_name));
	md.md_id = arc4random();
	md.md_all = nargs - 1;

	/*
	 * Ok, store metadata.
	 */
	for (i = 1; i < nargs; i++) {
		name = gctl_get_ascii(req, "arg%d", i);
		md.md_no = i - 1;
		if (!hardcode)
			bzero(md.md_provider, sizeof(md.md_provider));
		else {
			if (strncmp(name, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
				name += sizeof(_PATH_DEV) - 1;
			strlcpy(md.md_provider, name, sizeof(md.md_provider));
		}
		md.md_provsize = g_get_mediasize(name);
		if (md.md_provsize == 0) {
			fprintf(stderr, "Can't get mediasize of %s: %s.\n",
			    name, strerror(errno));
			gctl_error(req, "Not fully done.");
			continue;
		}
		concat_metadata_encode(&md, sector);
		error = g_metadata_store(name, sector, sizeof(sector));
		if (error != 0) {
			fprintf(stderr, "Can't store metadata on %s: %s.\n",
			    name, strerror(error));
			gctl_error(req, "Not fully done.");
			continue;
		}
		if (verbose)
			printf("Metadata value stored on %s.\n", name);
	}
#endif
}

static void
logstor_main(struct gctl_req *req, unsigned flags __unused)
{
	const char *name;

	//if ((flags & G_FLAG_VERBOSE) != 0)
	//	verbose = 1;

	name = gctl_get_ascii(req, "verb");
	if (name == NULL) {
		gctl_error(req, "No '%s' argument.", "verb");
		return;
	}
	if (strcmp(name, "label") == 0) {
		//logstor_label(req);
		gctl_error(req, "Command %s not implemented yet.", name);
	} else
		gctl_error(req, "Unknown command: %s.", name);
}
