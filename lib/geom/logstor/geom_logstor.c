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

#include <geom/logstor/g_logstor_md.h>
#include <geom/logstor/g_logstor.h>

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
#if 0
	{ "clear", G_FLAG_VERBOSE, logstor_main, G_NULL_OPTS,
	    "[-v] prov ..."
	},
#endif
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
	{ "stop", G_FLAG_VERBOSE, NULL,
	    {
		{ 'f', "force", NULL, G_TYPE_BOOL},
		G_OPT_SENTINEL
	    },
	    "[-fv] name ... (alias for \"destroy\")"
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
//static void logstor_clear(struct gctl_req *req);
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
#if 0
	else if (strcmp(name, "clear") == 0)
		logstor_clear(req);
#endif
	else if (strcmp(name, "dump") == 0)
		logstor_dump(req);
	else
		gctl_error(req, "%s: Unknown command: %s.", __func__, name);

	/* No CTASSERT in userland
	CTASSERT(LOGSTOR_MAP_BLOCK_ENTRIES*LOGSTOR_MAP_ENTRY_SIZE == MAXPHYS);
	*/
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
		gctl_error(req, "Too few arguments (%d): expecting: name provider", nargs);
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
	sb->sig = SIG_LOGSTOR;
	sb->ver_major = VER_MAJOR;
	sb->ver_minor = VER_MINOR;
	snprintf(sb->name, sizeof(sb->name), "%s%s", name, G_LOGSTOR_SUFFIX);
	sb->sb_gen = arc4random();
	seg_cnt = sector_cnt / SECTORS_PER_SEG;
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
	// the root sector address for the files 1, 2 and 3
	for (int i = 1; i < FD_COUNT; i++) {
		sb->fd_root[i] = SECTOR_DEL;	// the file does not exit
	}

	// write out super block
	pwrite(dev_fd, sb, SECTOR_SIZE, 0);

	// clear the rest of the supeblock's segment
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SECTORS_PER_SEG; i++) {
		pwrite(dev_fd, buf, SECTOR_SIZE, i * SECTOR_SIZE);
	}
	struct _seg_sum ss;
	for (int i = 0; i < SECTORS_PER_SEG - 1; ++i)
		ss.ss_rm[i] = BLOCK_INVALID;
	// initialize all segment summary blocks
	for (int i = SEG_DATA_START; i < seg_cnt; ++i)
	{	uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		pwrite(dev_fd, &ss, SECTOR_SIZE, sa);
	}
	close(dev_fd);
}

#if 0
/* Clears metadata on given provider(s) IF it's owned by us */
static void
logstor_clear(struct gctl_req *req)
{
	const char *name;
	char param[32];
	unsigned i;
	int nargs, error;
	int fd;

	nargs = gctl_get_int(req, "nargs");
	if (nargs < 1) {
		gctl_error(req, "Too few arguments.");
		return;
	}
	for (i = 0; i < (unsigned)nargs; i++) {
		snprintf(param, sizeof(param), "arg%u", i);
		name = gctl_get_ascii(req, "%s", param);

		error = g_metadata_clear(name, G_LOGSTOR_MAGIC);
		if (error != 0) {
			fprintf(stderr, "Can't clear metadata on %s: %s "
			    "(do I own it?)\n", name, strerror(error));
			gctl_error(req,
			    "Not fully done (can't clear metadata).");
			continue;
		}
		if (strncmp(name, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
			fd = open(name, O_RDWR);
		else {
			sprintf(param, "%s%s", _PATH_DEV, name);
			fd = open(param, O_RDWR);
		}
		if (fd < 0) {
			gctl_error(req, "Cannot clear header sector for %s",
			    name);
			continue;
		}
		if (verbose)
			printf("Metadata cleared on %s.\n", name);
	}
}

/* Print some metadata information */
static void
logstor_metadata_dump(const struct g_logstor_metadata *md)
{
	printf("          Magic string: %s\n", md->md_magic);
	printf("      Metadata version: %u\n", (u_int) md->md_version);
	printf("           Device name: %s\n", md->md_name);
	printf("             Device ID: %u\n", (u_int) md->md_id);
	printf("        Provider index: %u\n", (u_int) md->no);
	printf("      Active providers: %u\n", (u_int) md->md_count);
	printf("    Hardcoded provider: %s\n",
	    md->provider[0] != '\0' ? md->provider : "(not hardcoded)");
	printf("          Virtual size: %u MB\n",
	    (unsigned int)(md->md_virsize/(1024 * 1024)));
	printf("            Chunk size: %u kB\n", md->md_chunk_size / 1024);
	printf("    Chunks on provider: %u\n", md->chunk_count);
	printf("           Chunks free: %u\n", md->chunk_count - md->chunk_next);
	printf("       Reserved chunks: %u\n", md->chunk_reserved);
}
#endif

/* Called by geom(8) via glogstor_main() to dump metadata information */
static void
logstor_dump(struct gctl_req *req __unused)
{
#if 0
	struct g_logstor_metadata md;
	u_char tmpmd[512];	/* temporary buffer */
	const char *name;
	char param[16];
	int nargs, error, i;

	assert(sizeof(tmpmd) >= sizeof(md));

	nargs = gctl_get_int(req, "nargs");
	if (nargs < 1) {
		gctl_error(req, "Too few arguments.");
		return;
	}
	for (i = 0; i < nargs; i++) {
		snprintf(param, sizeof(param), "arg%u", i);
		name = gctl_get_ascii(req, "%s", param);

		error = g_metadata_read(name, (u_char *) & tmpmd, sizeof(tmpmd),
		    G_LOGSTOR_MAGIC);
		if (error != 0) {
			fprintf(stderr, "Can't read metadata from %s: %s.\n",
			    name, strerror(error));
			gctl_error(req,
			    "Not fully done (error reading metadata).");
			continue;
		}
		logstor_metadata_decode((u_char *) & tmpmd, &md);
		printf("Metadata on %s:\n", name);
		logstor_metadata_dump(&md);
		printf("\n");
	}
#endif
}
