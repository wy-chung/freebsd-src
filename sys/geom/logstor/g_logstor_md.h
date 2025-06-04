/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2005 Ivan Voras <ivoras@gmail.com>
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

#ifndef _G_LOGSTOR_MD_H_
#define _G_LOGSTOR_MD_H_

/*
 * Metadata declaration
 */

#define	G_LOGSTOR_MAGIC		"GEOM::LOGSTOR"
#define	G_LOGSTOR_VERSION	1

/* flag: provider is allocated */
#define	LOGSTOR_PROVIDER_ALLOCATED	1
/* flag: provider is currently being filled (usually it's the last
 * provider with LOGSTOR_PROVIDER_ALLOCATED flag */
#define LOGSTOR_PROVIDER_CURRENT	2

struct g_logstor_metadata {
	/* Data global to the logstor device */
	char		md_magic[16];		/* Magic value. */
	uint32_t	md_version;		/* Version number. */
	char		md_name[16];		/* Device name (e.g. "mydata") */
	uint32_t	md_id;			/* Unique ID. */
	uint64_t	md_virsize;		/* Virtual device's size */
	uint32_t	md_chunk_size;		/* Chunk size in bytes */
	uint16_t	md_count;		/* Total number of providers */

	/* Data local to this provider */
	char		provider[16];		/* Hardcoded provider name */
	uint16_t	no;			/* Provider number/index */
	uint64_t	provsize;		/* Provider's size */
	uint32_t	chunk_count;		/* Number of chunks in this pr. */
	uint32_t	chunk_next;		/* Next chunk to allocate */
	uint16_t	chunk_reserved;		/* Count of "reserved" chunks */
	uint16_t	flags;			/* Provider's flags */
};

void logstor_metadata_encode(struct g_logstor_metadata *md, unsigned char *data);
void logstor_metadata_decode(unsigned char *data, struct g_logstor_metadata *md);

#endif	/* !_G_LOGSTOR_H_ */
