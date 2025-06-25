/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2004-2006 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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

#ifndef	_G_NOP_H_
#define	_G_NOP_H_

#define	G_NOP_CLASS_NAME	"NOP"
#define	G_NOP_VERSION		4
#define	G_NOP_SUFFIX		".nop"
/*
 * Special flag to instruct gnop to passthrough the underlying provider's
 * physical path
 */
#define G_NOP_PHYSPATH_PASSTHROUGH "\255" // it is 173 in decimal (2 *8^2+ 5 *8^1+ 5 *8^0)

#ifdef _KERNEL
#define	G_NOP_DEBUG(lvl, ...) \
    _GEOM_DEBUG("GEOM_NOP", g_nop_debug, (lvl), NULL, __VA_ARGS__)
#define G_NOP_LOGREQLVL(lvl, bp, ...) \
    _GEOM_DEBUG("GEOM_NOP", g_nop_debug, (lvl), (bp), __VA_ARGS__)
#define	G_NOP_LOGREQ(bp, ...)	G_NOP_LOGREQLVL(2, bp, __VA_ARGS__)

struct g_nop_delay;

TAILQ_HEAD(g_nop_delay_head, g_nop_delay);

struct g_nop_softc {
	int			 sc_error;	// EIO the error number returned to upper layer when fail is injected
	off_t			 sc_offset;
	off_t			 sc_explicitsize; // the size specified in create
	off_t			 sc_stripesize;
	off_t			 sc_stripeoffset;
	u_int			 sc_rfailprob;	// default 0
	u_int			 sc_wfailprob;	// default 0
	u_int			 sc_delaymsec;	// default 1
	u_int			 sc_rdelayprob;	// default 0
	u_int			 sc_wdelayprob;	// default 0
	u_int			 sc_count_until_fail; // default 0
	uintmax_t		 sc_reads;
	uintmax_t		 sc_writes;
	uintmax_t		 sc_deletes;
	uintmax_t		 sc_getattrs;
	uintmax_t		 sc_flushes;
	uintmax_t		 sc_cmd0s;
	uintmax_t		 sc_cmd1s;
	uintmax_t		 sc_cmd2s;
	uintmax_t		 sc_speedups;
	uintmax_t		 sc_readbytes;
	uintmax_t		 sc_wrotebytes;
	char			*sc_physpath;	// NULL, Physical path of the transparent provider
	struct mtx		 sc_lock;
	struct g_nop_delay_head	 sc_head_delay;
};
#endif	/* _KERNEL */

#endif	/* _G_NOP_H_ */
