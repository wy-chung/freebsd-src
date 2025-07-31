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

#include <sys/endian.h>

#define	G_LOGSTOR_CLASS_NAME	"LOGSTOR"
#define	G_LOGSTOR_MAGIC		"GEOM::LOGSTOR"
/*
 * Version history:
 * 0 - prove of concept
 */
#define	G_LOGSTOR_VERSION	0

#ifdef _KERNEL
#define G_LOGSTOR_DEBUG(lvl, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, (lvl), NULL, __VA_ARGS__)
#define G_LOGSTOR_LOGREQ(bp, ...) \
    _GEOM_DEBUG("GEOM_LOGSTOR", g_logstor_debug, 2, (bp), __VA_ARGS__)
#endif	/* _KERNEL */

#define	SECTOR_SIZE	0x1000	// 4K

#endif	/* _G_LOGSTOR_H_ */
