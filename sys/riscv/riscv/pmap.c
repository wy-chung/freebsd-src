/*-
 * SPDX-License-Identifier: BSD-4-Clause
 *
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 * Copyright (c) 1994 David Greenman
 * All rights reserved.
 * Copyright (c) 2003 Peter Wemm
 * All rights reserved.
 * Copyright (c) 2005-2010 Alan L. Cox <alc@cs.rice.edu>
 * All rights reserved.
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
 * Copyright (c) 2014 The FreeBSD Foundation
 * All rights reserved.
 * Copyright (c) 2015-2018 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
 *
 * Portions of this software were developed by Andrew Turner under
 * sponsorship from The FreeBSD Foundation.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from:	@(#)pmap.c	7.7 (Berkeley)	5/12/91
 */
/*-
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Jake Burkholder,
 * Safeport Network Services, and Network Associates Laboratories, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
/*
 *	Manages physical address maps.
 *
 *	Since the information managed by this module is
 *	also stored by the logical address mapping module,
 *	this module may throw away valid virtual-to-physical
 *	mappings at almost any time.  However, invalidations
 *	of virtual-to-physical mappings must be done as
 *	requested.
 *
 *	In order to cope with hardware architectures which
 *	make virtual-to-physical map invalidates expensive,
 *	this module may delay invalidate or reduced protection
 *	operations until such time as they are actually
 *	necessary.  This module is given full information as
 *	to which processors are currently using which maps,
 *	and to when physical maps must be made correct.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bitstring.h>
#include <sys/bus.h>
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/msgbuf.h>
#include <sys/mutex.h>
#include <sys/physmem.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sx.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>
#include <vm/vm_radix.h>
#include <vm/vm_reserv.h>
#include <vm/vm_dumpset.h>
#include <vm/uma.h>

#include <machine/machdep.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/sbi.h>

/*
 * Boundary values for the page table page index space:
 *
 * L3 pages: [0, NL3PTP)
 * L2 pages: [NL3PTP, NL3PTP + NL2PTP)
 * L1 pages: [NL3PTP + NL2PTP, NL3PTP + NL2PTP + NL1PTP)
 *
 * Note that these ranges are used in both SV39 and SV48 mode.  In SV39 mode the
 * ranges are not fully populated since there are at most Ln_ENTRIES^2 L3 pages
 * in a set of page tables.
 */
#define	NL1PTP		Ln_ENTRIES		// total number of l1 page table pages
#define	NL2PTP		(NL1PTP * Ln_ENTRIES)	// total number of l2 page table pages
#define	NL3PTP		(NL2PTP * Ln_ENTRIES)	// total number of l3 page table pages

#ifdef PV_STATS
#define PV_STAT(x)	do { x ; } while (0)
#define	__pv_stat_used
#else
#define PV_STAT(x)	do { } while (0)
#define	__pv_stat_used	__unused
#endif

#define	pmap_l3_pindex(v)	((v) >> L2_SHIFT) // L2_SHIFT == 21
#define	pmap_l2_pindex(v)	(NL3PTP + ((v) >> L1_SHIFT))
#define	pa_to_pvh(pa)		(&pvh_table[pa_index(pa)])

#define	NPV_LIST_LOCKS	MAXCPU
#if !defined(WYC)
#define	PHYS_TO_PV_LIST_LOCK(pa)	\
			(&pv_list_locks[pmap_l3_pindex(pa) % NPV_LIST_LOCKS])

#define	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa)	do {	\
	struct rwlock **_lockp = (lockp);		\
	struct rwlock *_new_lock;			\
							\
	_new_lock = PHYS_TO_PV_LIST_LOCK(pa);		\
	if (_new_lock != *_lockp) {			\
		if (*_lockp != NULL)			\
			rw_wunlock(*_lockp);		\
		*_lockp = _new_lock;			\
		rw_wlock(*_lockp);			\
	}						\
} while (0)

#define	CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m)	\
			CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, VM_PAGE_TO_PHYS(m))

#define	RELEASE_PV_LIST_LOCK(lockp)		do {	\
	struct rwlock **_lockp = (lockp);		\
							\
	if (*_lockp != NULL) {				\
		rw_wunlock(*_lockp);			\
		*_lockp = NULL;				\
	}						\
} while (0)

#define	VM_PAGE_TO_PV_LIST_LOCK(m)	\
			PHYS_TO_PV_LIST_LOCK(VM_PAGE_TO_PHYS(m))
#else
struct rwlock *PHYS_TO_PV_LIST_LOCK(vm_paddr_t pa)
{
	return &pv_list_locks[pmap_l3_pindex(pa) % NPV_LIST_LOCKS];
}

void CHANGE_PV_LIST_LOCK_TO_PHYS(struct rwlock **_lockp, vm_paddr_t pa)
{
	struct rwlock *_new_lock;

	_new_lock = PHYS_TO_PV_LIST_LOCK(pa);
	if (_new_lock != *_lockp) {
		if (*_lockp != NULL)
			rw_wunlock(*_lockp);
		*_lockp = _new_lock;
		rw_wlock(*_lockp);
	}
}

void CHANGE_PV_LIST_LOCK_TO_VM_PAGE(struct rwlock **lockp, vm_page_t m)
{
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, VM_PAGE_TO_PHYS(m));
}

void RELEASE_PV_LIST_LOCK(struct rwlock **_lockp)
{
	if (*_lockp != NULL) {
		rw_wunlock(*_lockp);
		*_lockp = NULL;
	}
}

struct rwlock *VM_PAGE_TO_PV_LIST_LOCK(vm_page_t m)
{
	return PHYS_TO_PV_LIST_LOCK(VM_PAGE_TO_PHYS(m));
}
#endif // defined(WYC)
static SYSCTL_NODE(_vm, OID_AUTO, pmap, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "VM/pmap parameters");

/* The list of all the user pmaps */
typedef LIST_HEAD(, pmap) pmaplist_t;
static pmaplist_t allpmaps = LIST_HEAD_INITIALIZER();

enum _pmap_mode __read_frequently pmap_mode = PMAP_MODE_SV39;
SYSCTL_INT(_vm_pmap, OID_AUTO, mode, CTLFLAG_RDTUN | CTLFLAG_NOFETCH,
    &pmap_mode, 0,
    "translation mode, 0 = SV39, 1 = SV48");

struct pmap kernel_pmap_store;

vm_offset_t virtual_avail;	/* VA of first avail page (after kernel bss) */
vm_offset_t virtual_end;	/* VA of last avail page (end of kernel AS) */
vm_offset_t kernel_vm_end = 0;

vm_paddr_t dmap_phys_base;	/* The start of the dmap region */
vm_paddr_t dmap_phys_max;	/* The limit of the dmap region */
vm_offset_t dmap_max_addr;	/* The virtual address limit of the dmap */

/* This code assumes all L1 DMAP entries will be used */
CTASSERT((DMAP_MIN_ADDRESS  & ~L1_OFFSET) == DMAP_MIN_ADDRESS);
CTASSERT((DMAP_MAX_ADDRESS  & ~L1_OFFSET) == DMAP_MAX_ADDRESS);

/*
 * This code assumes that the early DEVMAP is L2_SIZE aligned and is fully
 * contained within a single L2 entry. The early DTB(Device tree blob) is mapped immediately
 * before the devmap L2 entry.
 */
CTASSERT((PMAP_MAPDEV_EARLY_SIZE & L2_OFFSET) == 0);
CTASSERT((VM_EARLY_DTB_ADDRESS & L2_OFFSET) == 0);
CTASSERT(VM_EARLY_DTB_ADDRESS < (VM_MAX_KERNEL_ADDRESS - PMAP_MAPDEV_EARLY_SIZE));

static struct rwlock_padalign pvh_global_lock;
static struct mtx_padalign allpmaps_lock;

static int __read_frequently superpages_enabled = 1;
SYSCTL_INT(_vm_pmap, OID_AUTO, superpages_enabled,
    CTLFLAG_RDTUN, &superpages_enabled, 0,
    "Enable support for transparent superpages");

static SYSCTL_NODE(_vm_pmap, OID_AUTO, l2, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "2MB page mapping counters");

static u_long pmap_l2_demotions; // the count of l2 demotions
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, demotions, CTLFLAG_RD,
    &pmap_l2_demotions, 0,
    "2MB page demotions");

static u_long pmap_l2_mappings; // the count of l2 mappings
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, mappings, CTLFLAG_RD,
    &pmap_l2_mappings, 0,
    "2MB page mappings");

static u_long pmap_l2_p_failures; // the count of l2 promotion failures
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, p_failures, CTLFLAG_RD,
    &pmap_l2_p_failures, 0,
    "2MB page promotion failures");

static u_long pmap_l2_promotions; // the count of l2 promotions
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, promotions, CTLFLAG_RD,
    &pmap_l2_promotions, 0,
    "2MB page promotions");

/*
 * Data for the pv entry allocation mechanism
 */
typedef TAILQ_HEAD(, pv_chunk) pvc_tailq_t;
static pvc_tailq_t pv_chunks = TAILQ_HEAD_INITIALIZER(pv_chunks); // linked-list of pv_chunks
static struct mtx pv_chunks_mutex;
static struct rwlock pv_list_locks[NPV_LIST_LOCKS];
static struct md_page *pvh_table;
static struct md_page pvh_dummy;

extern cpuset_t all_harts;

/*
 * Internal flags for pmap_enter()'s helper functions.
 */
#define	PMAP_ENTER_NORECLAIM	0x1000000	/* Don't reclaim PV entries. */
#define	PMAP_ENTER_NOREPLACE	0x2000000	/* Don't replace mappings. */

static void	free_pv_chunk(struct pv_chunk *pc);
static void	free_pv_entry(pmap_t pmap, pv_entry_t pv);
static pv_entry_t get_pv_entry(pmap_t pmap, struct rwlock **lockp);
static vm_page_t reclaim_pv_chunk(pmap_t locked_pmap, struct rwlock **lockp);
static void	pmap_pv_pvh_free(struct md_page *pvh, pmap_t pmap, vm_offset_t va);
static pv_entry_t pmap_pv_pvh_remove(struct md_page *pvh, pmap_t pmap,
		    vm_offset_t va);
static bool	pmap_demote_l2(pmap_t pmap, pd_entry_t *l2, vm_offset_t va);
static bool	pmap_demote_l2_locked(pmap_t pmap, pd_entry_t *l2,
		    vm_offset_t va, struct rwlock **lockp);
static int	pmap_enter_l2(pmap_t pmap, vm_offset_t va, pd_entry_t new_l2,
		    u_int flags, vm_page_t m, struct rwlock **lockp);
static vm_page_t pmap_enter_quick_locked(pmap_t pmap, vm_offset_t va,
    vm_page_t m, vm_prot_t prot, vm_page_t mptp, struct rwlock **lockp);
static bool pmap_remove_l3(pmap_t pmap, pt_entry_t *l3, vm_offset_t sva,
    pd_entry_t ptepde, spglist_t *free, struct rwlock **lockp);
static bool pmap_try_insert_pv_entry(pmap_t pmap, vm_offset_t va,
    vm_page_t m, struct rwlock **lockp);

static vm_page_t _pmap_alloc_l3(pmap_t pmap, vm_pindex_t ptepindex,
		struct rwlock **lockp);

static void _pmap_unwire_ptp(pmap_t pmap, vm_offset_t va, vm_page_t m,
    spglist_t *free);
static bool pmap_unuse_pt(pmap_t, vm_offset_t, pd_entry_t, spglist_t *);

static int pmap_change_attr_locked(vm_offset_t va, vm_size_t size, int mode);

#define	pmap_clear(pte)			pmap_store(pte, 0)
#define	pmap_clear_bits(pte, bits)	atomic_clear_64(pte, bits)
#define	pmap_load_store(pte, entry)	atomic_swap_64(pte, entry)
#define	pmap_load_clear(pte)		pmap_load_store(pte, 0)
#define	pmap_load(pte)			atomic_load_64(pte)
#define	pmap_store(pte, entry)		atomic_store_64(pte, entry)
#define	pmap_store_bits(pte, bits)	atomic_set_64(pte, bits)

/********************/
/* Inline functions */
/********************/

static __inline void
pagecopy(void *s, void *d)
{

	memcpy(d, s, PAGE_SIZE);
}

static __inline void
pagezero(void *p)
{

	bzero(p, PAGE_SIZE);
}

#define	pmap_l0_index(va)	(((va) >> L0_SHIFT) & Ln_ADDR_MASK)
#define	pmap_l1_index(va)	(((va) >> L1_SHIFT) & Ln_ADDR_MASK)
#define	pmap_l2_index(va)	(((va) >> L2_SHIFT) & Ln_ADDR_MASK)
#define	pmap_l3_index(va)	(((va) >> L3_SHIFT) & Ln_ADDR_MASK)

#define	PTE_TO_PHYS(pte) \
    ((((pte) & ~PTE_HI_MASK) >> PTE_PPN0_S) << PAGE_SHIFT)
#define	L2PTE_TO_PHYS(l2) \
    ((((l2) & ~PTE_HI_MASK) >> PTE_PPN1_S) << L2_SHIFT)

static __inline pd_entry_t *
pmap_l0(pmap_t pmap, vm_offset_t va)
{
	KASSERT(pmap_mode != PMAP_MODE_SV39, ("%s: in SV39 mode", __func__));
	KASSERT(VIRT_IS_VALID(va),
	    ("%s: malformed virtual address %#lx", __func__, va));
	return (&pmap->pm_top[pmap_l0_index(va)]);
}

static __inline pd_entry_t *
pmap_l0_to_l1(pd_entry_t *l0, vm_offset_t va)
{
	vm_paddr_t phys;
	pd_entry_t *l1pt;

	KASSERT(pmap_mode != PMAP_MODE_SV39, ("%s: in SV39 mode", __func__));
	phys = PTE_TO_PHYS(pmap_load(l0));
	l1pt = (pd_entry_t *)PHYS_TO_DMAP(phys);

	return (&l1pt[pmap_l1_index(va)]);
}

static __inline pd_entry_t *
pmap_l1(pmap_t pmap, vm_offset_t va)
{
	KASSERT(VIRT_IS_VALID(va), ("%s: malformed virtual address %#lx", __func__, va));
	if (pmap_mode == PMAP_MODE_SV39) {
		return (&pmap->pm_top[pmap_l1_index(va)]);
	} else {
		pd_entry_t *l0 = pmap_l0(pmap, va);
		if ((pmap_load(l0) & PTE_V) == 0)
			return (NULL);
		if ((pmap_load(l0) & PTE_RWX) != 0) //ori PTE_RX
			return (NULL);
		return (pmap_l0_to_l1(l0, va));
	}
}

static __inline pd_entry_t *
pmap_l1_to_l2(pd_entry_t *l1, vm_offset_t va)
{
	vm_paddr_t phys;
	pd_entry_t *l2pt;

	phys = PTE_TO_PHYS(pmap_load(l1));
	l2pt = (pd_entry_t *)PHYS_TO_DMAP(phys);

	return (&l2pt[pmap_l2_index(va)]);
}

static __inline pd_entry_t *
pmap_l2(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l1;

	l1 = pmap_l1(pmap, va);
	if (l1 == NULL)
		return (NULL);
	if ((pmap_load(l1) & PTE_V) == 0)
		return (NULL);
	if ((pmap_load(l1) & PTE_RWX) != 0) //ori PTE_RX
		return (NULL);

	return (pmap_l1_to_l2(l1, va));
}

static __inline pt_entry_t *
pmap_l2_to_l3(pd_entry_t *l2, vm_offset_t va)
{
	vm_paddr_t phys;
	pt_entry_t *l3pt;

	phys = PTE_TO_PHYS(pmap_load(l2));
	l3pt = (pd_entry_t *)PHYS_TO_DMAP(phys);

	return (&l3pt[pmap_l3_index(va)]);
}

static __inline pt_entry_t *
pmap_l3(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l2;

	l2 = pmap_l2(pmap, va);
	if (l2 == NULL)
		return (NULL);
	if ((pmap_load(l2) & PTE_V) == 0)
		return (NULL);
	if ((pmap_load(l2) & PTE_RWX) != 0) //ori PTE_RX
		return (NULL);

	return (pmap_l2_to_l3(l2, va));
}

static __inline void
pmap_resident_count_inc(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	pmap->pm_stats.resident_count += count;
}

static __inline void
pmap_resident_count_dec(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(pmap->pm_stats.resident_count >= count,
	    ("pmap %p resident count underflow %ld %d", pmap,
	    pmap->pm_stats.resident_count, count));
	pmap->pm_stats.resident_count -= count;
}

static void
pmap_distribute_l1(struct pmap *pmap, vm_pindex_t l1index, pt_entry_t entry)
{
	struct pmap *user_pmap;
	pd_entry_t *l1;

	/*
	 * Distribute new kernel L1 entry to all the user pmaps.  This is only
	 * necessary with three-level paging configured: with four-level paging
	 * the kernel's half of the top-level page table page is static and can
	 * simply be copied at pmap initialization time (i.e. pmap_pinit)
	 */
	if (pmap == kernel_pmap && pmap_mode == PMAP_MODE_SV39) {
		mtx_lock(&allpmaps_lock);
		LIST_FOREACH(user_pmap, &allpmaps, pm_list) {
			l1 = &user_pmap->pm_top[l1index];
			pmap_store(l1, entry);
		}
		mtx_unlock(&allpmaps_lock);
	}
}

static pt_entry_t *
pmap_early_page_idx(vm_offset_t l1pt_va, vm_offset_t va, u_int *l1_slot, u_int *l2_slot)
{
	pt_entry_t *l2pt;
	pd_entry_t *l1pt __diagused;

	l1pt = (pd_entry_t *)l1pt_va;
	*l1_slot = (va >> L1_SHIFT) & Ln_ADDR_MASK;

	/* Check locore has used a table L1 map */
	KASSERT((l1pt[*l1_slot] & PTE_RWX) == 0, //ori PTE_RX
		("Invalid bootstrap L1 table"));

	/* Find the address of the L2 table */
	l2pt = (pt_entry_t *)init_pt_va;
	*l2_slot = pmap_l2_index(va);

	return (l2pt);
}

static vm_paddr_t
pmap_early_vtophys(vm_offset_t l1pt_va, vm_offset_t va)
{
	u_int l1_slot __unused, l2_slot;
	pt_entry_t *l2pt;
	vm_paddr_t ret;

	l2pt = pmap_early_page_idx(l1pt_va, va, &l1_slot, &l2_slot);

	/* Check locore has used L2 superpages */
	KASSERT((l2pt[l2_slot] & PTE_RWX) != 0, //ori PTE_RX
		("Invalid bootstrap L2 table"));

	/* L2 is superpages */
	ret = L2PTE_TO_PHYS(l2pt[l2_slot]);
	ret += (va & L2_OFFSET);

	return (ret);
}

static void
pmap_bootstrap_dmap(vm_offset_t kern_l1, vm_paddr_t min_pa, vm_paddr_t max_pa)
{
	vm_offset_t va;
	vm_paddr_t pa;

	pd_entry_t *l1pt = (pd_entry_t *)kern_l1;
	u_int l1_slot = pmap_l1_index(DMAP_MIN_ADDRESS);
	dmap_phys_base = min_pa & ~L1_OFFSET;

	for (va = DMAP_MIN_ADDRESS, pa = dmap_phys_base;
	    va < DMAP_MAX_ADDRESS && pa < max_pa;
	    va += L1_SIZE, pa += L1_SIZE) { // 1G size
		KASSERT(l1_slot < Ln_ENTRIES, ("Invalid L1 index"));

		/* 1G pages */
		pn_t pn = (pa / PAGE_SIZE);
		pt_entry_t entry = PTE_KERN; // accessed and dirty are both 1
		entry |= (pn << PTE_PPN0_S);
		pmap_store(&l1pt[l1_slot++], entry);
	}

	/* Set the upper limit of the DMAP region */
	dmap_phys_max = pa;
	dmap_max_addr = va;

	sfence_vma();
}

static vm_offset_t
pmap_bootstrap_l3(vm_offset_t l1pt_va, vm_offset_t va, vm_offset_t l3_start)
{
	KASSERT((va & L2_OFFSET) == 0, ("Invalid virtual address"));

	vm_offset_t l2_va = (vm_offset_t)pmap_l2(kernel_pmap, va);
	pd_entry_t *l2pt = (pd_entry_t *)(l2_va & ~(PAGE_SIZE - 1));
	u_int l2_slot = pmap_l2_index(va);
	vm_offset_t l3pt_va = l3_start;

	for (; va < VM_MAX_KERNEL_ADDRESS; va += L2_SIZE) {
		KASSERT(l2_slot < Ln_ENTRIES, ("Invalid L2 index"));

		vm_paddr_t pa = pmap_early_vtophys(l1pt_va, l3pt_va);
		pn_t pn = (pa / PAGE_SIZE);
		pt_entry_t entry = (PTE_V);
		entry |= (pn << PTE_PPN0_S);
		pmap_store(&l2pt[l2_slot++], entry);
		l3pt_va += PAGE_SIZE;
	}

	/* Clean the L2 page table */
	memset((void *)l3_start, 0, l3pt_va - l3_start);

	return (l3pt_va);
}

/*
 *	Bootstrap the system enough to run with virtual memory.
 */
void
pmap_bootstrap(vm_offset_t l1pt_va, vm_paddr_t kernstart, vm_size_t kernlen) // < initriscv
{
	printf("%s %lx %lx %lx\n", __func__, l1pt_va, kernstart, kernlen);

	/* Set this early so we can use the pagetable walking functions */
	kernel_pmap_store.pm_top = (pd_entry_t *)l1pt_va;
	PMAP_LOCK_INIT(kernel_pmap);
	TAILQ_INIT(&kernel_pmap->pm_pvchunk);
	vm_radix_init(&kernel_pmap->pm_root);

	rw_init(&pvh_global_lock, "pmap pv global");

	/*
	 * Set the current CPU as active in the kernel pmap. Secondary cores
	 * will add themselves later in init_secondary(). The SBI firmware
	 * may rely on this mask being precise, so CPU_FILL() is not used.
	 */
	CPU_SET(PCPU_GET(pc_hart), &kernel_pmap->pm_active);

	/* Assume the address we were loaded to is a valid physical address. */
	vm_paddr_t max_pa, min_pa;
	min_pa = max_pa = kernstart;

	vm_paddr_t physmap[PHYS_AVAIL_ENTRIES];
	u_int physmap_idx = physmem_avail(physmap, nitems(physmap));
	physmap_idx /= 2;

	/*
	 * Find the minimum physical address. physmap is sorted,
	 * but may contain empty ranges.
	 */
	for (int i = 0; i < physmap_idx * 2; i += 2) {
		if (physmap[i] == physmap[i + 1])
			continue;
		if (physmap[i] <= min_pa)
			min_pa = physmap[i];
		if (physmap[i + 1] > max_pa)
			max_pa = physmap[i + 1];
	}
	printf("physmap_idx %u\n", physmap_idx);
	printf("min_pa %lx\n", min_pa);
	printf("max_pa %lx\n", max_pa);

	/* Create a direct map region early so we can use it for pa -> va */
	pmap_bootstrap_dmap(l1pt_va, min_pa, max_pa);

	/*
	 * Read the page table to find out what is already mapped.
	 * This assumes we have mapped a block of memory from KERNBASE
	 * using a single L1 entry.
	 */
	u_int l1_slot __unused, l2_slot;
	(void)pmap_early_page_idx(l1pt_va, KERNBASE, &l1_slot, &l2_slot);

	/* Sanity check the index, KERNBASE should be the first VA */
	KASSERT(l2_slot == 0, ("The L2 index is non-zero"));

	vm_offset_t freemempos = roundup2(KERNBASE + kernlen, PAGE_SIZE);

	/* Create the l3 tables for the early devmap */
	freemempos = pmap_bootstrap_l3(l1pt_va,
	    VM_MAX_KERNEL_ADDRESS - PMAP_MAPDEV_EARLY_SIZE, freemempos);

	/*
	 * Invalidate the mapping we created for the DTB(Device tree blob). At this point a copy
	 * has been created, and we no longer need it. We want to avoid the
	 * possibility of an aliased mapping in the future.
	 */
	pt_entry_t *l2p = pmap_l2(kernel_pmap, VM_EARLY_DTB_ADDRESS);
	if ((pmap_load(l2p) & PTE_V) != 0)
		pmap_clear(l2p);

	sfence_vma();

#define alloc_pages(var, np)						\
	(var) = freemempos;						\
	freemempos += (np * PAGE_SIZE);					\
	memset((char *)(var), 0, ((np) * PAGE_SIZE));

	int mode = 0;
	// the tunables are in /boot/loader.conf
	TUNABLE_INT_FETCH("vm.pmap.mode", &mode);
	mode = PMAP_MODE_SV48; //wyc force it to SV48 mode
	if (mode == PMAP_MODE_SV48 && (mmu_caps & MMU_SV48) != 0) {
		/*
		 * Enable SV48 mode: allocate an L0 page and set SV48 mode in
		 * SATP.  If the implementation does not provide SV48 mode,
		 * the mode read back from the (WARL) SATP register will be
		 * unchanged, and we continue in SV39 mode.
		 */
		vm_offset_t l0pv;
		alloc_pages(l0pv, 1);
		pd_entry_t *l0pt = (pd_entry_t *)l0pv;
		vm_paddr_t l1pa = pmap_early_vtophys(l1pt_va, l1pt_va);
		l0pt[pmap_l0_index(KERNBASE)] = PTE_V |
		    ((l1pa >> PAGE_SHIFT) << PTE_PPN0_S);

		vm_paddr_t l0pa = pmap_early_vtophys(l1pt_va, l0pv);
		csr_write(satp, (l0pa >> PAGE_SHIFT) | SATP_MODE_SV48);
		uint64_t satp = csr_read(satp);
		if ((satp & SATP_MODE_M) == SATP_MODE_SV48) {
			pmap_mode = PMAP_MODE_SV48;
			kernel_pmap_store.pm_top = l0pt;
		} else {
			/* Mode didn't change, give the page back. */
			freemempos -= PAGE_SIZE;
		}
	}

	/* Allocate dynamic per-cpu area. */
	vm_offset_t dpcpu;
	alloc_pages(dpcpu, DPCPU_SIZE / PAGE_SIZE);
	dpcpu_init((void *)dpcpu, 0);

	/* Allocate memory for the msgbuf, e.g. for /sbin/dmesg */
	vm_offset_t msgbufpv;
	alloc_pages(msgbufpv, round_page(msgbufsize) / PAGE_SIZE);
	msgbufp = (void *)msgbufpv;

	virtual_avail = roundup2(freemempos, L2_SIZE);
	virtual_end = VM_MAX_KERNEL_ADDRESS - PMAP_MAPDEV_EARLY_SIZE;
	kernel_vm_end = virtual_avail;

	vm_paddr_t pa = pmap_early_vtophys(l1pt_va, freemempos);

	physmem_exclude_region(kernstart, pa - kernstart, EXFLAG_NOALLOC);
}

/*
 *	Initialize a vm_page's machine-dependent fields.
 */
void
pmap_page_init(vm_page_t m)
{

	TAILQ_INIT(&m->md.pv_list);
	m->md.pv_memattr = VM_MEMATTR_WRITE_BACK;
}

/*
 *	Initialize the pmap module.
 *
 *	Called by vm_mem_init(), to initialize any structures that the pmap
 *	system needs to map virtual memory.
 */
void
pmap_init(void)
{
	vm_size_t s;
	int i, pv_npg;

	/*
	 * Initialize the pv chunk and pmap list mutexes.
	 */
	mtx_init(&pv_chunks_mutex, "pmap pv chunk list", NULL, MTX_DEF);
	mtx_init(&allpmaps_lock, "allpmaps", NULL, MTX_DEF);

	/*
	 * Initialize the pool of pv list locks.
	 */
	for (i = 0; i < NPV_LIST_LOCKS; i++)
		rw_init(&pv_list_locks[i], "pmap pv list");

	/*
	 * Calculate the size of the pv head table for superpages.
	 */
	pv_npg = howmany(vm_phys_segs[vm_phys_nsegs - 1].end, L2_SIZE); // 2M

	/*
	 * Allocate memory for the pv head table for superpages.
	 */
	s = (vm_size_t)(pv_npg * sizeof(struct md_page));
	s = round_page(s);
	pvh_table = kmem_malloc(s, M_WAITOK | M_ZERO);
	for (i = 0; i < pv_npg; i++)
		TAILQ_INIT(&pvh_table[i].pv_list);
	TAILQ_INIT(&pvh_dummy.pv_list);

	if (superpages_enabled)
		pagesizes[1] = L2_SIZE;
}

#ifdef SMP
/*
 * For SMP, these functions have to use IPIs for coherence.
 *
 * In general, the calling thread uses a plain fence to order the
 * writes to the page tables before invoking an SBI callback to invoke
 * sfence_vma() on remote CPUs.
 */
static void
pmap_invalidate_page(pmap_t pmap, vm_offset_t va)
{
	cpuset_t mask;

	sched_pin();
	mask = pmap->pm_active;
	CPU_CLR(PCPU_GET(pc_hart), &mask);
	fence();
	if (!CPU_EMPTY(&mask) && smp_started)
		sbi_remote_sfence_vma(mask.__bits, va, 1);
	sfence_vma_page(va);
	sched_unpin();
}

static void
pmap_invalidate_range(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	cpuset_t mask;

	sched_pin();
	mask = pmap->pm_active;
	CPU_CLR(PCPU_GET(pc_hart), &mask);
	fence();
	if (!CPU_EMPTY(&mask) && smp_started)
		sbi_remote_sfence_vma(mask.__bits, sva, eva - sva + 1);

	/*
	 * Might consider a loop of sfence_vma_page() for a small
	 * number of pages in the future.
	 */
	sfence_vma();
	sched_unpin();
}

static void
pmap_invalidate_all(pmap_t pmap)
{
	cpuset_t mask;

	sched_pin();
	mask = pmap->pm_active;
	CPU_CLR(PCPU_GET(pc_hart), &mask);

	/*
	 * XXX: The SBI doc doesn't detail how to specify x0 as the
	 * address to perform a global fence.  BBL currently treats
	 * all sfence_vma requests as global however.
	 */
	fence();
	if (!CPU_EMPTY(&mask) && smp_started)
		sbi_remote_sfence_vma(mask.__bits, 0, 0);
	sfence_vma();
	sched_unpin();
}
#else
/*
 * Normal, non-SMP, invalidation functions.
 * We inline these within pmap.c for speed.
 */
static __inline void
pmap_invalidate_page(pmap_t pmap, vm_offset_t va)
{

	sfence_vma_page(va);
}

static __inline void
pmap_invalidate_range(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{

	/*
	 * Might consider a loop of sfence_vma_page() for a small
	 * number of pages in the future.
	 */
	sfence_vma();
}

static __inline void
pmap_invalidate_all(pmap_t pmap)
{

	sfence_vma();
}
#endif

/*
 *	Routine:	pmap_extract
 *	Function:
 *		Extract the physical page address associated
 *		with the given map/virtual_address pair.
 */
vm_paddr_t 
pmap_extract(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t l2e;
	vm_paddr_t pa = 0;

	/*
	 * Start with an L2 lookup, L1 superpages are currently not implemented.
	 */
	PMAP_LOCK(pmap);
	pd_entry_t *l2p = pmap_l2(pmap, va);
	if (l2p != NULL && ((l2e = pmap_load(l2p)) & PTE_V) != 0) {
		if ((l2e & PTE_RWX) == 0) { // point to l3 page table
			pt_entry_t *l3p = pmap_l2_to_l3(l2p, va);
			pa = PTE_TO_PHYS(pmap_load(l3p));
			pa |= (va & L3_OFFSET);
		} else {
			/* L2 is a superpage mapping. */
			pa = L2PTE_TO_PHYS(l2e);
			pa |= (va & L2_OFFSET);
		}
	}
	PMAP_UNLOCK(pmap);
	return (pa);
}

/*
 *	Routine:	pmap_extract_and_hold
 *	Function:
 *		Atomically extract and hold the physical page
 *		with the given pmap and virtual address pair
 *		if that mapping permits the given protection.
 */
vm_page_t
pmap_extract_and_hold(pmap_t pmap, vm_offset_t va, vm_prot_t prot)
{
	pt_entry_t *l3p, l3e;
	vm_paddr_t phys;
	vm_page_t m;

	m = NULL;
	PMAP_LOCK(pmap);
	l3p = pmap_l3(pmap, va);
	if (l3p != NULL && (l3e = pmap_load(l3p)) != 0) {
		if ((l3e & PTE_W) != 0 || (prot & VM_PROT_WRITE) == 0) {
			phys = PTE_TO_PHYS(l3e);
			m = PHYS_TO_VM_PAGE(phys);
			if (!vm_page_wire_mapped(m))
				m = NULL;
		}
	}
	PMAP_UNLOCK(pmap);
	return (m);
}

vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	vm_paddr_t pa;

	if (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS) {
		pa = DMAP_TO_PHYS(va);
	} else {
		pd_entry_t *l2 = pmap_l2(kernel_pmap, va);
		if (l2 == NULL)
			panic("%s: No l2", __func__);
		pd_entry_t l2e = pmap_load(l2);
		/*
		 * Beware of concurrent promotion and demotion! We must
		 * use l2e rather than loading from l2 multiple times to
		 * ensure we see a consistent state, including the
		 * implicit load in pmap_l2_to_l3.  It is, however, safe
		 * to use an old l2e because the L3 page is preserved by
		 * promotion.
		 */
		if ((l2e & PTE_RWX) == 0) { //ori PTE_RX, point to l3 page table
			pt_entry_t *l3 = pmap_l2_to_l3(&l2e, va);
			pa = PTE_TO_PHYS(pmap_load(l3));
			pa |= (va & PAGE_MASK);
		} else {
			/* superpages */
			pa = L2PTE_TO_PHYS(l2e);
			pa |= (va & L2_OFFSET);
		}
	}
	return (pa);
}

/***************************************************
 * Low level mapping routines.....
 ***************************************************/
void
pmap_kenter(vm_offset_t sva, vm_size_t size, vm_paddr_t pa, int mode __unused)
{
	KASSERT((pa & L3_OFFSET) == 0,
	   ("%s: Invalid physical address", __func__));
	KASSERT((sva & L3_OFFSET) == 0,
	   ("%s: Invalid virtual address", __func__));
	KASSERT((size & PAGE_MASK) == 0,
	    ("%s: Mapping is not page-sized", __func__));

	vm_offset_t va = sva;
	while (size != 0) {
		pt_entry_t *l3 = pmap_l3(kernel_pmap, va);
		KASSERT(l3 != NULL, ("Invalid page table, va: 0x%lx", va));

		pn_t pn = (pa / PAGE_SIZE);
		pt_entry_t entry = PTE_KERN; // accessed and dirty are both 1
		entry |= (pn << PTE_PPN0_S);
		pmap_store(l3, entry);

		va += PAGE_SIZE;
		pa += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

void
pmap_kenter_device(vm_offset_t sva, vm_size_t size, vm_paddr_t pa)
{
	pmap_kenter(sva, size, pa, VM_MEMATTR_DEVICE);
}

/*
 * Remove a page from the kernel pagetables.
 * Note: not SMP coherent.
 */
void
pmap_kremove(vm_offset_t va)
{
	pt_entry_t *l3;

	l3 = pmap_l3(kernel_pmap, va);
	KASSERT(l3 != NULL, ("%s: Invalid address", __func__));

	pmap_clear(l3);
	sfence_vma();
}

void
pmap_kremove_device(vm_offset_t sva, vm_size_t size)
{
	KASSERT((sva & L3_OFFSET) == 0,
	   ("pmap_kremove_device: Invalid virtual address"));
	KASSERT((size & PAGE_MASK) == 0,
	    ("pmap_kremove_device: Mapping is not page-sized"));

	vm_offset_t va = sva;
	while (size != 0) {
		pt_entry_t *l3 = pmap_l3(kernel_pmap, va);
		KASSERT(l3 != NULL, ("Invalid page table, va: 0x%lx", va));
		pmap_clear(l3);

		va += PAGE_SIZE;
		size -= PAGE_SIZE;
	}

	pmap_invalidate_range(kernel_pmap, sva, va);
}

/*
 *	Used to map a range of physical addresses into kernel
 *	virtual address space.
 *
 *	The value passed in '*virt' is a suggested virtual address for
 *	the mapping. Architectures which can support a direct-mapped
 *	physical to virtual region can return the appropriate address
 *	within that region, leaving '*virt' unchanged. Other
 *	architectures should map the pages starting at '*virt' and
 *	update '*virt' with the first usable address after the mapped
 *	region.
 */
vm_offset_t
pmap_map(vm_offset_t *virt, vm_paddr_t start, vm_paddr_t end, int prot)
{

	return PHYS_TO_DMAP(start);
}

/*
 * Add a list of wired pages to the kva
 * this routine is only used for temporary
 * kernel mappings that do not need to have
 * page modification or references recorded.
 * Note that old mappings are simply written
 * over.  The page *must* be wired.
 * Note: SMP coherent.  Uses a ranged shootdown IPI.
 */
void
pmap_qenter(vm_offset_t sva, vm_page_t *ma, int count)
{
	vm_offset_t va = sva;
	for (int i = 0; i < count; i++) {
		vm_page_t m = ma[i];
		pt_entry_t pa = VM_PAGE_TO_PHYS(m);
		pn_t pn = (pa / PAGE_SIZE);
		pt_entry_t *l3 = pmap_l3(kernel_pmap, va);
		KASSERT(l3 != NULL, ("%s: Invalid address", __func__)); //wycpull
		pt_entry_t entry = PTE_KERN; // accessed and dirty are both 1
		entry |= (pn << PTE_PPN0_S);
		pmap_store(l3, entry);

		va += L3_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

/*
 * This routine tears out page mappings from the
 * kernel -- it is meant only for temporary mappings.
 * Note: SMP coherent.  Uses a ranged shootdown IPI.
 */
void
pmap_qremove(vm_offset_t sva, int count)
{
	vm_offset_t va;

	KASSERT(sva >= VM_MIN_KERNEL_ADDRESS, ("usermode va %lx", sva));

	for (va = sva; count-- > 0; va += PAGE_SIZE) {
		pt_entry_t *l3 = pmap_l3(kernel_pmap, va);
		KASSERT(l3 != NULL, ("%s: Invalid address", __func__));
		pmap_clear(l3);
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

bool
pmap_ps_enabled(pmap_t pmap __unused)
{

	return (superpages_enabled);
}

/***************************************************
 * Page table page management routines.....
 ***************************************************/
/*
 * Schedule the specified unused page table page to be freed.  Specifically,
 * add the page to the specified list of pages that will be released to the
 * physical memory manager after the TLB has been updated.
 */
static __inline void
pmap_add_delayed_free_list(vm_page_t m, spglist_t *free, boolean_t set_PG_ZERO)
{

	if (set_PG_ZERO)
		m->flags |= PG_ZERO;
	else
		m->flags &= ~PG_ZERO;
	SLIST_INSERT_HEAD(free, m, plinks.s.ss);
}

/*
 * Inserts the specified page table page into the specified pmap's collection
 * of idle page table pages.  Each of a pmap's page table pages is responsible
 * for mapping a distinct range of virtual addresses.  The pmap's collection is
 * ordered by this virtual address range.
 *
 * If @promoted is false, then the page table page @mptp must be zero filled;
 * @mptp's valid field will be set to 0.
 *
 * If @promoted is true and @all_l3e_PTE_A_set is false, then @mptp must
 * contain valid mappings with identical attributes except for PTE_A;
 * @mptp's valid field will be set to 1.
 *
 * If @promoted and @all_l3e_PTE_A_set are both true, then @mptp must contain
 * valid mappings with identical attributes including PTE_A; @mptp's valid
 * field will be set to VM_PAGE_BITS_ALL.
 */
// returns ENOMEM or ESUCCESS
static __inline int
pmap_insert_l3pt_page(pmap_t pmap, vm_page_t mptp, bool promoted, bool all_l3e_PTE_A_set)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(promoted || !all_l3e_PTE_A_set,
	    ("a zero-filled PTP can't have PTE_A set in every PTE"));
if (mptp->pindex >= NL3PTP) panic("%s: wyctest\n", __func__);
	mptp->valid = promoted ? (all_l3e_PTE_A_set ? VM_PAGE_BITS_ALL : 1) : 0;
	return (vm_radix_insert(&pmap->pm_root, mptp)); // returns ENOMEM or ESUCCESS
}

/*
 * Removes the page table page mapping the specified virtual address from the
 * specified pmap's collection of idle page table pages, and returns it.
 * Otherwise, returns NULL if there is no page table page corresponding to the
 * specified virtual address.
 */
static __inline vm_page_t
pmap_remove_l3pt_page(pmap_t pmap, vm_offset_t va)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	return (vm_radix_remove(&pmap->pm_root, pmap_l3_pindex(va)));
}

/*
 * Decrements a page table page's reference count, which is used to record the
 * number of valid page table entries within the page.  If the reference count
 * drops to zero, then the page table page is unmapped.  Returns TRUE if the
 * page table page was unmapped and FALSE otherwise.
 */
static inline bool
pmap_unwire_ptp(pmap_t pmap, vm_offset_t va, vm_page_t mptp /*ori m*/, spglist_t *free)
{
	KASSERT(mptp->ref_count > 0,
	    ("%s: page %p ref count underflow", __func__, mptp));

	--mptp->ref_count;
	if (mptp->ref_count == 0) {
		_pmap_unwire_ptp(pmap, va, mptp, free);
		return (true);
	} else {
		return (false);
	}
}

static void
_pmap_unwire_ptp(pmap_t pmap, vm_offset_t va, vm_page_t mptp /*ori m*/, spglist_t *free)
{
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if (mptp->pindex >= NL3PTP + NL2PTP) { // a L1PTP
		pd_entry_t *l0;
		l0 = pmap_l0(pmap, va);
		pmap_clear(l0);
	} else if (mptp->pindex >= NL3PTP) { // a L2PTP
		pd_entry_t *l1;
		l1 = pmap_l1(pmap, va);
		pmap_clear(l1);
		pmap_distribute_l1(pmap, pmap_l1_index(va), 0);
	} else { // a L3PTP
		pd_entry_t *l2;
		l2 = pmap_l2(pmap, va);
		pmap_clear(l2);
	}
	pmap_resident_count_dec(pmap, 1);

	if (mptp->pindex < NL3PTP) { // a L3PTP
		pd_entry_t *l1 = pmap_l1(pmap, va);
		vm_paddr_t l2pt_phys = PTE_TO_PHYS(pmap_load(l1));
		vm_page_t  l2pt_m = PHYS_TO_VM_PAGE(l2pt_phys);
		pmap_unwire_ptp(pmap, va, l2pt_m, free);
	} else if (mptp->pindex < NL3PTP + NL2PTP && // a L2PTP
		   pmap_mode != PMAP_MODE_SV39) {
		//MPASS(pmap_mode != PMAP_MODE_SV39); //wycpush
		pd_entry_t *l0 = pmap_l0(pmap, va);
		vm_paddr_t l1pt_phys = PTE_TO_PHYS(pmap_load(l0));
		vm_page_t  l1pt_m = PHYS_TO_VM_PAGE(l1pt_phys);
		pmap_unwire_ptp(pmap, va, l1pt_m, free);
	}
	pmap_invalidate_page(pmap, va);

	vm_wire_sub(1);

	/* 
	 * Put page on a list so that it is released after
	 * *ALL* TLB shootdown is done
	 */
	pmap_add_delayed_free_list(mptp, free, TRUE);
}

/*
 * After removing a page table entry, this routine is used to
 * conditionally free the page, and manage the reference count.
 */
static bool
pmap_unuse_pt(pmap_t pmap, vm_offset_t va, pd_entry_t ptepde, spglist_t *free)
{
	vm_page_t mptp;

	if (va >= VM_MAXUSER_ADDRESS)
		return (0);
	KASSERT(ptepde != 0, ("%s: ptepde != 0", __func__));
	mptp = PHYS_TO_VM_PAGE(PTE_TO_PHYS(ptepde));
	return (pmap_unwire_ptp(pmap, va, mptp, free));
}

static uint64_t
pmap_satp_mode(void)
{
	return (pmap_mode == PMAP_MODE_SV39 ? SATP_MODE_SV39 : SATP_MODE_SV48);
}

// init the pmap of proc0 (swapper)
void
pmap_pinit0(pmap_t pmap) // < proc0_init
{
	PMAP_LOCK_INIT(pmap);
	bzero(&pmap->pm_stats, sizeof(pmap->pm_stats));
	pmap->pm_top = kernel_pmap->pm_top;
	pmap->pm_satp = pmap_satp_mode() | (vtophys(pmap->pm_top) >> PAGE_SHIFT);
	CPU_ZERO(&pmap->pm_active);
	TAILQ_INIT(&pmap->pm_pvchunk);
	vm_radix_init(&pmap->pm_root);
	pmap_activate_boot(pmap);
}

int
pmap_pinit(pmap_t pmap)
{
	vm_paddr_t topphys;
	vm_page_t mtop;

	mtop = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO | VM_ALLOC_WAITOK);

	topphys = VM_PAGE_TO_PHYS(mtop);
	pmap->pm_top = (pd_entry_t *)PHYS_TO_DMAP(topphys);
	pmap->pm_satp = pmap_satp_mode() | (topphys >> PAGE_SHIFT);

	bzero(&pmap->pm_stats, sizeof(pmap->pm_stats));

	CPU_ZERO(&pmap->pm_active);

	if (pmap_mode == PMAP_MODE_SV39) {
		/*
		 * Copy L1 entries from the kernel pmap.  This must be done with
		 * the allpmaps lock held to avoid races with
		 * pmap_distribute_l1().
		 */
		mtx_lock(&allpmaps_lock);
		LIST_INSERT_HEAD(&allpmaps, pmap, pm_list);
		for (int i = pmap_l1_index(VM_MIN_KERNEL_ADDRESS);
		    i < pmap_l1_index(VM_MAX_KERNEL_ADDRESS); i++)
			pmap->pm_top[i] = kernel_pmap->pm_top[i];
		for (int i = pmap_l1_index(DMAP_MIN_ADDRESS);
		    i < pmap_l1_index(DMAP_MAX_ADDRESS); i++)
			pmap->pm_top[i] = kernel_pmap->pm_top[i];
		mtx_unlock(&allpmaps_lock);
	} else {
		int i = pmap_l0_index(VM_MIN_KERNEL_ADDRESS);
		pmap->pm_top[i] = kernel_pmap->pm_top[i];
	}

	TAILQ_INIT(&pmap->pm_pvchunk);
	vm_radix_init(&pmap->pm_root);

	return (1);
}

/*
 * This routine is called if the desired page table page does not exist.
 *
 * If page table page allocation fails, this routine may sleep before
 * returning NULL.  It sleeps only if a lock pointer was given.
 *
 * Note: If a page allocation fails at page table level two or three,
 * one or two pages may be held during the wait, only to be released
 * afterwards.  This conservative approach is easily argued to avoid
 * race conditions.
 */
// ptepindex: the pagtable page index. It will be stored in vm_page.pindex
static vm_page_t
_pmap_alloc_l123(pmap_t pmap, vm_pindex_t ptpindex, struct rwlock **lockp)
{
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	/*
	 * Allocate a page table page.
	 */
	vm_page_t mptp = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO);
	if (mptp == NULL) {
		if (lockp != NULL) {
			RELEASE_PV_LIST_LOCK(lockp);
			PMAP_UNLOCK(pmap);
			rw_runlock(&pvh_global_lock);
			vm_wait(NULL);
			rw_rlock(&pvh_global_lock);
			PMAP_LOCK(pmap);
		}

		/*
		 * Indicate the need to retry.  While waiting, the page table
		 * page may have been allocated.
		 */
		return (NULL);
	}
	mptp->pindex = ptpindex;

	/*
	 * Map the pagetable page into the process address space, if
	 * it isn't already there.
	 */
	pn_t pn = VM_PAGE_TO_PHYS(mptp) >> PAGE_SHIFT;
	if (ptpindex >= NL3PTP + NL2PTP) { // L1 pagetable page, only exists in SV48 mode
		KASSERT(pmap_mode != PMAP_MODE_SV39,
		    ("%s: pindex %#lx in SV39 mode", __func__, ptpindex));
		KASSERT(ptpindex < NL3PTP + NL2PTP + NL1PTP,
		    ("%s: pindex %#lx out of range", __func__, ptpindex));

		vm_pindex_t l0index = ptpindex - (NL3PTP + NL2PTP);
		pd_entry_t *l0 = &pmap->pm_top[l0index];
		KASSERT((pmap_load(l0) & PTE_V) == 0,
		    ("%s: L0 entry %#lx is valid", __func__, pmap_load(l0)));

		pt_entry_t entry = PTE_V | (pn << PTE_PPN0_S);
		pmap_store(l0, entry);
	} else if (ptpindex >= NL3PTP) { // L2 pagetable page
		pd_entry_t *l1;

		vm_pindex_t l1index = ptpindex - NL3PTP;
		if (pmap_mode == PMAP_MODE_SV39) {
			l1 = &pmap->pm_top[l1index];
		} else {
			vm_paddr_t phys;
			vm_pindex_t l0index = l1index >> Ln_ENTRIES_SHIFT;
			pd_entry_t *l0 = &pmap->pm_top[l0index];
			if (pmap_load(l0) == 0) {
				/* Recurse to allocate the L1 page. */
				if (_pmap_alloc_l123(pmap,
				    NL3PTP + NL2PTP + l0index, lockp) == NULL)
					goto fail;
				phys = PTE_TO_PHYS(pmap_load(l0));
			} else {
				phys = PTE_TO_PHYS(pmap_load(l0));
				vm_page_t pdpg = PHYS_TO_VM_PAGE(phys);
				pdpg->ref_count++;
			}
			pd_entry_t *l1pt = (pd_entry_t *)PHYS_TO_DMAP(phys);
			l1 = &l1pt[ptpindex & Ln_ADDR_MASK];
		}
		KASSERT((pmap_load(l1) & PTE_V) == 0,
		    ("%s: L1 entry %#lx is valid", __func__, pmap_load(l1)));

		pt_entry_t entry = PTE_V | (pn << PTE_PPN0_S);
		pmap_store(l1, entry);
		pmap_distribute_l1(pmap, l1index, entry);
	} else { // L3 pagetable page
		pd_entry_t *l1;

		vm_pindex_t l1index = ptpindex >> (L1_SHIFT - L2_SHIFT);
		if (pmap_mode == PMAP_MODE_SV39) {
			l1 = &pmap->pm_top[l1index];
			if (pmap_load(l1) == 0) {
				/* recurse for allocating page dir */
				if (_pmap_alloc_l123(pmap, NL3PTP + l1index,
				    lockp) == NULL)
					goto fail;
			} else {
				vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l1));
				vm_page_t pdpg = PHYS_TO_VM_PAGE(phys);
				pdpg->ref_count++;
			}
		} else { // PMAP_MODE_SV48
			vm_pindex_t l0index = l1index >> Ln_ENTRIES_SHIFT;
			pd_entry_t *l0 = &pmap->pm_top[l0index];
			if (pmap_load(l0) == 0) {
				/* Recurse to allocate the L1 entry. */
				if (_pmap_alloc_l123(pmap, NL3PTP + l1index,
				    lockp) == NULL)
					goto fail;
				vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l0));
				pd_entry_t *l1pt = (pd_entry_t *)PHYS_TO_DMAP(phys);
				l1 = &l1pt[l1index & Ln_ADDR_MASK];
			} else {
				vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l0));
				pd_entry_t *l1pt = (pd_entry_t *)PHYS_TO_DMAP(phys);
				l1 = &l1pt[l1index & Ln_ADDR_MASK];
				if (pmap_load(l1) == 0) {
					/* Recurse to allocate the L2 page. */
					if (_pmap_alloc_l123(pmap,
					    NL3PTP + l1index, lockp) == NULL)
						goto fail;
				} else {
					vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l1));
					vm_page_t pdpg = PHYS_TO_VM_PAGE(phys);
					pdpg->ref_count++;
				}
			}
		}

		vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l1));
		pd_entry_t *l2pt = (pd_entry_t *)PHYS_TO_DMAP(phys);
		pd_entry_t *l2 = &l2pt[ptpindex & Ln_ADDR_MASK];
		KASSERT((pmap_load(l2) & PTE_V) == 0,
		    ("%s: L2 entry %#lx is valid", __func__, pmap_load(l2)));

		pt_entry_t entry = PTE_V | (pn << PTE_PPN0_S);
		pmap_store(l2, entry);
	}

	pmap_resident_count_inc(pmap, 1);

	return (mptp);

fail:
	vm_page_unwire_noq(mptp);
	vm_page_free_zero(mptp);
	return (NULL);
}

static vm_page_t
pmap_alloc_l2(pmap_t pmap, vm_offset_t va, struct rwlock **lockp)
{
retry:;
	pd_entry_t *l1 = pmap_l1(pmap, va);
	vm_page_t mptp;
	if (l1 != NULL && (pmap_load(l1) & PTE_V) != 0) {
		KASSERT((pmap_load(l1) & PTE_RWX) == 0, // point to l2 page table
		    ("%s: L1 entry %#lx for VA %#lx is a leaf", __func__,
		    pmap_load(l1), va));
		/* Add a reference to the L2 page. */
		mptp = PHYS_TO_VM_PAGE(PTE_TO_PHYS(pmap_load(l1)));
		mptp->ref_count++;
	} else { //wyc if the l2 pagetable page has been deallocated
		/* Allocate a L2 page. */
		vm_pindex_t l2pindex = pmap_l2_pindex(va);
		mptp = _pmap_alloc_l123(pmap, l2pindex, lockp);
		if (mptp == NULL && lockp != NULL)
			goto retry;
	}
	return (mptp);
}

static vm_page_t
pmap_alloc_l3(pmap_t pmap, vm_offset_t va, struct rwlock **lockp)
{
retry:;
	pd_entry_t *l2 = pmap_l2(pmap, va); // Get the page directory entry
	vm_page_t mptp;
	if (l2 != NULL && pmap_load(l2) != 0) {
		/*
		 * If the page table page is mapped, we just increment the
		 * hold count, and activate it.
		 */
		vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l2));
		mptp = PHYS_TO_VM_PAGE(phys);
		mptp->ref_count++;
	} else { //wyc if the l3 pagetable page has been deallocated
		/*
		 * If the pte page isn't mapped, or if it has been
		 * deallocated.
		 */
		vm_pindex_t l3pindex = pmap_l3_pindex(va); // Calculate pagetable page index
		mptp = _pmap_alloc_l123(pmap, l3pindex, lockp);
		if (mptp == NULL && lockp != NULL)
			goto retry;
	}
	return (mptp);
}

/***************************************************
 * Pmap allocation/deallocation routines.
 ***************************************************/

/*
 * Release any resources held by the given physical map.
 * Called when a pmap initialized by pmap_pinit is being released.
 * Should only be called if the map contains no valid mappings.
 */
void
pmap_release(pmap_t pmap)
{
	vm_page_t m;

	KASSERT(pmap->pm_stats.resident_count == 0,
	    ("pmap_release: pmap resident count %ld != 0",
	    pmap->pm_stats.resident_count));
	KASSERT(CPU_EMPTY(&pmap->pm_active),
	    ("releasing active pmap %p", pmap));

	if (pmap_mode == PMAP_MODE_SV39) {
		mtx_lock(&allpmaps_lock);
		LIST_REMOVE(pmap, pm_list);
		mtx_unlock(&allpmaps_lock);
	}

	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pmap->pm_top));
	vm_page_unwire_noq(m);
	vm_page_free(m);
}

static int
kvm_size(SYSCTL_HANDLER_ARGS)
{
	unsigned long ksize = VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS;

	return sysctl_handle_long(oidp, &ksize, 0, req);
}
SYSCTL_PROC(_vm, OID_AUTO, kvm_size, CTLTYPE_LONG | CTLFLAG_RD | CTLFLAG_MPSAFE,
    0, 0, kvm_size, "LU",
    "Size of KVM");

static int
kvm_free(SYSCTL_HANDLER_ARGS)
{
	unsigned long kfree = VM_MAX_KERNEL_ADDRESS - kernel_vm_end;

	return sysctl_handle_long(oidp, &kfree, 0, req);
}
SYSCTL_PROC(_vm, OID_AUTO, kvm_free, CTLTYPE_LONG | CTLFLAG_RD | CTLFLAG_MPSAFE,
    0, 0, kvm_free, "LU",
    "Amount of KVM free");

/*
 * grow the number of kernel page table entries, if needed
 */
void
pmap_growkernel(vm_offset_t addr)
{
	mtx_assert(&kernel_map->system_mtx, MA_OWNED);

	addr = roundup2(addr, L2_SIZE); // 2M
	if (addr - 1 >= vm_map_max(kernel_map))
		addr = vm_map_max(kernel_map);
	while (kernel_vm_end < addr) {
		pd_entry_t *l1 = pmap_l1(kernel_pmap, kernel_vm_end);
		if (pmap_load(l1) == 0) {
			/* We need a new PDP entry */
			vm_page_t nkpg = vm_page_alloc_noobj(VM_ALLOC_INTERRUPT |
			    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
			if (nkpg == NULL)
				panic("%s: no memory to grow kernel", __func__);
			nkpg->pindex = kernel_vm_end >> L1_SHIFT; //wyc???
			vm_paddr_t paddr = VM_PAGE_TO_PHYS(nkpg);

			pn_t pn = (paddr / PAGE_SIZE);
			pt_entry_t entry = (PTE_V);
			entry |= (pn << PTE_PPN0_S);
			pmap_store(l1, entry);
			pmap_distribute_l1(kernel_pmap, pmap_l1_index(kernel_vm_end), entry);
			continue; /* try again */
		}
		pd_entry_t *l2 = pmap_l1_to_l2(l1, kernel_vm_end);
		if ((pmap_load(l2) & PTE_V) != 0 &&
		    (pmap_load(l2) & PTE_RWX) == 0) { // point to l3 page table
			kernel_vm_end = (kernel_vm_end + L2_SIZE) & ~L2_OFFSET;
			if (kernel_vm_end - 1 >= vm_map_max(kernel_map)) {
				kernel_vm_end = vm_map_max(kernel_map);
				break;
			}
			continue;
		}

		vm_page_t nkpg = vm_page_alloc_noobj(VM_ALLOC_INTERRUPT | VM_ALLOC_WIRED |
		    VM_ALLOC_ZERO);
		if (nkpg == NULL)
			panic("%s: no memory to grow kernel", __func__);
		nkpg->pindex = kernel_vm_end >> L2_SHIFT; //wyc???
		vm_paddr_t paddr = VM_PAGE_TO_PHYS(nkpg);

		pn_t pn = (paddr / PAGE_SIZE);
		pt_entry_t entry = (PTE_V);
		entry |= (pn << PTE_PPN0_S);
		pmap_store(l2, entry);

		pmap_invalidate_page(kernel_pmap, kernel_vm_end);

		kernel_vm_end = (kernel_vm_end + L2_SIZE) & ~L2_OFFSET;
		if (kernel_vm_end - 1 >= vm_map_max(kernel_map)) {
			kernel_vm_end = vm_map_max(kernel_map);
			break;                       
		}
	}
}

/***************************************************
 * page management routines.
 ***************************************************/

static const uint64_t pc_freemask[_NPCM] = {
	[0 ... _NPCM - 2] = PC_FREEN,
	[_NPCM - 1] = PC_FREEL
};

#if 0
#ifdef PV_STATS
static int pc_chunk_count, pc_chunk_allocs, pc_chunk_frees, pc_chunk_tryfail;

SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_count, CTLFLAG_RD, &pc_chunk_count, 0,
	"Current number of pv entry chunks");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_allocs, CTLFLAG_RD, &pc_chunk_allocs, 0,
	"Current number of pv entry chunks allocated");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_frees, CTLFLAG_RD, &pc_chunk_frees, 0,
	"Current number of pv entry chunks frees");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_tryfail, CTLFLAG_RD, &pc_chunk_tryfail, 0,
	"Number of times tried to get a chunk page but failed.");

static long pv_entry_frees, pv_entry_allocs, pv_entry_count;
static int pv_entry_spare;

SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_frees, CTLFLAG_RD, &pv_entry_frees, 0,
	"Current number of pv entry frees");
SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_allocs, CTLFLAG_RD, &pv_entry_allocs, 0,
	"Current number of pv entry allocs");
SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_count, CTLFLAG_RD, &pv_entry_count, 0,
	"Current number of pv entries");
SYSCTL_INT(_vm_pmap, OID_AUTO, pv_entry_spare, CTLFLAG_RD, &pv_entry_spare, 0,
	"Current number of spare pv entries");
#endif
#endif /* 0 */

/*
 * We are in a serious low memory condition.  Resort to
 * drastic measures to free some pages so we can allocate
 * another pv entry chunk.
 *
 * Returns NULL if PV entries were reclaimed from the specified pmap.
 *
 * We do not, however, unmap 2mpages because subsequent accesses will
 * allocate per-page pv entries until repromotion occurs, thereby
 * exacerbating the shortage of free pv entries.
 */
static vm_page_t
reclaim_pv_chunk(pmap_t locked_pmap, struct rwlock **lockp)
{

	panic("RISCVTODO: reclaim_pv_chunk");
}

/*
 * free the pv_entry back to the free list
 */
static void
free_pv_entry(pmap_t pmap, pv_entry_t pv)
{
	struct pv_chunk *pc;
	int idx, field, bit;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PV_STAT(atomic_add_long(&pv_entry_frees, 1));
	PV_STAT(atomic_add_int(&pv_entry_spare, 1));
	PV_STAT(atomic_subtract_long(&pv_entry_count, 1));
	pc = pv_to_chunk(pv);
	idx = pv - &pc->pc_pventry[0];
	field = idx / 64;
	bit = idx % 64;
	pc->pc_map[field] |= 1ul << bit; // 1 means free
	if (pc_is_free(pc)) {
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_pmlist);
		free_pv_chunk(pc);
	} else
		/* 98% of the time, pc is already at the head of the list. */
		if (__predict_false(pc != TAILQ_FIRST(&pmap->pm_pvchunk))) {
			TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_pmlist);
			TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_pmlist);
		}
}

static void
free_pv_chunk(struct pv_chunk *pc)
{
	vm_page_t m;

	mtx_lock(&pv_chunks_mutex);
	TAILQ_REMOVE(&pv_chunks, pc, pc_pvclist);
	mtx_unlock(&pv_chunks_mutex);
	PV_STAT(atomic_subtract_int(&pv_entry_spare, _NPCPV));
	PV_STAT(atomic_subtract_int(&pc_chunk_count, 1));
	PV_STAT(atomic_add_int(&pc_chunk_frees, 1));
	/* entire chunk is free, return it */
	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pc));
	dump_drop_page(m->phys_addr);
	vm_page_unwire_noq(m);
	vm_page_free(m);
}

/*
 * Returns a new PV entry, allocating a new PV chunk from the system when
 * needed.  If this PV chunk allocation fails and a PV list lock pointer was
 * given, a PV chunk is reclaimed from an arbitrary pmap.  Otherwise, NULL is
 * returned.
 *
 * The given PV list lock may be released.
 */
static pv_entry_t
get_pv_entry(pmap_t pmap, struct rwlock **lockp)
{
	int bit, field;
	pv_entry_t pv;
	struct pv_chunk *pc;
	vm_page_t m;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PV_STAT(atomic_add_long(&pv_entry_allocs, 1));
retry:
	pc = TAILQ_FIRST(&pmap->pm_pvchunk);
	if (pc != NULL) {
		for (field = 0; field < _NPCM; field++) {
			if (pc->pc_map[field]) {
				bit = ffsl(pc->pc_map[field]) - 1;
				break;
			}
		}
		if (field < _NPCM) {
			pv = &pc->pc_pventry[field * 64 + bit];
			pc->pc_map[field] &= ~(1ul << bit);
			/* If this was the last item, move it to tail */
			if (pc_is_full(pc)) {
				TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_pmlist);
				TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_pmlist);
			}
			PV_STAT(atomic_add_long(&pv_entry_count, 1));
			PV_STAT(atomic_subtract_int(&pv_entry_spare, 1));
			return (pv);
		}
	}
	/* No free items, allocate another chunk */
	m = vm_page_alloc_noobj(VM_ALLOC_WIRED);
	if (m == NULL) {
		if (lockp == NULL) {
			PV_STAT(pc_chunk_tryfail++);
			return (NULL);
		}
		m = reclaim_pv_chunk(pmap, lockp);
		if (m == NULL)
			goto retry;
	}
	PV_STAT(atomic_add_int(&pc_chunk_count, 1));
	PV_STAT(atomic_add_int(&pc_chunk_allocs, 1));
	dump_add_page(m->phys_addr);
	pc = (void *)PHYS_TO_DMAP(m->phys_addr);
	pc->pc_pmap = pmap;
	pc->pc_map[0] = PC_FREEN & ~1ul;	/* preallocated bit 0 */
	pc->pc_map[1] = PC_FREEN;
	pc->pc_map[2] = PC_FREEL;
	mtx_lock(&pv_chunks_mutex);
	TAILQ_INSERT_TAIL(&pv_chunks, pc, pc_pvclist);
	mtx_unlock(&pv_chunks_mutex);
	pv = &pc->pc_pventry[0];
	TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_pmlist);
	PV_STAT(atomic_add_long(&pv_entry_count, 1));
	PV_STAT(atomic_add_int(&pv_entry_spare, _NPCPV - 1));
	return (pv);
}

/*
 * Ensure that the number of spare PV entries in the specified pmap meets or
 * exceeds the given count, "needed".
 *
 * The given PV list lock may be released.
 */
static void
reserve_pv_entries(pmap_t pmap, int needed, struct rwlock **lockp)
{
	pvc_tailq_t new_tail;
	struct pv_chunk *pc;
	vm_page_t m;
	int avail, free;
	bool reclaimed;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(lockp != NULL, ("reserve_pv_entries: lockp is NULL"));

	/*
	 * Newly allocated PV chunks must be stored in a private list until
	 * the required number of PV chunks have been allocated.  Otherwise,
	 * reclaim_pv_chunk() could recycle one of these chunks.  In
	 * contrast, these chunks must be added to the pmap upon allocation.
	 */
	TAILQ_INIT(&new_tail);
retry:
	avail = 0;
	TAILQ_FOREACH(pc, &pmap->pm_pvchunk, pc_pmlist) {
		bit_count((bitstr_t *)pc->pc_map, 0,
		    sizeof(pc->pc_map) * NBBY, &free);
		if (free == 0)
			break;
		avail += free;
		if (avail >= needed)
			break;
	}
	for (reclaimed = false; avail < needed; avail += _NPCPV) {
		m = vm_page_alloc_noobj(VM_ALLOC_WIRED);
		if (m == NULL) {
			m = reclaim_pv_chunk(pmap, lockp);
			if (m == NULL)
				goto retry;
			reclaimed = true;
		}
		/* XXX PV STATS */
#if 0
		dump_add_page(m->phys_addr);
#endif
		pc = (void *)PHYS_TO_DMAP(m->phys_addr);
		pc->pc_pmap = pmap;
		pc->pc_map[0] = PC_FREEN;
		pc->pc_map[1] = PC_FREEN;
		pc->pc_map[2] = PC_FREEL;
		TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_pmlist);
		TAILQ_INSERT_TAIL(&new_tail, pc, pc_pvclist);

		/*
		 * The reclaim might have freed a chunk from the current pmap.
		 * If that chunk contained available entries, we need to
		 * re-count the number of available entries.
		 */
		if (reclaimed)
			goto retry;
	}
	if (!TAILQ_EMPTY(&new_tail)) {
		mtx_lock(&pv_chunks_mutex);
		TAILQ_CONCAT(&pv_chunks, &new_tail, pc_pvclist);
		mtx_unlock(&pv_chunks_mutex);
	}
}

/*
 * First find and then remove the pv entry for the specified pmap and virtual
 * address from the specified pv list.  Returns the pv entry if found and NULL
 * otherwise.  This operation can be performed on pv lists for either 4KB or
 * 2MB page mappings.
 */
static __inline pv_entry_t
pmap_pv_pvh_remove(struct md_page *pvh, pmap_t pmap, vm_offset_t va)
{
	pv_entry_t pv;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
		if (pmap == PV_PMAP(pv) && va == pv->pv_va) {
			TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
			pvh->pv_gen++;
			break;
		}
	}
	return (pv);
}

/*
 * First find and then destroy the pv entry for the specified pmap and virtual
 * address.  This operation can be performed on pv lists for either 4KB or 2MB
 * page mappings.
 */
static void
pmap_pv_pvh_free(struct md_page *pvh, pmap_t pmap, vm_offset_t va)
{
	pv_entry_t pv;

	pv = pmap_pv_pvh_remove(pvh, pmap, va);

	KASSERT(pv != NULL, ("%s: pv not found for %#lx", __func__, va));
	free_pv_entry(pmap, pv);
}

/*
 * Conditionally create the PV entry for a 4KB page mapping if the required
 * memory can be allocated without resorting to reclamation.
 */
static bool
pmap_try_insert_pv_entry(pmap_t pmap, vm_offset_t va, vm_page_t m,
    struct rwlock **lockp)
{
	pv_entry_t pv;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	/* Pass NULL instead of the lock pointer to disable reclamation. */
	if ((pv = get_pv_entry(pmap, NULL)) != NULL) {
		pv->pv_va = va;
		CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
		TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		return (true);
	} else
		return (false);
}

/*
 * After demotion from a 2MB page mapping to 512 4KB page mappings,
 * destroy the pv entry for the 2MB page mapping and reinstantiate the pv
 * entries for each of the 4KB page mappings.
 */
static void __unused
pmap_pv_demote_l2(pmap_t pmap, vm_offset_t va, vm_paddr_t pa,
    struct rwlock **lockp)
{
	struct md_page *pvh;
	struct pv_chunk *pc;
	pv_entry_t pv;
	vm_page_t m;
	vm_offset_t va_last;
	int bit, field;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);

	/*
	 * Transfer the 2mpage's pv entry for this mapping to the first
	 * page's pv list.  Once this transfer begins, the pv list lock
	 * must not be released until the last pv entry is reinstantiated.
	 */
	pvh = pa_to_pvh(pa);
	va &= ~L2_OFFSET;
	pv = pmap_pv_pvh_remove(pvh, pmap, va);
	KASSERT(pv != NULL, ("%s: pv not found", __func__));
	m = PHYS_TO_VM_PAGE(pa);
	TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
	m->md.pv_gen++;
	/* Instantiate the remaining 511 pv entries. */
	va_last = va + L2_SIZE - PAGE_SIZE;
	for (;;) {
		pc = TAILQ_FIRST(&pmap->pm_pvchunk);
		KASSERT(!pc_is_full(pc), ("%s: missing spare", __func__));
		for (field = 0; field < _NPCM; field++) {
			while (pc->pc_map[field] != 0) {
				bit = ffsl(pc->pc_map[field]) - 1;
				pc->pc_map[field] &= ~(1ul << bit);
				pv = &pc->pc_pventry[field * 64 + bit];
				va += PAGE_SIZE;
				pv->pv_va = va;
				m++;
				KASSERT((m->oflags & VPO_UNMANAGED) == 0,
			    ("%s: page %p is not managed", __func__, m));
				TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
				m->md.pv_gen++;
				if (va == va_last)
					goto out;
			}
		}
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_pmlist);
		TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_pmlist);
	}
out:
	if (pc_is_full(pc)) {
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_pmlist);
		TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_pmlist);
	}
	/* XXX PV stats */
}

#if VM_NRESERVLEVEL > 0
static void
pmap_pv_promote_l2(pmap_t pmap, vm_offset_t va, vm_paddr_t pa,
    struct rwlock **lockp)
{
	struct md_page *pvh;
	pv_entry_t pv;
	vm_page_t m;
	vm_offset_t va_last;

	rw_assert(&pvh_global_lock, RA_LOCKED);
	KASSERT((pa & L2_OFFSET) == 0,
	    ("%s: misaligned pa %#lx", __func__, pa));

	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);

	m = PHYS_TO_VM_PAGE(pa);
	va = va & ~L2_OFFSET;
	pv = pmap_pv_pvh_remove(&m->md, pmap, va);
	KASSERT(pv != NULL, ("%s: pv for %#lx not found", __func__, va));
	pvh = pa_to_pvh(pa);
	TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
	pvh->pv_gen++;

	va_last = va + L2_SIZE - PAGE_SIZE;
	do {
		m++;
		va += PAGE_SIZE;
		pmap_pv_pvh_free(&m->md, pmap, va);
	} while (va < va_last);
}
#endif /* VM_NRESERVLEVEL > 0 */

/*
 * Create the PV entry for a 2MB page mapping.  Always returns true unless the
 * flag PMAP_ENTER_NORECLAIM is specified.  If that flag is specified, returns
 * false if the PV entry cannot be allocated without resorting to reclamation.
 */
static bool
pmap_pv_insert_l2(pmap_t pmap, vm_offset_t va, pd_entry_t l2e, u_int flags,
    struct rwlock **lockp)
{
	struct md_page *pvh;
	pv_entry_t pv;
	vm_paddr_t pa;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	/* Pass NULL instead of the lock pointer to disable reclamation. */
	pv = get_pv_entry(pmap, (flags & PMAP_ENTER_NORECLAIM) != 0 ? NULL : lockp);
	if (pv == NULL)
		return (false);
	pv->pv_va = va;
	pa = PTE_TO_PHYS(l2e);
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);
	pvh = pa_to_pvh(pa);
	TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
	pvh->pv_gen++;
	return (true);
}

static void
pmap_remove_kernel_l2(pt_entry_t *l2, vm_offset_t va)
{
	KASSERT(!VIRT_IN_DMAP(va), ("removing direct mapping of %#lx", va));
	//KASSERT(pmap == kernel_pmap, ("pmap %p is not kernel_pmap", pmap));
	PMAP_LOCK_ASSERT(kernel_pmap, MA_OWNED);

	vm_page_t ml3 = pmap_remove_l3pt_page(kernel_pmap, va);
	if (ml3 == NULL)
		panic("%s: Missing pt page", __func__);

	vm_paddr_t ml3pa = VM_PAGE_TO_PHYS(ml3);
	pt_entry_t newl2e = ml3pa | PTE_V;

	/*
	 * If this page table page was unmapped by a promotion, then it
	 * contains valid mappings.  Zero it to invalidate those mappings.
	 */
	if (vm_page_any_valid(ml3))
		pagezero((void *)PHYS_TO_DMAP(ml3pa));

	/*
	 * Demote the mapping.
	 */
	pt_entry_t oldl2e __diagused = pmap_load_store(l2, newl2e);
	KASSERT(oldl2e == 0, ("%s: found existing mapping at %p: %#lx",
	    __func__, l2, oldl2e));
}

/*
 * pmap_remove_l2: Do the things to unmap a level 2 superpage.
 */
static bool
pmap_remove_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t sva,
    pd_entry_t l1e, spglist_t *free, struct rwlock **lockp)
{
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT((sva & L2_OFFSET) == 0, ("%s: sva is not aligned", __func__));
	pt_entry_t oldl2e = pmap_load_clear(l2);
	KASSERT((oldl2e & PTE_RWX) != 0, // assert that it is a superpage
	    ("%s: L2e %lx is not a superpage mapping", __func__, oldl2e));

	/*
	 * The sfence.vma documentation states that it is sufficient to specify
	 * a single address within a superpage mapping.  However, since we do
	 * not perform any invalidation upon promotion, TLBs may still be
	 * caching 4KB mappings within the superpage, so we must invalidate the
	 * entire range.
	 */
	pmap_invalidate_range(pmap, sva, sva + L2_SIZE);
	if ((oldl2e & PTE_SW_WIRED) != 0)
		pmap->pm_stats.wired_count -= L2_SIZE / PAGE_SIZE;
	pmap_resident_count_dec(pmap, L2_SIZE / PAGE_SIZE);
	if (oldl2e & PTE_SW_MANAGED) {
		CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, PTE_TO_PHYS(oldl2e));
		struct md_page *pvh = pa_to_pvh(PTE_TO_PHYS(oldl2e));
		pmap_pv_pvh_free(pvh, pmap, sva);
		vm_offset_t eva = sva + L2_SIZE;
		vm_page_t m = PHYS_TO_VM_PAGE(PTE_TO_PHYS(oldl2e));
		for (vm_offset_t va = sva; va < eva; va += PAGE_SIZE, m++) {
			if ((oldl2e & PTE_D) != 0)
				vm_page_dirty(m);
			if ((oldl2e & PTE_A) != 0)
				vm_page_aflag_set(m, PGA_REFERENCED);
			if (TAILQ_EMPTY(&m->md.pv_list) &&
			    TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
		}
	}
	if (pmap == kernel_pmap) {
		pmap_remove_kernel_l2(l2, sva);
	} else {
		vm_page_t ml3 = pmap_remove_l3pt_page(pmap, sva);
		if (ml3 != NULL) {
			KASSERT(vm_page_any_valid(ml3),
			    ("%s: l3 page not promoted", __func__));
			pmap_resident_count_dec(pmap, 1);
			KASSERT(ml3->ref_count == Ln_ENTRIES,
			    ("%s: l3 page ref count error", __func__));
			ml3->ref_count = 1;
			vm_page_unwire_noq(ml3);
			pmap_add_delayed_free_list(ml3, free, FALSE);
		}
	}
	return (pmap_unuse_pt(pmap, sva, l1e, free));
}

/*
 * pmap_remove_l3: do the things to unmap a page in a process
 */
static bool
pmap_remove_l3(pmap_t pmap, pt_entry_t *l3, vm_offset_t va, 
    pd_entry_t l2e, spglist_t *free, struct rwlock **lockp)
{
	pt_entry_t old_l3e;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	old_l3e = pmap_load_clear(l3);
	pmap_invalidate_page(pmap, va);
	if (old_l3e & PTE_SW_WIRED)
		pmap->pm_stats.wired_count -= 1;
	pmap_resident_count_dec(pmap, 1);
	if (old_l3e & PTE_SW_MANAGED) {
		vm_paddr_t phys = PTE_TO_PHYS(old_l3e);
		vm_page_t m = PHYS_TO_VM_PAGE(phys);
		if (old_l3e & PTE_D)
			vm_page_dirty(m);
		if (old_l3e & PTE_A)
			vm_page_aflag_set(m, PGA_REFERENCED);
		CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
		pmap_pv_pvh_free(&m->md, pmap, va);
		if (TAILQ_EMPTY(&m->md.pv_list) &&
		    (m->flags & PG_FICTITIOUS) == 0) {
			struct md_page *pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
			if (TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
		}
	}

	return (pmap_unuse_pt(pmap, va, l2e, free));
}

/*
 *	Remove the given range of addresses from the specified map.
 *
 *	It is assumed that the start and end are properly
 *	rounded to the page size.
 */
void
pmap_remove(pmap_t pmap, vm_offset_t sva, vm_offset_t eva) // pmap_remove_pages
{
	vm_offset_t va_next;
	pd_entry_t *l1;
	/*
	 * Perform an unsynchronized read.  This is, however, safe.
	 */
	if (pmap->pm_stats.resident_count == 0)
		return;

	spglist_t free = SLIST_HEAD_INITIALIZER(free);
	struct rwlock *lock = NULL;
	rw_rlock(&pvh_global_lock);
	PMAP_LOCK(pmap);

	for (; sva < eva; sva = va_next) {
		if (pmap->pm_stats.resident_count == 0)
			break;

		if (pmap_mode == PMAP_MODE_SV48) {
			pd_entry_t *l0 = pmap_l0(pmap, sva);
			if (pmap_load(l0) == 0) {
				va_next = (sva + L0_SIZE) & ~L0_OFFSET;
				if (va_next < sva)
					va_next = eva;
				continue;
			}
			l1 = pmap_l0_to_l1(l0, sva);
		} else {
			l1 = pmap_l1(pmap, sva);
		}

		if (pmap_load(l1) == 0) {
			va_next = (sva + L1_SIZE) & ~L1_OFFSET;
			if (va_next < sva)
				va_next = eva;
				//break; //wycpull can break immediately out of the for loop here
			continue;
		}

		/*
		 * Calculate index for next page table.
		 */
		va_next = (sva + L2_SIZE) & ~L2_OFFSET;
		if (va_next < sva)
			va_next = eva;

		pd_entry_t *l2 = pmap_l1_to_l2(l1, sva);
		pd_entry_t l2e = pmap_load(l2);
		if (l2e == 0)
			continue;
		if ((l2e & PTE_RWX) != 0) { // superpage
			if (sva + L2_SIZE == va_next && eva >= va_next) {
				(void)pmap_remove_l2(pmap, l2, sva,
				    pmap_load(l1), &free, &lock);
				continue;
			} else if (!pmap_demote_l2_locked(pmap, l2, sva, &lock)) {
				/*
				 * The large page mapping was destroyed.
				 */
				continue;
			}
			l2e = pmap_load(l2);
		}

		/*
		 * Limit our scan to either the end of the va represented
		 * by the current page table page, or to the end of the
		 * range being removed.
		 */
		if (va_next > eva)
			va_next = eva;

		vm_offset_t va = va_next;
		for (pt_entry_t *l3 = pmap_l2_to_l3(l2, sva);
		    sva != va_next; l3++, sva += L3_SIZE) {
			if (pmap_load(l3) == 0) {
				if (va != va_next) {
					pmap_invalidate_range(pmap, va, sva);
					va = va_next;
				}
				continue;
			}
			if (va == va_next)
				va = sva;
			if (pmap_remove_l3(pmap, l3, sva, l2e, &free, &lock)) {
				sva += L3_SIZE;
				break;
			}
		}
		if (va != va_next)
			pmap_invalidate_range(pmap, va, sva);
	}
	if (lock != NULL)
		rw_wunlock(lock);
	rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
	vm_page_free_pages_toq(&free, false);
}

/*
 *	Routine:	pmap_remove_all
 *	Function:
 *		Removes this physical page from
 *		all physical maps in which it resides.
 *		Reflects back modify bits to the pager.
 *
 *	Notes:
 *		Original versions of this routine were very
 *		inefficient because they iteratively called
 *		pmap_remove (slow...)
 */
void
pmap_remove_all(vm_page_t m)
{
	pd_entry_t *l2;
	pv_entry_t pv;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("%s: page %p is not managed", __func__, m));
	spglist_t free = SLIST_HEAD_INITIALIZER(free);
	struct md_page *pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pvh_dummy :
	    pa_to_pvh(VM_PAGE_TO_PHYS(m));

	rw_wlock(&pvh_global_lock);
	while ((pv = TAILQ_FIRST(&pvh->pv_list)) != NULL) {
		pmap_t pmap = PV_PMAP(pv);
		PMAP_LOCK(pmap);
		vm_offset_t va = pv->pv_va;
		l2 = pmap_l2(pmap, va);
		(void)pmap_demote_l2(pmap, l2, va);
		PMAP_UNLOCK(pmap);
	}
	while ((pv = TAILQ_FIRST(&m->md.pv_list)) != NULL) {
		pmap_t pmap = PV_PMAP(pv);
		PMAP_LOCK(pmap);
		pmap_resident_count_dec(pmap, 1);
		l2 = pmap_l2(pmap, pv->pv_va);
		KASSERT(l2 != NULL, ("%s: no l2 table found", __func__));
		pd_entry_t l2e __diagused = pmap_load(l2);

		KASSERT((l2e & PTE_RWX) == 0, //ori PTE_RX
		    ("%s: found a superpage in %p's pv list", __func__, m));

		pt_entry_t *l3 = pmap_l2_to_l3(l2, pv->pv_va);
		pt_entry_t l3e = pmap_load_clear(l3);
		pmap_invalidate_page(pmap, pv->pv_va);
		if (l3e & PTE_SW_WIRED)
			pmap->pm_stats.wired_count--;
		if ((l3e & PTE_A) != 0)
			vm_page_aflag_set(m, PGA_REFERENCED);

		/*
		 * Update the vm_page_t clean and reference bits.
		 */
		if ((l3e & PTE_D) != 0)
			vm_page_dirty(m);
		pmap_unuse_pt(pmap, pv->pv_va, pmap_load(l2), &free);
		TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		free_pv_entry(pmap, pv);
		PMAP_UNLOCK(pmap);
	}
	vm_page_aflag_clear(m, PGA_WRITEABLE);
	rw_wunlock(&pvh_global_lock);
	vm_page_free_pages_toq(&free, false);
}

/*
 *	Set the physical protection on the
 *	specified range of this map as requested.
 */
void
pmap_protect(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, vm_prot_t prot)
{
	pd_entry_t *l0, *l1, *l2, l2e;
	pt_entry_t *l3, l3e;
	vm_page_t m;
	vm_paddr_t pa;
	vm_offset_t va_next;

	if ((prot & VM_PROT_READ) == VM_PROT_NONE) {
		pmap_remove(pmap, sva, eva);
		return;
	}

	if ((prot & (VM_PROT_WRITE | VM_PROT_EXECUTE)) ==
	    (VM_PROT_WRITE | VM_PROT_EXECUTE))
		return;

	bool anychanged = false;
	bool pv_lists_locked = false;
	pt_entry_t mask = 0;
	if ((prot & VM_PROT_WRITE) == 0)
		mask |= PTE_W | PTE_D;
	if ((prot & VM_PROT_EXECUTE) == 0)
		mask |= PTE_X;
resume:
	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {
		if (pmap_mode == PMAP_MODE_SV48) {
			l0 = pmap_l0(pmap, sva);
			if (pmap_load(l0) == 0) {
				va_next = (sva + L0_SIZE) & ~L0_OFFSET;
				if (va_next < sva)
					va_next = eva;
				continue;
			}
			l1 = pmap_l0_to_l1(l0, sva);
		} else {
			l1 = pmap_l1(pmap, sva);
		}

		if (pmap_load(l1) == 0) {
			va_next = (sva + L1_SIZE) & ~L1_OFFSET;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		va_next = (sva + L2_SIZE) & ~L2_OFFSET;
		if (va_next < sva)
			va_next = eva;

		l2 = pmap_l1_to_l2(l1, sva);
		if ((l2e = pmap_load(l2)) == 0)
			continue;
		if ((l2e & PTE_RWX) != 0) { // superpage
			if (sva + L2_SIZE == va_next && eva >= va_next) {
retryl2:
				if ((prot & VM_PROT_WRITE) == 0 &&
				    (l2e & (PTE_SW_MANAGED | PTE_D)) == (PTE_SW_MANAGED | PTE_D)) {
					pa = PTE_TO_PHYS(l2e);
					m = PHYS_TO_VM_PAGE(pa);
					for (vm_page_t mt = m; mt < &m[Ln_ENTRIES]; mt++)
						vm_page_dirty(mt);
				}
				if (!atomic_fcmpset_long(l2, &l2e, l2e & ~mask))
					goto retryl2;
				anychanged = true;
				continue;
			} else {
				if (!pv_lists_locked) {
					pv_lists_locked = true;
					if (!rw_try_rlock(&pvh_global_lock)) {
						if (anychanged)
							pmap_invalidate_all(pmap);
						PMAP_UNLOCK(pmap);
						rw_rlock(&pvh_global_lock);
						goto resume;
					}
				}
				if (!pmap_demote_l2(pmap, l2, sva)) {
					/*
					 * The large page mapping was destroyed.
					 */
					continue;
				}
			}
		}

		if (va_next > eva)
			va_next = eva;

		for (l3 = pmap_l2_to_l3(l2, sva); sva != va_next; l3++, sva += L3_SIZE) {
			l3e = pmap_load(l3);
retryl3:
			if ((l3e & PTE_V) == 0)
				continue;
			if ((prot & VM_PROT_WRITE) == 0 &&
			    (l3e & (PTE_SW_MANAGED | PTE_D)) == (PTE_SW_MANAGED | PTE_D)) {
				m = PHYS_TO_VM_PAGE(PTE_TO_PHYS(l3e));
				vm_page_dirty(m);
			}
			if (!atomic_fcmpset_long(l3, &l3e, l3e & ~mask))
				goto retryl3;
			anychanged = true;
		}
	}
	if (anychanged)
		pmap_invalidate_all(pmap);
	if (pv_lists_locked)
		rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
}

bool
pmap_fault(pmap_t pmap, vm_offset_t va, vm_prot_t ftype)
{
	pd_entry_t *l2, l2e;
	pt_entry_t bits, *pte, olde;
	bool rv;

	KASSERT(VIRT_IS_VALID(va), ("%s: invalid va %#lx", __func__, va));

	rv = false;
	PMAP_LOCK(pmap);
	l2 = pmap_l2(pmap, va);
	if (l2 == NULL || ((l2e = pmap_load(l2)) & PTE_V) == 0)
		goto done;
	if ((l2e & PTE_RWX) == 0) { // point to l3 page table
		pte = pmap_l2_to_l3(l2, va);
		if (((olde = pmap_load(pte)) & PTE_V) == 0)
			goto done;
	} else {
		pte = l2;
		olde = l2e;
	}

	if ((pmap != kernel_pmap && (olde & PTE_U) == 0) ||
	    (ftype == VM_PROT_WRITE && (olde & PTE_W) == 0) ||
	    (ftype == VM_PROT_EXECUTE && (olde & PTE_X) == 0) ||
	    (ftype == VM_PROT_READ && (olde & PTE_R) == 0))
		goto done;

	bits = PTE_A;
	if (ftype == VM_PROT_WRITE)
		bits |= PTE_D;

	/*
	 * Spurious faults can occur if the implementation caches invalid
	 * entries in the TLB, or if simultaneous accesses on multiple CPUs
	 * race with each other.
	 */
	if ((olde & bits) != bits)
		pmap_store_bits(pte, bits);
	sfence_vma();
	rv = true;
done:
	PMAP_UNLOCK(pmap);
	return (rv);
}

static bool
pmap_demote_l2(pmap_t pmap, pd_entry_t *l2, vm_offset_t va)
{
	struct rwlock *lock;
	bool rv;

	lock = NULL;
	rv = pmap_demote_l2_locked(pmap, l2, va, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	return (rv);
}

/*
 * Tries to demote a 2MB page mapping.  If demotion fails, the 2MB page
 * mapping is invalidated.
 */
static bool
pmap_demote_l2_locked(pmap_t pmap, pd_entry_t *l2, vm_offset_t va,
    struct rwlock **lockp)
{
	vm_page_t mptp;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	pd_entry_t oldl2e = pmap_load(l2);
	KASSERT((oldl2e & PTE_RWX) != 0, // assert superpage
	    ("%s: oldl2e is not a leaf entry", __func__));
	if ((oldl2e & PTE_A) == 0 || (mptp = pmap_remove_l3pt_page(pmap, va)) == NULL) {
		KASSERT((oldl2e & PTE_SW_WIRED) == 0,
		    ("%s: page table page for a wired mapping is missing", __func__));
		if ((oldl2e & PTE_A) == 0 || (mptp = vm_page_alloc_noobj(
		    (VIRT_IN_DMAP(va) ? VM_ALLOC_INTERRUPT : 0) |
		    VM_ALLOC_WIRED)) == NULL) {
			spglist_t free = SLIST_HEAD_INITIALIZER(free);
			pd_entry_t l1e = pmap_load(pmap_l1(pmap, va));
			(void)pmap_remove_l2(pmap, l2, va & ~L2_OFFSET,
			    l1e, &free, lockp);
			vm_page_free_pages_toq(&free, true);
			CTR3(KTR_PMAP, "%s: "
			    "failure for va %#lx in pmap %p", __func__, va, pmap);
			return (false);
		}
		mptp->pindex = pmap_l3_pindex(va);
		if (va < VM_MAXUSER_ADDRESS) {
			mptp->ref_count = Ln_ENTRIES;
			pmap_resident_count_inc(pmap, 1);
		}
	}
	vm_paddr_t mptppa = VM_PAGE_TO_PHYS(mptp);
	pt_entry_t *firstl3 = (pt_entry_t *)PHYS_TO_DMAP(mptppa);
	pd_entry_t newl2e = ((mptppa / PAGE_SIZE) << PTE_PPN0_S) | PTE_V;
	KASSERT((oldl2e & PTE_A) != 0, ("%s: oldl2e is missing PTE_A", __func__));
	KASSERT((oldl2e & (PTE_D | PTE_W)) != PTE_W, ("%s: oldl2e is missing PTE_D", __func__));
	pt_entry_t newl3e = oldl2e;

	/*
	 * If the page table page is not leftover from an earlier promotion,
	 * initialize it.
	 */
	if (!vm_page_all_valid(mptp)) {
		for (int i = 0; i < Ln_ENTRIES; i++)
			pmap_store(firstl3 + i, newl3e + (i << PTE_PPN0_S));
	}
	KASSERT(PTE_TO_PHYS(pmap_load(firstl3)) == PTE_TO_PHYS(newl3e),
	    ("%s: firstl3 and newl3e map different physical addresses", __func__));

	/*
	 * If the mapping has changed attributes, update the PTEs.
	 */
	if ((pmap_load(firstl3) & PTE_PROMOTE) != (newl3e & PTE_PROMOTE))
		for (int i = 0; i < Ln_ENTRIES; i++)
			pmap_store(firstl3 + i, newl3e + (i << PTE_PPN0_S));

	/*
	 * The spare PV entries must be reserved prior to demoting the
	 * mapping, that is, prior to changing the L2 entry.  Otherwise, the
	 * state of the L2 entry and the PV lists will be inconsistent, which
	 * can result in reclaim_pv_chunk() attempting to remove a PV entry from
	 * the wrong PV list and pmap_pv_demote_l2() failing to find the
	 * expected PV entry for the 2MB page mapping that is being demoted.
	 */
	if (oldl2e & PTE_SW_MANAGED)
		reserve_pv_entries(pmap, Ln_ENTRIES - 1, lockp);

	/*
	 * Demote the mapping.
	 */
	pmap_store(l2, newl2e);

	/*
	 * Demote the PV entry.
	 */
	if (oldl2e & PTE_SW_MANAGED)
		pmap_pv_demote_l2(pmap, va, PTE_TO_PHYS(oldl2e), lockp);

	atomic_add_long(&pmap_l2_demotions, 1);
	CTR3(KTR_PMAP, "%s: success for va %#lx in pmap %p", __func__, va, pmap);
	return (true);
}

#if VM_NRESERVLEVEL > 0
static bool
pmap_promote_l2(pmap_t pmap, pd_entry_t *l2, vm_offset_t va, vm_page_t ml3, struct rwlock **lockp)
{
	pt_entry_t all_l3e_PTE_A, *firstl3, firstl3e, *l3, l3e;
	vm_paddr_t pa;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	if (!pmap_ps_enabled(pmap))
		return (false);

	KASSERT((pmap_load(l2) & PTE_RWX) == 0, // assert pointing to page table
	    ("%s: invalid l2 entry %p", __func__, l2));

	/*
	 * Examine the first L3E in the specified PTP.  Abort if this L3E is
	 * ineligible for promotion or does not map the first 4KB physical page
	 * within a 2MB page.
	 */
	firstl3 = (pt_entry_t *)PHYS_TO_DMAP(PTE_TO_PHYS(pmap_load(l2)));
	firstl3e = pmap_load(firstl3);
	pa = PTE_TO_PHYS(firstl3e);
	if ((pa & L2_OFFSET) != 0) {
		CTR3(KTR_PMAP, "%s: failure for va %#lx pmap %p", __func__, va, pmap);
		atomic_add_long(&pmap_l2_p_failures, 1);
		return (false);
	}

	/*
	 * Downgrade a clean, writable mapping to read-only to ensure that the
	 * hardware does not set PTE_D while we are comparing PTEs.
	 *
	 * Upon a write access to a clean mapping, the implementation will
	 * either atomically check protections and set PTE_D, or raise a page
	 * fault.  In the latter case, the pmap lock provides atomicity.  Thus,
	 * we do not issue an sfence.vma here and instead rely on pmap_fault()
	 * to do so lazily.
	 */
	while ((firstl3e & (PTE_W | PTE_D)) == PTE_W) {
		if (atomic_fcmpset_64(firstl3, &firstl3e, firstl3e & ~PTE_W)) {
			firstl3e &= ~PTE_W;
			break;
		}
	}

	/*
	 * Examine each of the other PTEs in the specified PTP.  Abort if this
	 * PTE maps an unexpected 4KB physical page or does not have identical
	 * characteristics to the first PTE.
	 */
	all_l3e_PTE_A = firstl3e & PTE_A;
	pa += L2_SIZE - PAGE_SIZE;
	for (l3 = firstl3 + Ln_ENTRIES - 1; l3 > firstl3; l3--) {
		l3e = pmap_load(l3);
		if (PTE_TO_PHYS(l3e) != pa) {
			CTR3(KTR_PMAP,
			    "%s: failure for va %#lx pmap %p", __func__, va, pmap);
			atomic_add_long(&pmap_l2_p_failures, 1);
			return (false);
		}
		while ((l3e & (PTE_W | PTE_D)) == PTE_W) {
			if (atomic_fcmpset_64(l3, &l3e, l3e & ~PTE_W)) {
				l3e &= ~PTE_W;
				break;
			}
		}
		if ((l3e & PTE_PROMOTE) != (firstl3e & PTE_PROMOTE)) {
			CTR3(KTR_PMAP,
			    "%s: failure for va %#lx pmap %p", __func__, va, pmap);
			atomic_add_long(&pmap_l2_p_failures, 1);
			return (false);
		}
		all_l3e_PTE_A &= l3e;
		pa -= PAGE_SIZE;
	}

	/*
	 * Unless all PTEs have PTE_A set, clear it from the superpage
	 * mapping, so that promotions triggered by speculative mappings,
	 * such as pmap_enter_quick(), don't automatically mark the
	 * underlying pages as referenced.
	 */
	firstl3e &= ~PTE_A | all_l3e_PTE_A;

	/*
	 * Save the page table page in its current state until the L2
	 * mapping the superpage is demoted by pmap_demote_l2() or
	 * destroyed by pmap_remove_l3().
	 */
	if (ml3 == NULL)
		ml3 = PHYS_TO_VM_PAGE(PTE_TO_PHYS(pmap_load(l2)));
	KASSERT(ml3->pindex == pmap_l3_pindex(va),
	    ("%s: page table page's pindex is wrong", __func__));
	if (pmap_insert_l3pt_page(pmap, ml3, true, all_l3e_PTE_A != 0)) {
		CTR3(KTR_PMAP, "%s: failure for va %#lx pmap %p",
		    __func__, va, pmap);
		atomic_add_long(&pmap_l2_p_failures, 1);
		return (false);
	}

	if ((firstl3e & PTE_SW_MANAGED) != 0)
		pmap_pv_promote_l2(pmap, va, PTE_TO_PHYS(firstl3e), lockp);

	pmap_store(l2, firstl3e);

	atomic_add_long(&pmap_l2_promotions, 1);
	CTR3(KTR_PMAP, "%s: success for va %#lx in pmap %p", __func__, va, pmap);
	return (true);
}
#endif

/*
 *	Insert the given physical page @m at
 *	the specified virtual address @va in the
 *	target physical map @pmap with the protection requested.
 *
 *	If PMAP_ENTER_WIRED specified, the page will be wired down, meaning
 *	that the related pte can not be reclaimed.
 *
 *	NB:  This is the only routine which MAY NOT lazy-evaluate
 *	or lose information.  That is, this routine must actually
 *	insert this page into the given map NOW.
 */
int
pmap_enter(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
    u_int flags, int8_t psind)
{
//if ((va & PAGE_MASK) != 0) panic("%s: wyctest\n", __func__); // tested: always page aligned
	va = trunc_page(va);
	if ((m->oflags & VPO_UNMANAGED) == 0)
		VM_PAGE_OBJECT_BUSY_ASSERT(m);
	vm_paddr_t pa = VM_PAGE_TO_PHYS(m);
	pn_t pn = (pa / PAGE_SIZE);

	pt_entry_t new_l3e = PTE_V | PTE_R | PTE_A;
	if (prot & VM_PROT_WRITE)
		new_l3e |= PTE_W;
	if (prot & VM_PROT_EXECUTE)
		new_l3e |= PTE_X;
	if (flags & VM_PROT_WRITE) // A write access to the given virtual address triggered the call
		new_l3e |= PTE_D;
	if ((flags & PMAP_ENTER_WIRED) != 0) // The mapping should be marked as wired
		new_l3e |= PTE_SW_WIRED;
	if (va < VM_MAX_USER_ADDRESS)
		new_l3e |= PTE_U;
	new_l3e |= (pn << PTE_PPN0_S);

	/*
	 * Set modified bit gratuitously for writeable mappings if
	 * the page is unmanaged. We do not want to take a fault
	 * to do the dirty bit accounting for these mappings.
	 */
	if ((m->oflags & VPO_UNMANAGED) != 0) {
		if (prot & VM_PROT_WRITE)
			new_l3e |= PTE_D;
	} else
		new_l3e |= PTE_SW_MANAGED;

	CTR3(KTR_PMAP, "%s: %.16lx -> %.16lx", __func__, va, pa);

	int rv;
	struct rwlock *lock = NULL;
	rw_rlock(&pvh_global_lock);
	PMAP_LOCK(pmap);
	if (psind == 1) {
		/* Assert the required virtual and physical alignment. */
		KASSERT((va & L2_OFFSET) == 0,
		    ("%s: va %#lx unaligned", __func__, va));
		KASSERT(m->psind > 0, ("%s: m->psind < psind", __func__));
		rv = pmap_enter_l2(pmap, va, new_l3e, flags, m, &lock);
		goto out;
	}

	pd_entry_t *l2 = pmap_l2(pmap, va);
	pd_entry_t l2e;
	pt_entry_t *l3;
	vm_page_t mptp = NULL; // is only for user pmap
	if (l2 != NULL && ((l2e = pmap_load(l2)) & PTE_V) != 0 &&
	    ((l2e & PTE_RWX) == 0 || // is superpage
	     pmap_demote_l2_locked(pmap, l2, va, &lock))) {
//if (pmap == kernel_pmap) panic("%s: wyctest\n", __func__); // failed. it could be kernel_map
		l3 = pmap_l2_to_l3(l2, va);
		if (va < VM_MAXUSER_ADDRESS) {
			mptp = PHYS_TO_VM_PAGE(PTE_TO_PHYS(pmap_load(l2)));
			mptp->ref_count++;
		}
	} else if (va < VM_MAXUSER_ADDRESS) {
		bool nosleep = (flags & PMAP_ENTER_NOSLEEP) != 0;
		mptp = pmap_alloc_l3(pmap, va, nosleep ? NULL : &lock);
		if (mptp == NULL && nosleep) {
			CTR1(KTR_PMAP, "%s: mptp == NULL", __func__);
			if (lock != NULL)
				rw_wunlock(lock);
			rw_runlock(&pvh_global_lock);
			PMAP_UNLOCK(pmap);
			return (KERN_RESOURCE_SHORTAGE);
		}
		l3 = pmap_l3(pmap, va);
	} else {
		l3 = pmap_l3(pmap, va);
		/* TODO: This is not optimal, but should mostly work */
		if (l3 == NULL) {
			if (l2 == NULL) {
				vm_page_t l2_m = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO);
				if (l2_m == NULL)
					panic("%s: l2 pte_m == NULL", __func__);

				vm_paddr_t l2_pa = VM_PAGE_TO_PHYS(l2_m);
				pn_t l2_pn = (l2_pa / PAGE_SIZE);

				pd_entry_t *l1 = pmap_l1(pmap, va);
				pt_entry_t entry = (PTE_V);
				entry |= (l2_pn << PTE_PPN0_S);
				pmap_store(l1, entry);
				pmap_distribute_l1(pmap, pmap_l1_index(va), entry);
				l2 = pmap_l1_to_l2(l1, va);
			}

			vm_page_t l3_m = vm_page_alloc_noobj(VM_ALLOC_WIRED | VM_ALLOC_ZERO);
			if (l3_m == NULL)
				panic("%s: l3 pte_m == NULL", __func__);

			vm_paddr_t l3_pa = VM_PAGE_TO_PHYS(l3_m);
			pn_t l3_pn = (l3_pa / PAGE_SIZE);
			pt_entry_t entry = (PTE_V);
			entry |= (l3_pn << PTE_PPN0_S);
			pmap_store(l2, entry);
			l3 = pmap_l2_to_l3(l2, va);
		}
		pmap_invalidate_page(pmap, va);
	}

	pt_entry_t orig_l3e = pmap_load(l3);
	vm_paddr_t orig_pa = PTE_TO_PHYS(orig_l3e);
	pv_entry_t pv = NULL;

	/*
	 * Is the specified virtual address already mapped?
	 */
	if ((orig_l3e & PTE_V) != 0) {
		/*
		 * Wiring change, just update stats. We don't worry about
		 * wiring PT pages as they remain resident as long as there
		 * are valid mappings in them. Hence, if a user page is wired,
		 * the PT page will be also.
		 */
		if ((flags & PMAP_ENTER_WIRED) != 0 &&
		    (orig_l3e & PTE_SW_WIRED) == 0)
			pmap->pm_stats.wired_count++;
		else if ((flags & PMAP_ENTER_WIRED) == 0 &&
		    (orig_l3e & PTE_SW_WIRED) != 0)
			pmap->pm_stats.wired_count--;

		/*
		 * Remove the extra PT page reference.
		 */
		if (mptp != NULL) {
			mptp->ref_count--;
			KASSERT(mptp->ref_count > 0,
			    ("%s: missing reference to page table page,"
			     " va: 0x%lx", __func__, va));
		}

		/*
		 * Has the physical page changed?
		 */
		if (orig_pa == pa) {
			/*
			 * No, might be a protection or wiring change.
			 */
			if ((orig_l3e & PTE_SW_MANAGED) && (new_l3e & PTE_W))
				vm_page_aflag_set(m, PGA_WRITEABLE);
			goto validate;
		}

		/*
		 * The physical page has changed.  Temporarily invalidate
		 * the mapping.  This ensures that all threads sharing the
		 * pmap keep a consistent view of the mapping, which is
		 * necessary for the correct handling of COW faults.  It
		 * also permits reuse of the old mapping's PV entry,
		 * avoiding an allocation.
		 *
		 * For consistency, handle unmanaged mappings the same way.
		 */
		orig_l3e = pmap_load_clear(l3);
		KASSERT(PTE_TO_PHYS(orig_l3e) == orig_pa,
		    ("%s: unexpected pa update for %#lx", __func__, va));
		if ((orig_l3e & PTE_SW_MANAGED)) {
			vm_page_t om = PHYS_TO_VM_PAGE(orig_pa);

			/*
			 * The pmap lock is sufficient to synchronize with
			 * concurrent calls to pmap_page_test_mappings() and
			 * pmap_ts_referenced().
			 */
			if ((orig_l3e & PTE_D) != 0)
				vm_page_dirty(om);
			if ((orig_l3e & PTE_A) != 0)
				vm_page_aflag_set(om, PGA_REFERENCED);
			CHANGE_PV_LIST_LOCK_TO_PHYS(&lock, orig_pa);
			pv = pmap_pv_pvh_remove(&om->md, pmap, va);
			KASSERT(pv != NULL, ("%s: no PV entry for %#lx", __func__, va));
			if (!(new_l3e & PTE_SW_MANAGED))
				free_pv_entry(pmap, pv);
			if ((om->a.flags & PGA_WRITEABLE) != 0 &&
			    TAILQ_EMPTY(&om->md.pv_list) &&
			    ((om->flags & PG_FICTITIOUS) != 0 ||
			    TAILQ_EMPTY(&pa_to_pvh(orig_pa)->pv_list)))
				vm_page_aflag_clear(om, PGA_WRITEABLE);
		}
		pmap_invalidate_page(pmap, va);
		orig_l3e = 0;
	} else {
		/*
		 * Increment the counters.
		 */
		if ((new_l3e & PTE_SW_WIRED) != 0)
			pmap->pm_stats.wired_count++;
		pmap_resident_count_inc(pmap, 1);
	}
	/*
	 * Enter on the PV list if part of our managed memory.
	 */
	if (new_l3e & PTE_SW_MANAGED) {
		if (pv == NULL) {
			pv = get_pv_entry(pmap, &lock);
			pv->pv_va = va;
		}
		CHANGE_PV_LIST_LOCK_TO_PHYS(&lock, pa);
		TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		if ((new_l3e & PTE_W) != 0)
			vm_page_aflag_set(m, PGA_WRITEABLE);
	}

validate:
	/*
	 * Sync the i-cache on all harts before updating the PTE
	 * if the new PTE is executable.
	 */
	if (prot & VM_PROT_EXECUTE)
		pmap_sync_icache(pmap, va, PAGE_SIZE);

	/*
	 * Update the L3 entry.
	 */
	if (orig_l3e != 0) {
		orig_l3e = pmap_load_store(l3, new_l3e);
		pmap_invalidate_page(pmap, va);
		KASSERT(PTE_TO_PHYS(orig_l3e) == pa, ("%s: invalid update", __func__));
		if ((orig_l3e & (PTE_D | PTE_SW_MANAGED)) == (PTE_D | PTE_SW_MANAGED))
			vm_page_dirty(m);
	} else {
		pmap_store(l3, new_l3e);
	}

#if VM_NRESERVLEVEL > 0
	if (mptp != NULL && mptp->ref_count == Ln_ENTRIES &&
	    (m->flags & PG_FICTITIOUS) == 0 &&
	    vm_reserv_level_iffullpop(m) == 0)
		(void)pmap_promote_l2(pmap, l2, va, mptp, &lock);
#endif

	rv = KERN_SUCCESS;
out:
	if (lock != NULL)
		rw_wunlock(lock);
	rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
	return (rv);
}

/*
 * Tries to create a read- and/or execute-only 2MB page mapping.  Returns
 * KERN_SUCCESS if the mapping was created.  Otherwise, returns an error
 * value.  See pmap_enter_l2() for the possible error values when "no sleep",
 * "no replace", and "no reclaim" are specified.
 */
static int
pmap_enter_2mpage(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
    struct rwlock **lockp)
{
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	pn_t pn = VM_PAGE_TO_PHYS(m) / PAGE_SIZE;
	pd_entry_t new_l2e = (pd_entry_t)((pn << PTE_PPN0_S) | PTE_R | PTE_V);
	if ((m->oflags & VPO_UNMANAGED) == 0)
		new_l2e |= PTE_SW_MANAGED;
	if ((prot & VM_PROT_EXECUTE) != 0)
		new_l2e |= PTE_X;
	if (va < VM_MAXUSER_ADDRESS)
		new_l2e |= PTE_U;
	return (pmap_enter_l2(pmap, va, new_l2e, PMAP_ENTER_NOSLEEP |
	    PMAP_ENTER_NOREPLACE | PMAP_ENTER_NORECLAIM, NULL, lockp));
}

/*
 * Returns true if every page table entry in the specified page table is
 * zero.
 */
static bool
pmap_every_pte_zero(vm_paddr_t pa)
{
	KASSERT((pa & PAGE_MASK) == 0, ("pa is misaligned"));
	pt_entry_t *pt_start = (pt_entry_t *)PHYS_TO_DMAP(pa);
	pt_entry_t *pt_end = pt_start + Ln_ENTRIES;
	for (pt_entry_t *pte = pt_start; pte < pt_end; pte++) {
		if (*pte != 0)
			return (false);
	}
	return (true);
}

/*
  Tries to create the specified 2MB page mapping.

  Returns
    KERN_SUCCESS if the mapping was created
    KERN_FAILURE if PMAP_ENTER_NOREPLACE was specified and a 4KB page mapping
      already exists within the 2MB virtual address range starting at the
      specified virtual address.
    KERN_NO_SPACE if PMAP_ENTER_NOREPLACE was specified and a 2MB page mapping
      already exists at the specified virtual address.
    KERN_RESOURCE_SHORTAGE if either
      (1) PMAP_ENTER_NOSLEEP was specified and a page table page allocation failed or
      (2) PMAP_ENTER_NORECLAIM was specified and a PV entry allocation failed.

  The parameter "m" is only used when creating a managed, writeable mapping.
 */
static int
pmap_enter_l2(pmap_t pmap, vm_offset_t va, pd_entry_t new_l2e, u_int flags,
    vm_page_t m, struct rwlock **lockp)
{
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	vm_page_t mptp = pmap_alloc_l2(pmap, va, flags & PMAP_ENTER_NOSLEEP ? NULL : lockp);
	if (mptp == NULL) {
		CTR3(KTR_PMAP, "%s: failed to allocate PT page"
		    " for va %#lx in pmap %p", __func__, va, pmap);
		return (KERN_RESOURCE_SHORTAGE);
	}

	pd_entry_t *l2pt = (pd_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mptp));
	pd_entry_t *l2 = &l2pt[pmap_l2_index(va)];
	pd_entry_t oldl2e = pmap_load(l2);
	if (oldl2e != 0) {
		KASSERT(mptp->ref_count > 1,
		    ("%s: mptp's ref count is too low", __func__));
		if ((flags & PMAP_ENTER_NOREPLACE) != 0) {
			if ((oldl2e & PTE_RWX) != 0) { // it's a superpage
				mptp->ref_count--;
				CTR3(KTR_PMAP,
				    "%s: no space for va %#lx"
				    " in pmap %p", __func__, va, pmap);
				return (KERN_NO_SPACE);
			} else if (va < VM_MAXUSER_ADDRESS ||
			    !pmap_every_pte_zero(L2PTE_TO_PHYS(oldl2e))) {
				mptp->ref_count--;
				CTR3(KTR_PMAP, "%s:"
				    " failed to replace existing mapping"
				    " for va %#lx in pmap %p", __func__, va, pmap);
				return (KERN_FAILURE);
			}
		}
		spglist_t free = SLIST_HEAD_INITIALIZER(free);
		if ((oldl2e & PTE_RWX) != 0) // it's a superpage
			(void)pmap_remove_l2(pmap, l2, va,
			    pmap_load(pmap_l1(pmap, va)), &free, lockp);
		else
			for (vm_offset_t sva = va; sva < va + L2_SIZE; sva += PAGE_SIZE) {
				pd_entry_t *l3 = pmap_l2_to_l3(l2, sva);
				if ((pmap_load(l3) & PTE_V) != 0 &&
				    pmap_remove_l3(pmap, l3, sva, oldl2e, &free, lockp))
					break;
			}
		vm_page_free_pages_toq(&free, true);
		if (va >= VM_MAXUSER_ADDRESS) {
			/*
			 * Both pmap_remove_l2() and pmap_remove_l3() will
			 * leave the kernel page table page zero filled.
			 */
			vm_page_t ml3 = PHYS_TO_VM_PAGE(PTE_TO_PHYS(pmap_load(l2)));
			if (pmap_insert_l3pt_page(pmap, ml3, false, false) != ESUCCESS)
				panic("%s: trie insert failed", __func__);
		} else
			KASSERT(pmap_load(l2) == 0,
			    ("%s: non-zero L2 entry %p", __func__, l2));
	}

	/*
	 * Allocate leaf ptpage for wired userspace pages.
	 */
	vm_page_t uwml3 = NULL; // userspace wired l3 pagetable page
	if ((new_l2e & PTE_SW_WIRED) != 0 && pmap != kernel_pmap) {
		uwml3 = vm_page_alloc_noobj(VM_ALLOC_WIRED);
		if (uwml3 == NULL) {
			return (KERN_RESOURCE_SHORTAGE);
		}
		uwml3->pindex = pmap_l3_pindex(va);
		if (pmap_insert_l3pt_page(pmap, uwml3, true, false) != ESUCCESS) {
			vm_page_unwire_noq(uwml3);
			vm_page_free(uwml3);
			return (KERN_RESOURCE_SHORTAGE);
		}
		pmap_resident_count_inc(pmap, 1);
		uwml3->ref_count = Ln_ENTRIES;
	}
	if ((new_l2e & PTE_SW_MANAGED) != 0) {
		/*
		 * Abort this mapping if its PV entry could not be created.
		 */
		if (!pmap_pv_insert_l2(pmap, va, new_l2e, flags, lockp)) {
			spglist_t free = SLIST_HEAD_INITIALIZER(free);
			if (pmap_unwire_ptp(pmap, va, mptp, &free)) {
				/*
				 * Although "va" is not mapped, paging-structure
				 * caches could nonetheless have entries that
				 * refer to the freed page table pages.
				 * Invalidate those entries.
				 */
				pmap_invalidate_page(pmap, va);
				vm_page_free_pages_toq(&free, true);
			}
			if (uwml3 != NULL) {
				vm_page_t mt __unused = pmap_remove_l3pt_page(pmap, va);
				KASSERT(mt == uwml3,
				    ("removed pt page %p, expected %p", mt, uwml3));
				pmap_resident_count_dec(pmap, 1);
				uwml3->ref_count = 1;
				vm_page_unwire_noq(uwml3);
				vm_page_free(uwml3);
			}
			CTR3(KTR_PMAP,
			    "%s: failed to create PV entry"
			    " for va %#lx in pmap %p", __func__, va, pmap);
			return (KERN_RESOURCE_SHORTAGE);
		}
		if ((new_l2e & PTE_W) != 0)
			for (vm_page_t mt = m; mt < &m[L2_SIZE / PAGE_SIZE]; mt++)
				vm_page_aflag_set(mt, PGA_WRITEABLE);
	}

	/*
	 * Increment counters.
	 */
	if ((new_l2e & PTE_SW_WIRED) != 0)
		pmap->pm_stats.wired_count += L2_SIZE / PAGE_SIZE;
	pmap->pm_stats.resident_count += L2_SIZE / PAGE_SIZE;

	/*
	 * Map the superpage.
	 */
	pmap_store(l2, new_l2e);

	atomic_add_long(&pmap_l2_mappings, 1);
	CTR3(KTR_PMAP, "%s: success for va %#lx in pmap %p", __func__, va, pmap);

	return (KERN_SUCCESS);
}

/*
 * Maps a sequence of resident pages belonging to the same object.
 * The sequence begins with the given page @m_start.  This page is
 * mapped at the given virtual address @start.  Each subsequent page is
 * mapped at a virtual address that is offset from @start by the same
 * amount as the page is offset from @m_start within the object.  The
 * last page in the sequence is the page with the largest offset from
 * @m_start that can be mapped at a virtual address less than the given
 * virtual address @end.  Not every virtual page between @start and @end
 * is mapped; only those for which a resident page exists with the
 * corresponding offset from @m_start are mapped.
 */
void
pmap_enter_object(pmap_t pmap, vm_offset_t start, vm_offset_t end,
    vm_page_t m_start, vm_prot_t prot)
{
	vm_pindex_t diff;
	int rv;

	VM_OBJECT_ASSERT_LOCKED(m_start->object);

	vm_pindex_t psize = atop(end - start);
	vm_pindex_t start_pindex = m_start->pindex;
	vm_page_t m = m_start;
	vm_page_t mptp = NULL;
	struct rwlock *lock = NULL;
	rw_rlock(&pvh_global_lock);
	PMAP_LOCK(pmap);
	while (m != NULL && (diff = m->pindex - start_pindex) < psize) {
		vm_offset_t va = start + ptoa(diff);
		if ((va & L2_OFFSET) == 0 && va + L2_SIZE <= end &&
		    m->psind == 1 && pmap_ps_enabled(pmap) &&
		    ((rv = pmap_enter_2mpage(pmap, va, m, prot, &lock)) ==
		    KERN_SUCCESS || rv == KERN_NO_SPACE))
			m = &m[L2_SIZE / PAGE_SIZE - 1]; // 511
		else
			mptp = pmap_enter_quick_locked(pmap, va, m, prot, mptp,
			    &lock);
		m = TAILQ_NEXT(m, listq); // next page in same object
	}
	if (lock != NULL)
		rw_wunlock(lock);
	rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
}

/*
 * this code makes some *MAJOR* assumptions:
 * 1. Current pmap & pmap exists.
 * 2. Not wired.
 * 3. Read access.
 * 4. No page table pages.
 * but is *MUCH* faster than pmap_enter...
 */
void
pmap_enter_quick(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot)
{
	struct rwlock *lock;

	lock = NULL;
	rw_rlock(&pvh_global_lock);
	PMAP_LOCK(pmap);
	(void)pmap_enter_quick_locked(pmap, va, m, prot, NULL, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
}

static vm_page_t
pmap_enter_quick_locked(pmap_t pmap, vm_offset_t va, vm_page_t m,
    vm_prot_t prot, vm_page_t mptp, struct rwlock **lockp)
{
	KASSERT(!VA_IS_CLEANMAP(va) ||
	    (m->oflags & VPO_UNMANAGED) != 0,
	    ("%s: managed mapping within the clean submap", __func__));
	rw_assert(&pvh_global_lock, RA_LOCKED);
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	CTR3(KTR_PMAP, "%s: %p %lx", __func__, pmap, va);
	/*
	 * In the case that a page table page is not
	 * resident, we are creating it here.
	 */
	pd_entry_t *l2 = NULL;
	pt_entry_t *l3;
	if (va < VM_MAXUSER_ADDRESS) {
		/*
		 * Calculate pagetable page index
		 */
		vm_pindex_t l3pindex = pmap_l3_pindex(va);
		if (mptp && (mptp->pindex == l3pindex)) {
			mptp->ref_count++;
		} else {
			/*
			 * Get the l2 entry
			 */
			l2 = pmap_l2(pmap, va);

			/*
			 * If the page table page is mapped, we just increment
			 * the hold count, and activate it.  Otherwise, we
			 * attempt to allocate a page table page.  If this
			 * attempt fails, we don't retry.  Instead, we give up.
			 */
			if (l2 != NULL && pmap_load(l2) != 0) {
				if ((pmap_load(l2) & PTE_RWX) != 0) // superpage
					return (NULL);
				vm_paddr_t phys = PTE_TO_PHYS(pmap_load(l2));
				mptp = PHYS_TO_VM_PAGE(phys);
				mptp->ref_count++;
			} else {
				/*
				 * Pass NULL instead of the PV list lock
				 * pointer, because we don't intend to sleep.
				 */
				mptp = _pmap_alloc_l123(pmap, l3pindex, NULL);
				if (mptp == NULL)
					return (NULL);
			}
		}
		pt_entry_t *l3pt = (pt_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mptp));
		l3 = &l3pt[pmap_l3_index(va)];
	} else {
		mptp = NULL;
		l3 = pmap_l3(kernel_pmap, va);
		if (l3 == NULL)
			panic("%s: No l3", __func__);
	}
	if (pmap_load(l3) != 0) {
		if (mptp != NULL)
			mptp->ref_count--;
		return (NULL);
	}

	/*
	 * Enter on the PV list if part of our managed memory.
	 */
	if ((m->oflags & VPO_UNMANAGED) == 0 &&
	    !pmap_try_insert_pv_entry(pmap, va, m, lockp)) {
		if (mptp != NULL) {
			spglist_t free = SLIST_HEAD_INITIALIZER(free);
			if (pmap_unwire_ptp(pmap, va, mptp, &free))
				vm_page_free_pages_toq(&free, false);
		}
		return (NULL);
	}

	/*
	 * Increment counters
	 */
	pmap_resident_count_inc(pmap, 1);

	pt_entry_t newl3e = ((VM_PAGE_TO_PHYS(m) / PAGE_SIZE) << PTE_PPN0_S) |
	    PTE_V | PTE_R;
	if ((prot & VM_PROT_EXECUTE) != 0)
		newl3e |= PTE_X;
	if ((m->oflags & VPO_UNMANAGED) == 0)
		newl3e |= PTE_SW_MANAGED;
	if (va < VM_MAX_USER_ADDRESS)
		newl3e |= PTE_U;

	/*
	 * Sync the i-cache on all harts before updating the PTE
	 * if the new PTE is executable.
	 */
	if (prot & VM_PROT_EXECUTE)
		pmap_sync_icache(pmap, va, PAGE_SIZE);

	pmap_store(l3, newl3e);

#if VM_NRESERVLEVEL > 0
	/*
	 * If both the PTP and the reservation are fully populated, then attempt
	 * promotion.
	 */
	if ((mptp == NULL || mptp->ref_count == Ln_ENTRIES) &&
	    (m->flags & PG_FICTITIOUS) == 0 &&
	    vm_reserv_level_iffullpop(m) == 0) {
		if (l2 == NULL)
			l2 = pmap_l2(pmap, va);

		/*
		 * If promotion succeeds, then the next call to this function
		 * should not be given the unmapped PTP as a hint.
		 */
		if (pmap_promote_l2(pmap, l2, va, mptp, lockp))
			mptp = NULL;
	}
#endif

	return (mptp);
}

/*
 * This code maps large physical mmap regions into the
 * processor address space.  Note that some shortcuts
 * are taken, but the code works.
 */
void
pmap_object_init_pt(pmap_t pmap, vm_offset_t addr, vm_object_t object,
    vm_pindex_t pindex, vm_size_t size)
{

	VM_OBJECT_ASSERT_WLOCKED(object);
	KASSERT(object->type == OBJT_DEVICE || object->type == OBJT_SG,
	    ("pmap_object_init_pt: non-device object"));
}

/*
 *	Clear the wired attribute from the mappings for the specified range of
 *	addresses in the given pmap.  Every valid mapping within that range
 *	must have the wired attribute set.  In contrast, invalid mappings
 *	cannot have the wired attribute set, so they are ignored.
 *
 *	The wired attribute of the page table entry is not a hardware feature,
 *	so there is no need to invalidate any TLB entries.
 */
void
pmap_unwire(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	vm_offset_t va_next;
	pd_entry_t *l1, *l2, l2e;
	bool pv_lists_locked;

	pv_lists_locked = false;
retry:
	PMAP_LOCK(pmap);
	for (vm_offset_t va = sva; va < eva; va = va_next) {
		if (pmap_mode == PMAP_MODE_SV48) {
			pd_entry_t *l0 = pmap_l0(pmap, va);
			if (pmap_load(l0) == 0) {
				va_next = (va + L0_SIZE) & ~L0_OFFSET;
				if (va_next < va)
					va_next = eva;
				continue;
			}
			l1 = pmap_l0_to_l1(l0, va);
		} else {
			l1 = pmap_l1(pmap, va);
		}

		if (pmap_load(l1) == 0) {
			va_next = (va + L1_SIZE) & ~L1_OFFSET;
			if (va_next < va)
				va_next = eva;
			continue;
		}

		va_next = (va + L2_SIZE) & ~L2_OFFSET;
		if (va_next < va)
			va_next = eva;

		l2 = pmap_l1_to_l2(l1, va);
		if ((l2e = pmap_load(l2)) == 0)
			continue;
		if ((l2e & PTE_RWX) != 0) { // superpage
			if (va + L2_SIZE == va_next && eva >= va_next) {
				if ((l2e & PTE_SW_WIRED) == 0)
					panic("%s: l2 %#jx is missing "
					    "PTE_SW_WIRED", __func__, (uintmax_t)l2e);
				pmap_clear_bits(l2, PTE_SW_WIRED);
				continue;
			} else {
				if (!pv_lists_locked) {
					pv_lists_locked = true;
					if (!rw_try_rlock(&pvh_global_lock)) {
						PMAP_UNLOCK(pmap);
						rw_rlock(&pvh_global_lock);
						/* Repeat va. */
						goto retry;
					}
				}
				if (!pmap_demote_l2(pmap, l2, va))
					panic("%s: demotion failed", __func__);
			}
		}

		if (va_next > eva)
			va_next = eva;
		for (pt_entry_t *l3 = pmap_l2_to_l3(l2, va);
		     va != va_next; l3++, va += L3_SIZE) {
			pt_entry_t l3e = pmap_load(l3);
			if (l3e == 0)
				continue;
			if ((l3e & PTE_SW_WIRED) == 0)
				panic("%s: l3 %#jx is missing "
				    "PTE_SW_WIRED", __func__, (uintmax_t)l3e);

			/*
			 * PG_W must be cleared atomically.  Although the pmap
			 * lock synchronizes access to PG_W, another processor
			 * could be setting PG_M and/or PG_A concurrently.
			 */
			pmap_clear_bits(l3, PTE_SW_WIRED);
			pmap->pm_stats.wired_count--;
		}
	}
	if (pv_lists_locked)
		rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
}

/*
 *	Copy the range specified by src_addr/len
 *	from the source map to the range dst_addr/len
 *	in the destination map.
 *
 *	This routine is only advisory and need not do anything.
 */

void
pmap_copy(pmap_t dst_pmap, pmap_t src_pmap, vm_offset_t dst_addr, vm_size_t len,
    vm_offset_t src_addr)
{

}

/*
 *	pmap_zero_page zeros the specified hardware page by mapping
 *	the page into KVM and using bzero to clear its contents.
 */
void
pmap_zero_page(vm_page_t m)
{
	vm_offset_t va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));

	pagezero((void *)va);
}

/*
 *	pmap_zero_page_area zeros the specified hardware page by mapping 
 *	the page into KVM and using bzero to clear its contents.
 *
 *	off and size may not cover an area beyond a single hardware page.
 */
void
pmap_zero_page_area(vm_page_t m, int off, int size)
{
	vm_offset_t va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));

	if (off == 0 && size == PAGE_SIZE)
		pagezero((void *)va);
	else
		bzero((char *)va + off, size);
}

/*
 *	pmap_copy_page copies the specified (machine independent)
 *	page by mapping the page into virtual memory and using
 *	bcopy to copy the page, one machine dependent page at a
 *	time.
 */
void
pmap_copy_page(vm_page_t msrc, vm_page_t mdst)
{
	vm_offset_t src = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(msrc));
	vm_offset_t dst = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mdst));

	pagecopy((void *)src, (void *)dst);
}

int unmapped_buf_allowed = 1;

void
pmap_copy_pages(vm_page_t ma[], vm_offset_t a_offset, vm_page_t mb[],
    vm_offset_t b_offset, int xfersize)
{
	void *a_cp, *b_cp;
	vm_page_t m_a, m_b;
	vm_paddr_t p_a, p_b;
	vm_offset_t a_pg_offset, b_pg_offset;
	int cnt;

	while (xfersize > 0) {
		a_pg_offset = a_offset & PAGE_MASK;
		m_a = ma[a_offset >> PAGE_SHIFT];
		p_a = m_a->phys_addr;
		b_pg_offset = b_offset & PAGE_MASK;
		m_b = mb[b_offset >> PAGE_SHIFT];
		p_b = m_b->phys_addr;
		cnt = min(xfersize, PAGE_SIZE - a_pg_offset);
		cnt = min(cnt, PAGE_SIZE - b_pg_offset);
		if (__predict_false(!PHYS_IN_DMAP(p_a))) {
			panic("!DMAP a %lx", p_a);
		} else {
			a_cp = (char *)PHYS_TO_DMAP(p_a) + a_pg_offset;
		}
		if (__predict_false(!PHYS_IN_DMAP(p_b))) {
			panic("!DMAP b %lx", p_b);
		} else {
			b_cp = (char *)PHYS_TO_DMAP(p_b) + b_pg_offset;
		}
		bcopy(a_cp, b_cp, cnt);
		a_offset += cnt;
		b_offset += cnt;
		xfersize -= cnt;
	}
}

vm_offset_t
pmap_quick_enter_page(vm_page_t m)
{

	return (PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)));
}

void
pmap_quick_remove_page(vm_offset_t addr)
{
}

/*
 * Returns true if the pmap's pv is one of the first
 * 16 pvs linked to from this page.  This count may
 * be changed upwards or downwards in the future; it
 * is only necessary that true be returned for a small
 * subset of pmaps for proper page aging.
 */
boolean_t
pmap_page_exists_quick(pmap_t pmap, vm_page_t m)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pv_entry_t pv;
	int loops = 0;
	boolean_t rv;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_page_exists_quick: page %p is not managed", m));
	rv = FALSE;
	rw_rlock(&pvh_global_lock);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		if (PV_PMAP(pv) == pmap) {
			rv = TRUE;
			break;
		}
		loops++;
		if (loops >= 16)
			break;
	}
	if (!rv && loops < 16 && (m->flags & PG_FICTITIOUS) == 0) {
		pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			if (PV_PMAP(pv) == pmap) {
				rv = TRUE;
				break;
			}
			loops++;
			if (loops >= 16)
				break;
		}
	}
	rw_runlock(lock);
	rw_runlock(&pvh_global_lock);
	return (rv);
}

/*
 *	pmap_page_wired_mappings:
 *
 *	Return the number of managed mappings to the given physical page
 *	that are wired.
 */
int
pmap_page_wired_mappings(vm_page_t m)
{
	struct rwlock *lock;
	pv_entry_t pv;

	if ((m->oflags & VPO_UNMANAGED) != 0)
		return (0);
	rw_rlock(&pvh_global_lock);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
restart:;
	int count = 0;
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap_t pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			int md_gen = m->md.pv_gen;
			rw_runlock(lock);
			PMAP_LOCK(pmap);
			rw_rlock(lock);
			if (md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		pd_entry_t *l2 = pmap_l2(pmap, pv->pv_va);
		KASSERT(l2 != NULL && (pmap_load(l2) & PTE_RWX) == 0, //wycpull assert pointing to page table
		    ("%s: found a 2mpage in page %p's pv list", __func__, m));
		pt_entry_t *l3 = pmap_l2_to_l3(l2, pv->pv_va);
		if ((pmap_load(l3) & PTE_SW_WIRED) != 0)
			count++;
		PMAP_UNLOCK(pmap);
	}
	if ((m->flags & PG_FICTITIOUS) == 0) {
		struct md_page *pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			pmap_t pmap = PV_PMAP(pv);
			if (!PMAP_TRYLOCK(pmap)) {
				int md_gen = m->md.pv_gen;
				int pvh_gen = pvh->pv_gen;
				rw_runlock(lock);
				PMAP_LOCK(pmap);
				rw_rlock(lock);
				if (md_gen != m->md.pv_gen ||
				    pvh_gen != pvh->pv_gen) {
					PMAP_UNLOCK(pmap);
					goto restart;
				}
			}
			pd_entry_t *l2 = pmap_l2(pmap, pv->pv_va);
			if ((pmap_load(l2) & PTE_SW_WIRED) != 0)
				count++;
			PMAP_UNLOCK(pmap);
		}
	}
	rw_runlock(lock);
	rw_runlock(&pvh_global_lock);
	return (count);
}

/*
 * Returns true if the given page is mapped individually or as part of
 * a 2mpage.  Otherwise, returns false.
 */
bool
pmap_page_is_mapped(vm_page_t m)
{
	struct rwlock *lock;
	bool rv;

	if ((m->oflags & VPO_UNMANAGED) != 0)
		return (false);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
	rv = !TAILQ_EMPTY(&m->md.pv_list) ||
	    ((m->flags & PG_FICTITIOUS) == 0 &&
	    !TAILQ_EMPTY(&pa_to_pvh(VM_PAGE_TO_PHYS(m))->pv_list));
	rw_runlock(lock);
	return (rv);
}

// remove @pv from @m's pv_list
static void
pmap_remove_pages_pv(pmap_t pmap, vm_page_t m, pv_entry_t pv,
    spglist_t *free, bool superpage)
{
	struct md_page *pvh;
	vm_page_t mptp, mt;

	if (superpage) {
		pmap_resident_count_dec(pmap, Ln_ENTRIES);
		pvh = pa_to_pvh(m->phys_addr);
		TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
		pvh->pv_gen++;
		if (TAILQ_EMPTY(&pvh->pv_list)) {
			for (mt = m; mt < &m[Ln_ENTRIES]; mt++)
				if (TAILQ_EMPTY(&mt->md.pv_list) &&
				    (mt->a.flags & PGA_WRITEABLE) != 0)
					vm_page_aflag_clear(mt, PGA_WRITEABLE);
		}
		mptp = pmap_remove_l3pt_page(pmap, pv->pv_va);
		if (mptp != NULL) {
			KASSERT(vm_page_any_valid(mptp),
			    ("%s: pte page not promoted", __func__));
			pmap_resident_count_dec(pmap, 1);
			KASSERT(mptp->ref_count == Ln_ENTRIES,
			    ("%s: pte page ref count error", __func__));
			mptp->ref_count = 0;
			pmap_add_delayed_free_list(mptp, free, FALSE);
		}
	} else {
		pmap_resident_count_dec(pmap, 1);
		TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		if (TAILQ_EMPTY(&m->md.pv_list) &&
		    (m->a.flags & PGA_WRITEABLE) != 0) {
			pvh = pa_to_pvh(m->phys_addr);
			if (TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
		}
	}
}

/*
 * Destroy all managed, non-wired mappings in the given user-space
 * pmap.  This pmap cannot be active on any processor besides the
 * caller.
 *
 * This function cannot be applied to the kernel pmap.  Moreover, it
 * is not intended for general use.  It is only to be used during
 * process termination.  Consequently, it can be implemented in ways
 * that make it faster than pmap_remove().  First, it can more quickly
 * destroy mappings by iterating over the pmap's collection of PV
 * entries, rather than searching the page table.  Second, it doesn't
 * have to test and clear the page table entries atomically, because
 * no processor is currently accessing the user address space.  In
 * particular, a page table entry's dirty bit won't change state once
 * this function starts.
 */
void
pmap_remove_pages(pmap_t pmap) // reference pmap_remove()
{
	struct pv_chunk *pc, *npc;
	struct rwlock *lock = NULL;

	spglist_t free = SLIST_HEAD_INITIALIZER(free);
	rw_rlock(&pvh_global_lock);
	PMAP_LOCK(pmap);
	TAILQ_FOREACH_SAFE(pc, &pmap->pm_pvchunk, pc_pmlist, npc) {
		bool allfree = true;
		int freed __pv_stat_used = 0;
		for (int field = 0; field < _NPCM; field++) {
			uint64_t inuse = ~pc->pc_map[field] & pc_freemask[field];
			while (inuse != 0) {
				int64_t bit = ffsl(inuse) - 1;
				int idx = field * 64 + bit;
				pv_entry_t pv = &pc->pc_pventry[idx];
				uint64_t bitmask = 1UL << bit;
				inuse &= ~bitmask;

				pt_entry_t *ln = pmap_l1(pmap, pv->pv_va); // point to an entry in ln
				pd_entry_t lme = pmap_load(ln); // a page table entry in lm
				ln = pmap_l1_to_l2(ln, pv->pv_va);
				pt_entry_t lne = pmap_load(ln); // the entry in ln

				KASSERT((lne & PTE_V) != 0,
				    ("L2 PTE is invalid... bogus PV entry? "
				    "va=%#lx, pte=%#lx", pv->pv_va, lne));
				bool superpage;
				if ((lne & PTE_RWX) != 0) { // superpage
					superpage = true;
				} else { // point to l3 page table
					superpage = false;
					lme = lne;
					ln = pmap_l2_to_l3(ln, pv->pv_va);
					lne = pmap_load(ln);
				}

				/*
				 * We cannot remove wired pages from a
				 * process' mapping at this time.
				 */
				if (lne & PTE_SW_WIRED) {
					allfree = false;
					continue;
				}
				/* Mark free */
				pc->pc_map[field] |= bitmask;

				vm_page_t m = PHYS_TO_VM_PAGE(PTE_TO_PHYS(lne));
				KASSERT((m->flags & PG_FICTITIOUS) != 0 ||
				    m < &vm_page_array[vm_page_array_size],
				    ("%s: bad pte %#jx", __func__, (uintmax_t)lne));

				pmap_clear(ln);

				/*
				 * Update the vm_page_t clean/reference bits.
				 */
				if ((lne & (PTE_D | PTE_W)) == (PTE_D | PTE_W)) {
					if (superpage)
						for (vm_page_t mt = m;
						    mt < &m[Ln_ENTRIES]; mt++)
							vm_page_dirty(mt);
					else
						vm_page_dirty(m);
				}

				CHANGE_PV_LIST_LOCK_TO_VM_PAGE(&lock, m);

				pmap_remove_pages_pv(pmap, m, pv, &free, superpage);
				pmap_unuse_pt(pmap, pv->pv_va, lme, &free);
				freed++;
			}
		}
		PV_STAT(atomic_add_long(&pv_entry_frees, freed));
		PV_STAT(atomic_add_int(&pv_entry_spare, freed));
		PV_STAT(atomic_subtract_long(&pv_entry_count, freed));
		if (allfree) {
			TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_pmlist);
			free_pv_chunk(pc); // remove from pv_chunks list
		}
	} // TAILQ_FOREACH_SAFE(pc,...)
	if (lock != NULL)
		rw_wunlock(lock);
	pmap_invalidate_all(pmap);
	rw_runlock(&pvh_global_lock);
	PMAP_UNLOCK(pmap);
	vm_page_free_pages_toq(&free, false);
}

static bool
pmap_page_test_mappings(vm_page_t m, boolean_t accessed, boolean_t modified)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pd_entry_t *l2;
	pt_entry_t *l3, mask;
	pv_entry_t pv;
	pmap_t pmap;
	int md_gen, pvh_gen;
	bool rv;

	mask = 0;
	if (modified)
		mask |= PTE_D;
	if (accessed)
		mask |= PTE_A;

	rv = FALSE;
	rw_rlock(&pvh_global_lock);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
restart:
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			rw_runlock(lock);
			PMAP_LOCK(pmap);
			rw_rlock(lock);
			if (md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		l2 = pmap_l2(pmap, pv->pv_va);
		KASSERT(l2 != NULL && (pmap_load(l2) & PTE_RWX) == 0, //wycpull assert pointing to page table
		    ("%s: found a 2mpage in page %p's pv list", __func__, m));
		l3 = pmap_l2_to_l3(l2, pv->pv_va);
		rv = (pmap_load(l3) & mask) == mask;
		PMAP_UNLOCK(pmap);
		if (rv)
			goto out;
	}
	if ((m->flags & PG_FICTITIOUS) == 0) {
		pvh = pa_to_pvh(VM_PAGE_TO_PHYS(m));
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			pmap = PV_PMAP(pv);
			if (!PMAP_TRYLOCK(pmap)) {
				md_gen = m->md.pv_gen;
				pvh_gen = pvh->pv_gen;
				rw_runlock(lock);
				PMAP_LOCK(pmap);
				rw_rlock(lock);
				if (md_gen != m->md.pv_gen ||
				    pvh_gen != pvh->pv_gen) {
					PMAP_UNLOCK(pmap);
					goto restart;
				}
			}
			l2 = pmap_l2(pmap, pv->pv_va);
			rv = (pmap_load(l2) & mask) == mask;
			PMAP_UNLOCK(pmap);
			if (rv)
				goto out;
		}
	}
out:
	rw_runlock(lock);
	rw_runlock(&pvh_global_lock);
	return (rv);
}

/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page was modified
 *	in any physical maps.
 */
boolean_t
pmap_is_modified(vm_page_t m)
{

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_is_modified: page %p is not managed", m));

	/*
	 * If the page is not busied then this check is racy.
	 */
	if (!pmap_page_is_write_mapped(m))
		return (FALSE);
	return (pmap_page_test_mappings(m, FALSE, TRUE));
}

/*
 *	pmap_is_prefaultable:
 *
 *	Return whether or not the specified virtual address is eligible
 *	for prefault.
 */
boolean_t
pmap_is_prefaultable(pmap_t pmap, vm_offset_t addr)
{
	pt_entry_t *l3;
	boolean_t rv;

	/*
	 * Return TRUE if and only if the L3 entry for the specified virtual
	 * address is allocated but invalid.
	 */
	rv = FALSE;
	PMAP_LOCK(pmap);
	l3 = pmap_l3(pmap, addr);
	if (l3 != NULL && pmap_load(l3) == 0) {
		rv = TRUE;
	}
	PMAP_UNLOCK(pmap);
	return (rv);
}

/*
 *	pmap_is_referenced:
 *
 *	Return whether or not the specified physical page was referenced
 *	in any physical maps.
 */
boolean_t
pmap_is_referenced(vm_page_t m)
{

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_is_referenced: page %p is not managed", m));
	return (pmap_page_test_mappings(m, TRUE, FALSE));
}

/*
 * Clear the write and modified bits in each of the given page's mappings.
 */
void
pmap_remove_write(vm_page_t m)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pmap_t pmap;
	pd_entry_t *l2;
	pt_entry_t *l3, oldl3e, newl3e;
	pv_entry_t next_pv, pv;
	vm_offset_t va;
	int md_gen, pvh_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_remove_write: page %p is not managed", m));
	vm_page_assert_busied(m);

	if (!pmap_page_is_write_mapped(m))
		return;
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pvh_dummy :
	    pa_to_pvh(VM_PAGE_TO_PHYS(m));
	rw_rlock(&pvh_global_lock);
retry_pv_loop:
	rw_wlock(lock);
	TAILQ_FOREACH_SAFE(pv, &pvh->pv_list, pv_next, next_pv) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				rw_wunlock(lock);
				goto retry_pv_loop;
			}
		}
		va = pv->pv_va;
		l2 = pmap_l2(pmap, va);
		if ((pmap_load(l2) & PTE_W) != 0)
			(void)pmap_demote_l2_locked(pmap, l2, va, &lock);
		KASSERT(lock == VM_PAGE_TO_PV_LIST_LOCK(m),
		    ("inconsistent pv lock %p %p for page %p",
		    lock, VM_PAGE_TO_PV_LIST_LOCK(m), m));
		PMAP_UNLOCK(pmap);
	}
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				rw_wunlock(lock);
				goto retry_pv_loop;
			}
		}
		l2 = pmap_l2(pmap, pv->pv_va);
		KASSERT(l2 != NULL && (pmap_load(l2) & PTE_RWX) == 0, //wycpull assert pointing to page table
		    ("%s: found a 2mpage in page %p's pv list", __func__, m));
		l3 = pmap_l2_to_l3(l2, pv->pv_va);
		oldl3e = pmap_load(l3);
retry:
		if ((oldl3e & PTE_W) != 0) {
			newl3e = oldl3e & ~(PTE_D | PTE_W);
			if (!atomic_fcmpset_long(l3, &oldl3e, newl3e))
				goto retry;
			if ((oldl3e & PTE_D) != 0)
				vm_page_dirty(m);
			pmap_invalidate_page(pmap, pv->pv_va);
		}
		PMAP_UNLOCK(pmap);
	}
	rw_wunlock(lock);
	vm_page_aflag_clear(m, PGA_WRITEABLE);
	rw_runlock(&pvh_global_lock);
}

/*
 *	pmap_ts_referenced:
 *
 *	Return a count of reference bits for a page, clearing those bits.
 *	It is not necessary for every reference bit to be cleared, but it
 *	is necessary that 0 only be returned when there are truly no
 *	reference bits set.
 *
 *	As an optimization, update the page's dirty field if a modified bit is
 *	found while counting reference bits.  This opportunistic update can be
 *	performed at low cost and can eliminate the need for some future calls
 *	to pmap_is_modified().  However, since this function stops after
 *	finding PMAP_TS_REFERENCED_MAX reference bits, it may not detect some
 *	dirty pages.  Those dirty pages will only be detected by a future call
 *	to pmap_is_modified().
 */
static inline unsigned hash_pvp(vm_paddr_t pa, vm_offset_t va, uintptr_t pmap)
{
	return
	    ((pa >> PAGE_SHIFT) ^ (va >> L2_SHIFT) ^ pmap) &
	    (Ln_ENTRIES - 1);
}

int
pmap_ts_referenced(vm_page_t m)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pv_entry_t pv, pvf;
	vm_paddr_t pa;
	int cleared, not_cleared;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("%s: page %p is not managed", __func__, m));
	spglist_t free = SLIST_HEAD_INITIALIZER(free);
	cleared = 0;
	pa = VM_PAGE_TO_PHYS(m);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pvh_dummy : pa_to_pvh(pa);

	lock = PHYS_TO_PV_LIST_LOCK(pa);
	rw_rlock(&pvh_global_lock);
	rw_wlock(lock);
retry:
	not_cleared = 0;
	if ((pvf = TAILQ_FIRST(&pvh->pv_list)) == NULL)
		goto small_mappings;
	pv = pvf;
	do {
		pmap_t pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			int pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		vm_offset_t va = pv->pv_va;
		pd_entry_t *l2 = pmap_l2(pmap, va);
		pd_entry_t l2e = pmap_load(l2);
		if ((l2e & (PTE_W | PTE_D)) == (PTE_W | PTE_D)) {
			/*
			 * Although l2e is mapping a 2MB page, because
			 * this function is called at a 4KB page granularity,
			 * we only update the 4KB page under test.
			 */
			vm_page_dirty(m);
		}
		if ((l2e & PTE_A) != 0) {
			/*
			 * Since this reference bit is shared by 512 4KB
			 * pages, it should not be cleared every time it is
			 * tested.  Apply a simple "hash" function on the
			 * physical page number, the virtual superpage number,
			 * and the pmap address to select one 4KB page out of
			 * the 512 on which testing the reference bit will
			 * result in clearing that reference bit.  This
			 * function is designed to avoid the selection of the
			 * same 4KB page for every 2MB page mapping.
			 *
			 * On demotion, a mapping that hasn't been referenced
			 * is simply destroyed.  To avoid the possibility of a
			 * subsequent page fault on a demoted wired mapping,
			 * always leave its reference bit set.  Moreover,
			 * since the superpage is wired, the current state of
			 * its reference bit won't affect page replacement.
			 */
			if (hash_pvp(pa, pv->pv_va, (uintptr_t)pmap) == 0 &&
			    (l2e & PTE_SW_WIRED) == 0) {
				pmap_clear_bits(l2, PTE_A);
				pmap_invalidate_page(pmap, va);
				cleared++;
			} else
				not_cleared++;
		}
		PMAP_UNLOCK(pmap);
		/* Rotate the PV list if it has more than one entry. */
		if (pv != NULL && TAILQ_NEXT(pv, pv_next) != NULL) {
			TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
			TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
			pvh->pv_gen++;
		}
		if (cleared + not_cleared >= PMAP_TS_REFERENCED_MAX)
			goto out;
	} while ((pv = TAILQ_FIRST(&pvh->pv_list)) != pvf);
small_mappings:
	if ((pvf = TAILQ_FIRST(&m->md.pv_list)) == NULL)
		goto out;
	pv = pvf;
	do {
		pmap_t pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			int pvh_gen = pvh->pv_gen;
			int md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		pd_entry_t *l2 = pmap_l2(pmap, pv->pv_va);
		KASSERT(l2 != NULL && (pmap_load(l2) & PTE_RWX) == 0, //wycpull  //ori PTE_RX
		    ("%s: found an invalid l2 table", __func__));
		pt_entry_t *l3 = pmap_l2_to_l3(l2, pv->pv_va);
		pt_entry_t l3e = pmap_load(l3);
		if ((l3e & PTE_D) != 0)
			vm_page_dirty(m);
		if ((l3e & PTE_A) != 0) {
			if ((l3e & PTE_SW_WIRED) == 0) {
				/*
				 * Wired pages cannot be paged out so
				 * doing accessed bit emulation for
				 * them is wasted effort. We do the
				 * hard work for unwired pages only.
				 */
				pmap_clear_bits(l3, PTE_A);
				pmap_invalidate_page(pmap, pv->pv_va);
				cleared++;
			} else
				not_cleared++;
		}
		PMAP_UNLOCK(pmap);
		/* Rotate the PV list if it has more than one entry. */
		if (pv != NULL && TAILQ_NEXT(pv, pv_next) != NULL) {
			TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
			TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
			m->md.pv_gen++;
		}
	} while ((pv = TAILQ_FIRST(&m->md.pv_list)) != pvf && cleared +
	    not_cleared < PMAP_TS_REFERENCED_MAX);
out:
	rw_wunlock(lock);
	rw_runlock(&pvh_global_lock);
	vm_page_free_pages_toq(&free, false);
	return (cleared + not_cleared);
}

/*
 *	Apply the given advice to the specified range of addresses within the
 *	given pmap.  Depending on the advice, clear the referenced and/or
 *	modified flags in each mapping and set the mapped page's dirty field.
 */
void
pmap_advise(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, int advice)
{
}

/*
 *	Clear the modify bits on the specified physical page.
 */
void
pmap_clear_modify(vm_page_t m)
{
	pv_entry_t next_pv, pv;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("%s: page %p is not managed", __func__, m));
	vm_page_assert_busied(m);

	if (!pmap_page_is_write_mapped(m))
	        return;

	struct md_page *pvh = (m->flags & PG_FICTITIOUS) != 0 ?
		&pvh_dummy : pa_to_pvh(VM_PAGE_TO_PHYS(m));
	struct rwlock *lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(&pvh_global_lock);
	rw_wlock(lock);
restart:
	TAILQ_FOREACH_SAFE(pv, &pvh->pv_list, pv_next, next_pv) {
		pmap_t pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			int pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		vm_offset_t va = pv->pv_va;
		pd_entry_t *l2 = pmap_l2(pmap, va);
		pd_entry_t oldl2e = pmap_load(l2);
		/* If oldl2e has PTE_W set, then it also has PTE_D set. */
		if ((oldl2e & PTE_W) != 0 &&
		    pmap_demote_l2_locked(pmap, l2, va, &lock) &&
		    (oldl2e & PTE_SW_WIRED) == 0) {
			/*
			 * Write protect the mapping to a single page so that
			 * a subsequent write access may repromote.
			 */
			va += VM_PAGE_TO_PHYS(m) - PTE_TO_PHYS(oldl2e);
			pt_entry_t *l3 = pmap_l2_to_l3(l2, va);
			pmap_clear_bits(l3, PTE_D | PTE_W);
			vm_page_dirty(m);
			pmap_invalidate_page(pmap, va);
		}
		PMAP_UNLOCK(pmap);
	}
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap_t pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			int md_gen = m->md.pv_gen;
			int pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		pd_entry_t *l2 = pmap_l2(pmap, pv->pv_va);
		KASSERT(l2 != NULL && (pmap_load(l2) & PTE_RWX) == 0, //wycpull assert pointing to page table
		    ("%s: found a 2mpage in page %p's pv list", __func__, m));
		pt_entry_t *l3 = pmap_l2_to_l3(l2, pv->pv_va);
		if ((pmap_load(l3) & (PTE_D | PTE_W)) == (PTE_D | PTE_W)) {
			pmap_clear_bits(l3, PTE_D | PTE_W);
			pmap_invalidate_page(pmap, pv->pv_va);
		}
		PMAP_UNLOCK(pmap);
	}
	rw_wunlock(lock);
	rw_runlock(&pvh_global_lock);
}

void *
pmap_mapbios(vm_paddr_t pa, vm_size_t size)
{

        return ((void *)PHYS_TO_DMAP(pa));
}

void
pmap_unmapbios(void *p, vm_size_t size)
{
}

/*
 * Sets the memory attribute for the specified page.
 */
void
pmap_page_set_memattr(vm_page_t m, vm_memattr_t ma)
{

	m->md.pv_memattr = ma;

	/*
	 * If "m" is a normal page, update its direct mapping.  This update
	 * can be relied upon to perform any cache operations that are
	 * required for data coherence.
	 */
	if ((m->flags & PG_FICTITIOUS) == 0 &&
	    pmap_change_attr(PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)), PAGE_SIZE,
	    m->md.pv_memattr) != 0)
		panic("memory attribute change on the direct map failed");
}

/*
 * Changes the specified virtual address range's memory type to that given by
 * the parameter "mode".  The specified virtual address range must be
 * completely contained within either the direct map or the kernel map.
 *
 * Returns zero if the change completed successfully, and either EINVAL or
 * ENOMEM if the change failed.  Specifically, EINVAL is returned if some part
 * of the virtual address range was not mapped, and ENOMEM is returned if
 * there was insufficient memory available to complete the change.  In the
 * latter case, the memory type may have been changed on some part of the
 * virtual address range.
 */
int
pmap_change_attr(vm_offset_t va, vm_size_t size, int mode)
{
	int error;

	PMAP_LOCK(kernel_pmap);
	error = pmap_change_attr_locked(va, size, mode);
	PMAP_UNLOCK(kernel_pmap);
	return (error);
}

static int
pmap_change_attr_locked(vm_offset_t va, vm_size_t size, int mode)
{
	vm_offset_t base, offset, tmpva;
	pd_entry_t *l1, l1e;
	pd_entry_t *l2, l2e;
	pt_entry_t *l3, l3e;

	PMAP_LOCK_ASSERT(kernel_pmap, MA_OWNED);
	base = trunc_page(va);
	offset = va & PAGE_MASK;
	size = round_page(offset + size);

	if (!VIRT_IN_DMAP(base) &&
	    !(base >= VM_MIN_KERNEL_ADDRESS && base < VM_MAX_KERNEL_ADDRESS))
		return (EINVAL);

	for (tmpva = base; tmpva < base + size; ) {
		l1 = pmap_l1(kernel_pmap, tmpva);
		if (l1 == NULL || ((l1e = pmap_load(l1)) & PTE_V) == 0)
			return (EINVAL);
		if ((l1e & PTE_RWX) != 0) { // this should not be supported
panic("%s: wyctest\n", __func__); // tested. not reach here
			/*
			 * TODO: Demote if attributes don't match and there
			 * isn't an L1 page left in the range, and update the
			 * L1 entry if the attributes don't match but there is
			 * an L1 page left in the range, once we support the
			 * upcoming Svpbmt extension.
			 */
			tmpva = (tmpva & ~L1_OFFSET) + L1_SIZE;
			continue;
		}
		l2 = pmap_l1_to_l2(l1, tmpva);
		if (((l2e = pmap_load(l2)) & PTE_V) == 0)
			return (EINVAL);
		if ((l2e & PTE_RWX) != 0) { // superpage
			/*
			 * TODO: Demote if attributes don't match and there
			 * isn't an L2 page left in the range, and update the
			 * L2 entry if the attributes don't match but there is
			 * an L2 page left in the range, once we support the
			 * upcoming Svpbmt extension.
			 */
			tmpva = (tmpva & ~L2_OFFSET) + L2_SIZE;
			continue;
		}
		l3 = pmap_l2_to_l3(l2, tmpva);
		if (((l3e = pmap_load(l3)) & PTE_V) == 0)
			return (EINVAL);
		/*
		 * TODO: Update the L3 entry if the attributes don't match once
		 * we support the upcoming Svpbmt extension.
		 */
		tmpva += PAGE_SIZE;
	}

	return (0);
}

/*
 * Perform the pmap work for mincore(2).  If the page is not both referenced and
 * modified by this pmap, returns its physical address so that the caller can
 * find other mappings.
 */
int
pmap_mincore(pmap_t pmap, vm_offset_t addr, vm_paddr_t *pap)
{
	pt_entry_t *l2, *l3, tpte;
	vm_paddr_t pa;
	int val;
	bool managed;

	PMAP_LOCK(pmap);
	l2 = pmap_l2(pmap, addr);
	if (l2 != NULL && ((tpte = pmap_load(l2)) & PTE_V) != 0) {
		if ((tpte & PTE_RWX) != 0) { // superpage
			pa = PTE_TO_PHYS(tpte) | (addr & L2_OFFSET);
			val = MINCORE_INCORE | MINCORE_PSIND(1);
		} else {
			l3 = pmap_l2_to_l3(l2, addr);
			tpte = pmap_load(l3);
			if ((tpte & PTE_V) == 0) {
				PMAP_UNLOCK(pmap);
				return (0);
			}
			pa = PTE_TO_PHYS(tpte) | (addr & L3_OFFSET);
			val = MINCORE_INCORE;
		}

		if ((tpte & PTE_D) != 0)
			val |= MINCORE_MODIFIED | MINCORE_MODIFIED_OTHER;
		if ((tpte & PTE_A) != 0)
			val |= MINCORE_REFERENCED | MINCORE_REFERENCED_OTHER;
		managed = (tpte & PTE_SW_MANAGED) == PTE_SW_MANAGED;
	} else {
		managed = false;
		val = 0;
	}
	if ((val & (MINCORE_MODIFIED_OTHER | MINCORE_REFERENCED_OTHER)) !=
	    (MINCORE_MODIFIED_OTHER | MINCORE_REFERENCED_OTHER) && managed) {
		*pap = pa;
	}
	PMAP_UNLOCK(pmap);
	return (val);
}

void
pmap_activate_sw(struct thread *td)
{
	pmap_t oldpmap, pmap;
	u_int hart;

	oldpmap = PCPU_GET(pc_curpmap);
	pmap = vmspace_pmap(td->td_proc->p_vmspace);
	if (pmap == oldpmap)
		return;
	csr_write(satp, pmap->pm_satp);

	hart = PCPU_GET(pc_hart);
#ifdef SMP
	CPU_SET_ATOMIC(hart, &pmap->pm_active);
	CPU_CLR_ATOMIC(hart, &oldpmap->pm_active);
#else
	CPU_SET(hart, &pmap->pm_active);
	CPU_CLR(hart, &oldpmap->pm_active);
#endif
	PCPU_SET(pc_curpmap, pmap);

	sfence_vma();
}

void
pmap_activate(struct thread *td)
{

	critical_enter();
	pmap_activate_sw(td);
	critical_exit();
}

void
pmap_activate_boot(pmap_t pmap)
{
	u_int hart;

	hart = PCPU_GET(pc_hart);
#ifdef SMP
	CPU_SET_ATOMIC(hart, &pmap->pm_active);
#else
	CPU_SET(hart, &pmap->pm_active); // (src, dst)
#endif
	PCPU_SET(pc_curpmap, pmap); // (dst, src)
}

void
pmap_active_cpus(pmap_t pmap, cpuset_t *res)
{
	*res = pmap->pm_active;
}

void
pmap_sync_icache(pmap_t pmap, vm_offset_t va, vm_size_t sz)
{
	cpuset_t mask;

	/*
	 * From the RISC-V User-Level ISA V2.2:
	 *
	 * "To make a store to instruction memory visible to all
	 * RISC-V harts, the writing hart has to execute a data FENCE
	 * before requesting that all remote RISC-V harts execute a
	 * FENCE.I."
	 *
	 * However, this is slightly misleading; we still need to
	 * perform a FENCE.I for the local hart, as FENCE does nothing
	 * for its icache. FENCE.I alone is also sufficient for the
	 * local hart.
	 */
	sched_pin();
	mask = all_harts;
	CPU_CLR(PCPU_GET(pc_hart), &mask);
	fence_i();
	if (!CPU_EMPTY(&mask) && smp_started) {
		fence();
		sbi_remote_fence_i(mask.__bits);
	}
	sched_unpin();
}

/*
 *	Increase the starting virtual address of the given mapping if a
 *	different alignment might result in more superpage mappings.
 */
void
pmap_align_superpage(vm_object_t object, vm_ooffset_t offset,
    vm_offset_t *addr, vm_size_t size)
{
	vm_offset_t superpage_offset;

	if (size < L2_SIZE)
		return;
	if (object != NULL && (object->flags & OBJ_COLORED) != 0)
		offset += ptoa(object->pg_color);
	superpage_offset = offset & L2_OFFSET;
	if (size - ((L2_SIZE - superpage_offset) & L2_OFFSET) < L2_SIZE ||
	    (*addr & L2_OFFSET) == superpage_offset)
		return;
	if ((*addr & L2_OFFSET) < superpage_offset)
		*addr = (*addr & ~L2_OFFSET) + superpage_offset;
	else
		*addr = ((*addr + L2_OFFSET) & ~L2_OFFSET) + superpage_offset;
}

/**
 * Get the kernel virtual address of a set of physical pages. If there are
 * physical addresses not covered by the DMAP perform a transient mapping
 * that will be removed when calling pmap_unmap_io_transient.
 *
 * \param page        The pages the caller wishes to obtain the virtual
 *                    address on the kernel memory map.
 * \param vaddr       On return contains the kernel virtual memory address
 *                    of the pages passed in the page parameter.
 * \param count       Number of pages passed in.
 * \param can_fault   true if the thread using the mapped pages can take
 *                    page faults, false otherwise.
 *
 * \returns true if the caller must call pmap_unmap_io_transient when
 *          finished or false otherwise.
 *
 */
bool
pmap_map_io_transient(vm_page_t page[], vm_offset_t vaddr[], int count,
    bool can_fault)
{
	vm_paddr_t paddr;
	bool needs_mapping;
	int error __diagused, i;

	/*
	 * Allocate any KVA space that we need, this is done in a separate
	 * loop to prevent calling vmem_alloc while pinned.
	 */
	needs_mapping = false;
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (__predict_false(paddr >= DMAP_MAX_PHYSADDR)) {
			error = vmem_alloc(kernel_arena, PAGE_SIZE,
			    M_BESTFIT | M_WAITOK, &vaddr[i]);
			KASSERT(error == 0, ("vmem_alloc failed: %d", error));
			needs_mapping = true;
		} else {
			vaddr[i] = PHYS_TO_DMAP(paddr);
		}
	}

	/* Exit early if everything is covered by the DMAP */
	if (!needs_mapping)
		return (false);

	if (!can_fault)
		sched_pin();
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (paddr >= DMAP_MAX_PHYSADDR) {
			panic(
			   "pmap_map_io_transient: TODO: Map out of DMAP data");
		}
	}

	return (needs_mapping);
}

void
pmap_unmap_io_transient(vm_page_t page[], vm_offset_t vaddr[], int count,
    bool can_fault)
{
	vm_paddr_t paddr;
	int i;

	if (!can_fault)
		sched_unpin();
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (paddr >= DMAP_MAX_PHYSADDR) {
			panic("RISCVTODO: pmap_unmap_io_transient: Unmap data");
		}
	}
}

boolean_t
pmap_is_valid_memattr(pmap_t pmap __unused, vm_memattr_t mode)
{

	return (mode >= VM_MEMATTR_DEVICE && mode <= VM_MEMATTR_WRITE_BACK);
}

bool
pmap_get_tables(pmap_t pmap, vm_offset_t va, pd_entry_t **l1, pd_entry_t **l2,
    pt_entry_t **l3)
{
if (pmap != kernel_pmap) panic("%s: wyctest\n", __func__); // tested. the @pmap is always kernel_pmap
	/* Get l1 directory entry. */
	pd_entry_t *l1p = pmap_l1(pmap, va);
	*l1 = l1p;

	if (l1p == NULL || (pmap_load(l1p) & PTE_V) == 0)
		return (false);

	if ((pmap_load(l1p) & PTE_RWX) != 0) { //ori PTE_RX
		*l2 = NULL;
		*l3 = NULL;
		return (true);
	}

	/* Get l2 directory entry. */
	pd_entry_t *l2p = pmap_l1_to_l2(l1p, va);
	*l2 = l2p;

	if (/*l2p == NULL || */(pmap_load(l2p) & PTE_V) == 0) //wycpull
		return (false);

	if ((pmap_load(l2p) & PTE_RWX) != 0) { //ori PTE_RX
		*l3 = NULL;
		return (true);
	}

	/* Get l3 page table entry. */
	*l3 = pmap_l2_to_l3(l2p, va);

	return (true);
}

/*
 * Track a range of the kernel's virtual address space that is contiguous
 * in various mapping attributes.
 */
struct pmap_kernel_map_range {
	vm_offset_t sva;
	pt_entry_t attrs;
	int l3pages;
	int l2pages;
	int l1pages;
};

static void
sysctl_kmaps_dump(struct sbuf *sb, struct pmap_kernel_map_range *range,
    vm_offset_t eva)
{

	if (eva <= range->sva)
		return;

	sbuf_printf(sb, "0x%016lx-0x%016lx %c%c%c%c%c %d %d %d\n",
	    range->sva, eva,
	    (range->attrs & PTE_R) ? 'r' : '-',
	    (range->attrs & PTE_W) ? 'w' : '-',
	    (range->attrs & PTE_X) ? 'x' : '-',
	    (range->attrs & PTE_U) ? 'u' : 's',
	    (range->attrs & PTE_G) ? 'g' : '-',
	    range->l1pages, range->l2pages, range->l3pages);

	/* Reset to sentinel value. */
	range->sva = 0xfffffffffffffffful;
}

/*
 * Determine whether the attributes specified by a page table entry match those
 * being tracked by the current range.
 */
static bool
sysctl_kmaps_match(struct pmap_kernel_map_range *range, pt_entry_t attrs)
{

	return (range->attrs == attrs);
}

static void
sysctl_kmaps_reinit(struct pmap_kernel_map_range *range, vm_offset_t va,
    pt_entry_t attrs)
{

	memset(range, 0, sizeof(*range));
	range->sva = va;
	range->attrs = attrs;
}

/*
 * Given a leaf PTE, derive the mapping's attributes. If they do not match
 * those of the current run, dump the address range and its attributes, and
 * begin a new run.
 */
static void
sysctl_kmaps_check(struct sbuf *sb, struct pmap_kernel_map_range *range,
    vm_offset_t va, pd_entry_t l1e, pd_entry_t l2e, pt_entry_t l3e)
{
	pt_entry_t attrs;

	/* The PTE global bit is inherited by lower levels. */
	attrs = l1e & PTE_G;
	if ((l1e & PTE_RWX) != 0)
		attrs |= l1e & (PTE_RWX | PTE_U);
	else if (l2e != 0)
		attrs |= l2e & PTE_G;
	if ((l2e & PTE_RWX) != 0)
		attrs |= l2e & (PTE_RWX | PTE_U);
	else if (l3e != 0)
		attrs |= l3e & (PTE_RWX | PTE_U | PTE_G);

	if (range->sva > va || !sysctl_kmaps_match(range, attrs)) {
		sysctl_kmaps_dump(sb, range, va);
		sysctl_kmaps_reinit(range, va, attrs);
	}
}

static int
sysctl_kmaps(SYSCTL_HANDLER_ARGS)
{
	struct pmap_kernel_map_range range;
	struct sbuf sbuf;

	int error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	struct sbuf *sb = &sbuf;
	sbuf_new_for_sysctl(sb, NULL, PAGE_SIZE, req);

	/* Sentinel value. */
	range.sva = 0xfffffffffffffffful;

	/*
	 * Iterate over the kernel page tables without holding the kernel pmap
	 * lock. Kernel page table pages are never freed, so at worst we will
	 * observe inconsistencies in the output.
	 */
	vm_offset_t sva = VM_MIN_KERNEL_ADDRESS;
	for (int i = pmap_l1_index(sva); i < Ln_ENTRIES; i++) {
		if (i == pmap_l1_index(DMAP_MIN_ADDRESS))
			sbuf_printf(sb, "\nDirect map:\n");
		else if (i == pmap_l1_index(VM_MIN_KERNEL_ADDRESS))
			sbuf_printf(sb, "\nKernel map:\n");

		pd_entry_t l1e = kernel_pmap->pm_top[i];
		if ((l1e & PTE_V) == 0) {
			sysctl_kmaps_dump(sb, &range, sva);
			sva += L1_SIZE;
			continue;
		}
		if ((l1e & PTE_RWX) != 0) { // a "huge page", it is bigger than superpage
//panic("%s: wyctest\n", __func__); // tested. the program will run to here when running "sysctl vm.pmap.kernel_maps"
			sysctl_kmaps_check(sb, &range, sva, l1e, 0, 0);
			range.l1pages++;
			sva += L1_SIZE;
			continue;
		}
		vm_paddr_t pa = PTE_TO_PHYS(l1e);
		pd_entry_t *l2pt = (pd_entry_t *)PHYS_TO_DMAP(pa);

		for (int j = pmap_l2_index(sva); j < Ln_ENTRIES; j++) {
			pd_entry_t l2e = l2pt[j];
			if ((l2e & PTE_V) == 0) {
				sysctl_kmaps_dump(sb, &range, sva);
				sva += L2_SIZE;
				continue;
			}
			if ((l2e & PTE_RWX) != 0) { // superpage
				sysctl_kmaps_check(sb, &range, sva, l1e, l2e, 0);
				range.l2pages++;
				sva += L2_SIZE;
				continue;
			}
			vm_paddr_t pa = PTE_TO_PHYS(l2e);
			pt_entry_t *l3pt = (pd_entry_t *)PHYS_TO_DMAP(pa);

			for (int k = pmap_l3_index(sva); k < Ln_ENTRIES; k++,
			    sva += L3_SIZE) {
				pt_entry_t l3e = l3pt[k];
				if ((l3e & PTE_V) == 0) {
					sysctl_kmaps_dump(sb, &range, sva);
					continue;
				}
				sysctl_kmaps_check(sb, &range, sva,
				    l1e, l2e, l3e);
				range.l3pages++;
			}
		}
	}

	error = sbuf_finish(sb);
	sbuf_delete(sb);
	return (error);
}
SYSCTL_OID(_vm_pmap, OID_AUTO, kernel_maps,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP,
    NULL, 0, sysctl_kmaps, "A",
    "Dump kernel address layout");
