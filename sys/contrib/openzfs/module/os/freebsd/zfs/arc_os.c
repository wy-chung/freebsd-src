/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/spa_impl.h>
#include <sys/counter.h>
#include <sys/zio_compress.h>
#include <sys/zio_checksum.h>
#include <sys/zfs_context.h>
#include <sys/arc.h>
#include <sys/arc_os.h>
#include <sys/zfs_refcount.h>
#include <sys/vdev.h>
#include <sys/vdev_trim.h>
#include <sys/vdev_impl.h>
#include <sys/dsl_pool.h>
#include <sys/zio_checksum.h>
#include <sys/multilist.h>
#include <sys/abd.h>
#include <sys/zil.h>
#include <sys/fm/fs/zfs.h>
#include <sys/eventhandler.h>
#include <sys/callb.h>
#include <sys/kstat.h>
#include <sys/zthr.h>
#include <zfs_fletcher.h>
#include <sys/arc_impl.h>
#include <sys/sdt.h>
#include <sys/aggsum.h>
#include <sys/vnode.h>
#include <cityhash.h>
#include <machine/vmparam.h>
#include <sys/vm.h>
#include <sys/vmmeter.h>

extern struct vfsops zfs_vfsops;

uint_t zfs_arc_free_target = 0;

static void
arc_free_target_init(void *unused __unused)
{
	zfs_arc_free_target = vm_cnt.v_free_target;
}
SYSINIT(arc_free_target_init, SI_SUB_KTHREAD_PAGE, SI_ORDER_ANY,
    arc_free_target_init, NULL);

/*
 * We don't have a tunable for arc_free_target due to the dependency on
 * pagedaemon initialisation.
 */
ZFS_MODULE_PARAM_CALL(zfs_arc, zfs_arc_, free_target,
    param_set_arc_free_target, 0, CTLFLAG_RW,
	"Desired number of free pages below which ARC triggers reclaim");
ZFS_MODULE_PARAM_CALL(zfs_arc, zfs_arc_, no_grow_shift,
    param_set_arc_no_grow_shift, 0, ZMOD_RW,
	"log2(fraction of ARC which must be free to allow growing)");

int64_t
arc_available_memory(void)
{
	int64_t lowest = INT64_MAX;
	int64_t n __unused;

	/*
	 * Cooperate with pagedaemon when it's time for it to scan
	 * and reclaim some pages.
	 */
	n = PAGESIZE * ((int64_t)freemem - zfs_arc_free_target);
	if (n < lowest) {
		lowest = n;
	}
#if defined(__i386) || !defined(UMA_MD_SMALL_ALLOC)
	/*
	 * If we're on an i386 platform, it's possible that we'll exhaust the
	 * kernel heap space before we ever run out of available physical
	 * memory.  Most checks of the size of the heap_area compare against
	 * tune.t_minarmem, which is the minimum available real memory that we
	 * can have in the system.  However, this is generally fixed at 25 pages
	 * which is so low that it's useless.  In this comparison, we seek to
	 * calculate the total heap-size, and reclaim if more than 3/4ths of the
	 * heap is allocated.  (Or, in the calculation, if less than 1/4th is
	 * free)
	 */
	n = uma_avail() - (long)(uma_limit() / 4);
	if (n < lowest) {
		lowest = n;
	}
#endif

	DTRACE_PROBE1(arc__available_memory, int64_t, lowest);
	return (lowest);
}

/*
 * Return a default max arc size based on the amount of physical memory.
 */
uint64_t
arc_default_max(uint64_t min, uint64_t allmem)
{
	uint64_t size;

	if (allmem >= 1 << 30)
		size = allmem - (1 << 30);
	else
		size = min;
	return (MAX(allmem * 5 / 8, size));
}

uint64_t
arc_all_memory(void)
{
	return (ptob(physmem));
}

int
arc_memory_throttle(spa_t *spa, uint64_t reserve, uint64_t txg)
{
	return (0);
}

uint64_t
arc_free_memory(void)
{
	return (ptob(freemem));
}

static eventhandler_tag arc_event_lowmem = NULL;

static void
arc_lowmem(void *arg __unused, int howto __unused)
{
	int64_t free_memory, to_free;

	arc_no_grow = B_TRUE;
	arc_warm = B_TRUE;
	arc_growtime = gethrtime() + SEC2NSEC(arc_grow_retry);
	free_memory = arc_available_memory();
	int64_t can_free = arc_c - arc_c_min;
	if (can_free <= 0)
		return;
	to_free = (can_free >> arc_shrink_shift) - MIN(free_memory, 0);
	DTRACE_PROBE2(arc__needfree, int64_t, free_memory, int64_t, to_free);
	arc_reduce_target_size(to_free);

	/*
	 * It is unsafe to block here in arbitrary threads, because we can come
	 * here from ARC itself and may hold ARC locks and thus risk a deadlock
	 * with ARC reclaim thread.
	 */
	if (curproc == pageproc) {
		arc_wait_for_eviction(to_free, B_FALSE);
		ARCSTAT_BUMP(arcstat_memory_indirect_count);
	} else {
		ARCSTAT_BUMP(arcstat_memory_direct_count);
	}
}

void
arc_lowmem_init(void)
{
	arc_event_lowmem = EVENTHANDLER_REGISTER(vm_lowmem, arc_lowmem, NULL,
	    EVENTHANDLER_PRI_FIRST);
}

void
arc_lowmem_fini(void)
{
	if (arc_event_lowmem != NULL)
		EVENTHANDLER_DEREGISTER(vm_lowmem, arc_event_lowmem);
}

void
arc_register_hotplug(void)
{
}

void
arc_unregister_hotplug(void)
{
}
