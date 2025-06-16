/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2006-2007 Ivan Voras <ivoras@freebsd.org>
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

/* Implementation notes:
 * - "Components" are wrappers around providers that make up the
 *   virtual storage (i.e. a logstor has "physical" components)
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sx.h>
#include <sys/bio.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/mutex.h>
#include <vm/uma.h>
#include <geom/geom.h>
#include <geom/geom_dbg.h>

#include <geom/logstor/g_logstor.h>

FEATURE(g_logstor, "GEOM log virtual storage support");

/* Declare malloc(9) label */
static MALLOC_DEFINE(M_GLOGSTOR, "glogstor", "GEOM_LOGSTOR Data");

#define DOING_COMMIT	0x00000001	/* a commit command is in progress */
#define DOING_COMMIT_BITNUM	 0	/* a commit command is in progress */
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

#if !defined(WYC)
/* GEOM class methods */
static g_init_t g_logstor_init;
static g_fini_t g_logstor_fini;
static g_taste_t g_logstor_taste;
static g_ctl_req_t g_logstor_config;
static g_ctl_destroy_geom_t g_logstor_destroy_geom;
#endif
/* Declare & initialize class structure ("geom class") */
struct g_class g_logstor_class = {
	.name =		G_LOGSTOR_CLASS_NAME,
	.version =	G_VERSION,
	.taste =	g_logstor_taste,
	.ctlreq =	g_logstor_config,
	.init =		g_logstor_init,	// empty
	.fini =		g_logstor_fini,	// empty
	.destroy_geom = g_logstor_destroy_geom
	/* The .dumpconf and the rest are only usable for a geom instance, so
	 * they will be set when such instance is created. */
#if 0 // init in g_logstor_taste()
	.start = g_logstor_start;
	.access = g_logstor_access;
	.orphan = g_logstor_orphan;
	.dumpconf = g_logstor_dumpconf;
	.spoiled = g_logstor_orphan;
#endif
};

/* Declare sysctl's and loader tunables */
SYSCTL_DECL(_kern_geom);
static SYSCTL_NODE(_kern_geom, OID_AUTO, logstor,
    CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "GEOM_GLOGSTOR information");

static u_int g_logstor_debug = 2; /* XXX: lower to 2 when released to public */
SYSCTL_UINT(_kern_geom_logstor, OID_AUTO, debug, CTLFLAG_RWTUN, &g_logstor_debug,
    0, "Debug level (2=production, 5=normal, 15=excessive)");

static u_int g_logstor_chunk_watermark = 100;
SYSCTL_UINT(_kern_geom_logstor, OID_AUTO, chunk_watermark, CTLFLAG_RWTUN,
    &g_logstor_chunk_watermark, 0,
    "Minimum number of free chunks before issuing administrative warning");

static u_int g_logstor_component_watermark = 1;
SYSCTL_UINT(_kern_geom_logstor, OID_AUTO, component_watermark, CTLFLAG_RWTUN,
    &g_logstor_component_watermark, 0,
    "Minimum number of free components before issuing administrative warning");

//=========================

static struct g_geom *g_logstor_find_geom(struct g_class *, const char *);

static void g_logstor_start(struct bio *);
static void g_logstor_orphan(struct g_consumer *);
static int g_logstor_access(struct g_provider *, int, int, int);
static void g_logstor_dumpconf(struct sbuf *, const char *, struct g_geom *,
    struct g_consumer *, struct g_provider *);

static void invalid_call(void);
static void g_logstor_done(struct bio *);

static void g_logstor_ctl_destroy(struct gctl_req *req, struct g_class *mp);
static void g_logstor_ctl_commit(struct gctl_req *, struct g_class *);
static void g_logstor_ctl_revert(struct gctl_req *, struct g_class *);
static int  g_logstor_destroy(struct gctl_req *req, struct g_geom *gp, bool force);

static uint32_t logstor_read(struct g_logstor_softc *sc, struct bio *bp);
static uint32_t logstor_write(struct g_logstor_softc *sc, struct bio *bp);
static uint32_t _logstor_write(struct g_logstor_softc *sc, struct bio *bp, uint32_t ba, void *data);
static int logstor_delete(struct g_logstor_softc *sc, struct bio *bp);

static void seg_alloc(struct g_logstor_softc *sc);
static void seg_sum_write(struct g_logstor_softc *sc);

static int  superblock_read(struct g_consumer *cp, struct logstor_superblock *sbp, uint32_t *sb_sa);
static void superblock_write(struct g_logstor_softc *sc);

static struct _fbuf *file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t offset, uint32_t *off_4byte);
static uint32_t file_read_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba);
static void file_write_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba, uint32_t sa);

static void fbuf_mod_init(struct g_logstor_softc *sc);
static void fbuf_queue_init(struct g_logstor_softc *sc, int which);
static void fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf);
static void fbuf_queue_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static struct _fbuf *fbuf_search(struct g_logstor_softc *sc, union meta_addr ma);
static void fbuf_hash_insert_head(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static void fbuf_bucket_init(struct g_logstor_softc *sc, int which);
static void fbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf);
static void fbuf_bucket_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static void fbuf_write(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static struct _fbuf *fbuf_alloc(struct g_logstor_softc *sc, union meta_addr ma, int depth);
static struct _fbuf *fbuf_access(struct g_logstor_softc *sc, union meta_addr ma);
static void fbuf_cache_flush(struct g_logstor_softc *sc);
static void fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2);
static void fbuf_clean_queue_check(struct g_logstor_softc *sc);

static union meta_addr ma2pma(union meta_addr ma, unsigned *pindex_out);
static uint32_t ma2sa(struct g_logstor_softc *sc, union meta_addr ma);

static void md_read (struct g_logstor_softc *sc, void *buf, uint32_t sa);
static void md_write(struct g_logstor_softc *sc, void *buf, uint32_t sa);
static void md_update(struct g_logstor_softc *sc);
static int _g_read_data(struct g_consumer *cp, off_t offset, void *ptr, off_t length);

static uint32_t ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba);
static uint32_t ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba);
static bool is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_valid(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);

//=========================

/*
 * Initialise GEOM class (per-class callback)
 */
static void
g_logstor_init(struct g_class *mp __unused)
{
	printf("%s called\n", __func__);
	/* Init UMA zones, TAILQ's, other global vars */
}

/*
 * Finalise GEOM class (per-class callback)
 */
static void
g_logstor_fini(struct g_class *mp __unused)
{
	printf("%s called\n", __func__);
	/* Deinit UMA zones & global vars */
}

/*
 * Config (per-class callback)
 */
__attribute__((optnone)) static void
g_logstor_config(struct gctl_req *req, struct g_class *mp, char const *verb)
{
	uint32_t *version;

	g_topology_assert();

	version = gctl_get_paraml(req, "version", sizeof(*version));
	if (version == NULL) {
		gctl_error(req, "Failed to get 'version' argument");
		return;
	}
	if (*version != G_LOGSTOR_VERSION) {
		gctl_error(req, "Userland and kernel versions out of sync");
		return;
	}

	g_topology_unlock();
	if (strcmp(verb, "destroy") == 0)
		g_logstor_ctl_destroy(req, mp);
	else if (strcmp(verb, "commit") == 0)
		g_logstor_ctl_commit(req, mp);
	else if (strcmp(verb, "revert") == 0)
		g_logstor_ctl_revert(req, mp);
	else
		gctl_error(req, "unknown verb: '%s'", verb);
	g_topology_lock();
}

/*
 * Clean up a logstor geom.
 */
static int
g_logstor_destroy_geom(struct gctl_req *req, struct g_class *mp,
    struct g_geom *gp)
{

	return (g_logstor_destroy(NULL, gp, false));
}

/*
 * Clean up a logstor device.
 */
static int
g_logstor_destroy(struct gctl_req *req, struct g_geom *gp, bool force)
{
	struct g_logstor_softc *sc;
	struct g_provider *pp;
	int error;

	g_topology_assert();
	sc = gp->softc;
	if (sc == NULL)
		return (ENXIO);
	pp = LIST_FIRST(&gp->provider);
	if ((sc->sc_flags & DOING_COMMIT) != 0 ||
	    (pp != NULL && (pp->acr != 0 || pp->acw != 0 || pp->ace != 0))) {
		if (force) {
			if (req != NULL)
				gctl_msg(req, 0, "Device %s is still in use, "
				    "so is being forcibly removed.", gp->name);
			//G_UNION_DEBUG(1, "Device %s is still in use, so "
			//    "is being forcibly removed.", gp->name);
		} else {
			if (req != NULL)
				gctl_msg(req, EBUSY, "Device %s is still open "
				    "(r=%d w=%d e=%d).", gp->name, pp->acr,
				    pp->acw, pp->ace);
			//G_UNION_DEBUG(1, "Device %s is still open "
			//    "(r=%d w=%d e=%d).", gp->name, pp->acr,
			//    pp->acw, pp->ace);
			return (EBUSY);
		}
	} else {
		if (req != NULL)
			gctl_msg(req, 0, "Device %s removed.", gp->name);
		//G_UNION_DEBUG(1, "Device %s removed.", gp->name);
	}
	/* Close consumers */
	if ((error = g_access(sc->consumer, -1, 0, -1)) != 0) {
		printf("%s(%d): error %d\n", __func__, __LINE__, error);
		//G_UNION_DEBUG(2, "Error %d: device %s could not reset access "
		//    "to %s.", error, gp->name, sc->sc_lowercp->provider->name);
	}
	free(sc, M_GLOGSTOR);
	g_wither_geom(gp, ENXIO);

	return (0);
}

/*
 * Called when the consumer gets orphaned (?)
 */
static void
g_logstor_orphan(struct g_consumer *cp)
{

	g_topology_assert();
	g_logstor_destroy(NULL, cp->geom, true);
}

/*
 * Generate XML dump of current state
 */
static void
g_logstor_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
}

/*
 * GEOM .done handler
 * Can't use standard handler (g_std_done) because one requested IO may
 * fork into additional data IOs
 */
static void
g_logstor_done(struct bio *bp)
{
	struct bio *bp2;

	KASSERT(bp->bio_completed == SECTOR_SIZE, ("%s", __func__));
	bp2 = bp->bio_parent;
	if (bp2->bio_error == 0)
		bp2->bio_error = bp->bio_error;
	bp2->bio_completed += bp->bio_completed;
	g_destroy_bio(bp);
	bp2->bio_inbed++;
	if (bp2->bio_completed == bp2->bio_length) {
		KASSERT(bp2->bio_children == bp2->bio_inbed, ("%s", __func__));
		g_io_deliver(bp2, bp2->bio_error);
	}
}

//=========================
/*
 * The function that shouldn't be called.
 * When this is called, the stack is already garbled because of
 * argument mismatch. There's nothing to do now but panic, which is
 * accidentally the whole purpose of this function.
 * Motivation: to guard from accidentally calling geom methods when
 * they shouldn't be called. (see g_..._taste)
 */
static void
invalid_call(void)
{
	panic("%s() has just been called. Something's fishy here.", __func__);
}

/*
 * Find a logstor geom.
 */
static struct g_geom *
g_logstor_find_geom(struct g_class *mp, const char *name)
{
	struct g_geom *gp;

	LIST_FOREACH(gp, &mp->geom, geom) {
		if (strcmp(gp->name, name) == 0)
			return (gp);
	}
	return (NULL);
}

// there are 3 kinds of metadata in the system, the fbuf cache, segment summary block and superblock
static void
md_update(struct g_logstor_softc *sc)
{
	fbuf_cache_flush(sc);
	seg_sum_write(sc);
	superblock_write(sc);
}

/*******************************
 *        logstor              *
 *******************************/
/*
 * The writelock is held while a commit operation is in progress.
 * While held logstor device may not be used or in use.
 * Returns == 0 if lock was successfully obtained.
 */
static inline int
g_logstor_get_writelock(struct g_logstor_softc *sc)
{

	return (atomic_testandset_long(&sc->sc_flags, DOING_COMMIT_BITNUM)); // set bit DOING_COMMIT_BITNUM
}

static inline void
g_logstor_rel_writelock(struct g_logstor_softc *sc)
{
	long ret __diagused; // is used only when KASSERT is defined

	ret = atomic_testandclear_long(&sc->sc_flags, DOING_COMMIT_BITNUM); // clear bit DOING_COMMIT_BITNUM
	KASSERT(ret != 0, ("LOGSTOR GEOM releasing unheld lock"));
}

/*
 * Generally allow access unless a commit is in progress.
 */
static int
g_logstor_access(struct g_provider *pp, int r, int w, int e)
{
	struct g_logstor_softc *sc;

	sc = pp->geom->softc;
	if (sc == NULL) {
		if (r <= 0 && w <= 0 && e <= 0)
			return (0);
		return (ENXIO);
	}
	r += pp->acr;
	w += pp->acw;
	e += pp->ace;
	if (g_logstor_get_writelock(sc) != 0) {
		if ((pp->acr + pp->acw + pp->ace) > 0 && (r + w + e) == 0)
			return (0);
		return (EBUSY);
	}
	g_logstor_rel_writelock(sc);
	return (0);
}

/*
 * I/O starts here
 * Called in g_down thread
 */
static void
g_logstor_start(struct bio *bp)
{
	struct g_logstor_softc *sc;
	struct g_provider *pp;
	uint32_t (*logstor_access_fp)(struct g_logstor_softc *sc, struct bio *bp);

	pp = bp->bio_to;
	sc = pp->geom->softc;
	KASSERT(sc != NULL, ("%s: no softc (error=%d, device=%s)", __func__,
	    bp->bio_to->error, bp->bio_to->name));

	LOG_REQ(LVL_MOREDEBUG, bp, "%s", __func__);

	switch (bp->bio_cmd) {
	case BIO_READ:
		logstor_access_fp = logstor_read;
		break;
	case BIO_WRITE:
		logstor_access_fp = logstor_write;
		break;
	case BIO_DELETE:
		logstor_delete(sc, bp);
		return;
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		return;
	}

	LOG_MSG(LVL_DEBUG2, "BIO arrived, size=%ju", bp->bio_length);

	KASSERT(bp->bio_offset % SECTOR_SIZE == 0, ("%s", __func__));
	KASSERT(bp->bio_length % SECTOR_SIZE == 0, ("%s", __func__));

	int sec_cnt = bp->bio_length / SECTOR_SIZE;
	for (int i = 0; i < sec_cnt; ++i) {
		struct bio *cb = g_clone_bio(bp);
		if (cb == NULL) {
			if (bp->bio_error == 0)
				bp->bio_error = ENOMEM;
			g_io_deliver(bp, bp->bio_error);
			return;
		}
		//cb->bio_to = sc->provider;
		cb->bio_done = g_logstor_done;
		cb->bio_offset = bp->bio_offset + i * SECTOR_SIZE;
		cb->bio_data = bp->bio_data + i * SECTOR_SIZE;
		cb->bio_length = SECTOR_SIZE;
		fbuf_clean_queue_check(sc);
		logstor_access_fp(sc, cb);
	}
}

/*
 * Taste event (per-class callback)
 * Examines a provider and creates geom instances if needed
 */
// from g_virstor_taste
__attribute__((optnone)) static struct g_geom *
g_logstor_taste(struct g_class *mp, struct g_provider *pp, int flags __unused)
{
	struct g_geom *gp;
	struct g_consumer *cp;
	struct g_logstor_softc *sc;
	struct logstor_superblock sb;
	uint32_t sb_sa;
	int error;

	g_trace(G_T_TOPOLOGY, "%s(%s, %s)", __func__, mp->name, pp->name);
	g_topology_assert();
	LOG_MSG(LVL_DEBUG, "Tasting %s", pp->name);

	/* We need a dummy geom to attach a consumer to the given provider */
	gp = g_new_geomf(mp, "logstor:taste.helper");
	gp->start = (void *)invalid_call;	/* XXX: hacked up so the        */
	gp->access = (void *)invalid_call;	/* compiler doesn't complain.   */
	gp->orphan = (void *)invalid_call;	/* I really want these to fail. */

	cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	error = g_attach(cp, pp);
	if (!error) {
		error = superblock_read(cp, &sb, &sb_sa);
		g_detach(cp);
	}
	g_destroy_consumer(cp);
	g_destroy_geom(gp);

	if (error) { // ENXIO 6
		printf("%s() #%d: error %d\n", __func__, __LINE__, error);
		return (NULL);
	}
	/* Iterate all geoms this class already knows about to see if a new
	 * geom instance of this class needs to be created (in case the provider
	 * is first from a (possibly) multi-consumer geom) or it just needs
	 * to be added to an existing instance. */
	sc = NULL;
	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc == NULL)
			continue;
		if (strcmp(sb.name, sc->geom->name) != 0)
			continue;
		//if (md.md_id != sc->id)
		//	continue;
		break;
	}
	if (gp != NULL) { /* We found an existing geom instance; add to it */
		printf("%s(%d): error %d\n", __func__, __LINE__, error);
		LOG_MSG(LVL_INFO, "%s already exists", sb.name);
		return (NULL);
	}
	/* New geom instance needs to be created */
	gp = g_new_geomf(mp, "%s", sb.name);
	gp->softc = NULL; /* to circumevent races that test softc */
	gp->start = g_logstor_start;
	gp->spoiled = g_logstor_orphan;
	gp->orphan = g_logstor_orphan;
	gp->access = g_logstor_access;
	gp->dumpconf = g_logstor_dumpconf;

	cp = g_new_consumer(gp);
	error = g_attach(cp, pp);
	if (error) {
		printf("%s(%d): error %d\n", __func__, __LINE__, error);
		LOG_MSG(LVL_ERROR, "Error creating new instance of "
		    "class %s: %s", mp->name, sb.name);
		LOG_MSG(LVL_DEBUG, "Error creating %s at %s",
		    sb.name, pp->name);

		g_destroy_consumer(cp);
		g_destroy_geom(gp);
		return (NULL);
	}
	sc = malloc(sizeof(*sc), M_GLOGSTOR, M_WAITOK | M_ZERO);;
	sc->geom = gp;
	sc->consumer = cp;

	memcpy(&sc->superblock, &sb, sizeof(sb));
	sc->sb_modified = false;
	sc->sb_sa = sb_sa;

	// read the segment summary block
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	uint32_t sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	md_read(sc, &sc->seg_sum, sa);
	KASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET, ("%s", __func__));
	sc->ss_modified = false;

	fbuf_mod_init(sc);

	sc->data_write_count = sc->other_write_count = 0;
	sc->is_sec_valid_fp = is_sec_valid_normal;
	sc->ba2sa_fp = ba2sa_normal;
	gp->softc = sc;

	struct g_provider *newpp;
	newpp = g_new_providerf(gp, "%s", gp->name);
	newpp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE;
	newpp->mediasize = sc->superblock.block_cnt_max * (off_t)SECTOR_SIZE;
	newpp->sectorsize = SECTOR_SIZE;
	g_error_provider(newpp, 0);

	LOG_MSG(LVL_INFO, "Adding %s to %s (first found)", pp->name,
	    sb.name);

	return (gp);
#if 0
	bzero(sc, sizeof(*sc));
	int error __unused;

	error = superblock_read(sc);
	KASSERT(error == 0, ("%s", __func__));
	sc->sb_modified = false;

	// read the segment summary block
	KASSERT(sc->superblock.seg_allocp >= SEG_DATA_START, ("%s", __func__));
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	uint32_t sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	md_read(sc, &sc->seg_sum, sa);
	KASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET, ("%s", __func__));
	sc->ss_modified = false;
	sc->data_write_count = sc->other_write_count = 0;

	fbuf_mod_init(sc);

	return 0;
#endif
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
__attribute__((optnone)) static int
superblock_read(struct g_consumer *cp, struct logstor_superblock *sbp, uint32_t *sb_sa)
{
	int error;
	int i;
	uint16_t sb_gen;
	struct logstor_superblock *sb;
	char buf[2][SECTOR_SIZE];

	_Static_assert(sizeof(sb_gen) == sizeof(sb->sb_gen), "sb_gen");

	// from virstor's read_metadata()
	g_topology_assert();
	error = g_access(cp, 1, 0, 0);
	if (error) { // ENXIO 6
		printf("%s() #%d: error %d\n", __func__, __LINE__, error);
		return (error);
	}
	g_topology_unlock();

	// get the superblock
	sb = (struct logstor_superblock *)buf[0];
	error = _g_read_data(cp, 0, sb, SECTOR_SIZE);
	if (error) {
		printf("%s() #%d: error %d\n", __func__, __LINE__, error);
		goto end;
	}
	if (sb->magic != G_LOGSTOR_MAGIC ||
	    sb->seg_allocp >= sb->seg_cnt) {
		printf("%s() #%d: not logstor\n", __func__, __LINE__);
		error = EINVAL;
		goto end;
	}
	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SECTORS_PER_SEG; i++) {
		sb = (struct logstor_superblock *)buf[i%2];
		error = _g_read_data(cp, i * SECTOR_SIZE, sb, SECTOR_SIZE);
		if (error) {
			goto end;
		}
		if (sb->magic != G_LOGSTOR_MAGIC)
			break;
		if (sb->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	if (i == SECTORS_PER_SEG) {
		printf("%s() #%d: error %d\n", __func__, __LINE__, error);
		error = EINVAL;
		goto end;
	}
	*sb_sa = (i - 1);
	sb = (struct logstor_superblock *)buf[(i-1)%2]; // get the previous valid superblock
	if (sb->seg_allocp >= sb->seg_cnt) {
		printf("%s() #%d: error %d\n", __func__, __LINE__, error);
		error = EINVAL;
		goto end;
	}
	if (sb->seg_allocp < SEG_DATA_START) {
		printf("%s() #%d: error %d\n", __func__, __LINE__, error);
		error = EINVAL;
		goto end;
	}
end:	// from virstor's read_metadata
	g_topology_lock();
	g_access(cp, -1, 0, 0);

	if (!error) {
		for (i = 0; i < FD_COUNT; ++i)
			KASSERT(sb->fd_root[i] != SECTOR_CACHE, ("%s", __func__));
		memcpy(sbp, sb, sizeof(*sb));
	}
	return error;
}

// read one block
// must call fbuf_clean_queue_check() before calling this function
uint32_t
logstor_read(struct g_logstor_softc *sc, struct bio *bp)
{
	uint32_t ba;	// block address
	uint32_t sa;	// sector address

	ba = bp->bio_offset / SECTOR_SIZE;
	KASSERT(ba < sc->superblock.block_cnt_max, ("%s", __func__));

	sa = sc->ba2sa_fp(sc, ba);
#if defined(WYC)
	ba2sa_normal();
	ba2sa_during_commit();
#endif
	if (sa == SECTOR_NULL) {
		bzero(bp->bio_data, SECTOR_SIZE);
		bp->bio_error = 0;
		bp->bio_completed = SECTOR_SIZE;
		g_logstor_done(bp);
#if defined(WYC)
		g_std_done(bp);
#endif
	} else {
		KASSERT(sa >= SECTORS_PER_SEG, ("%s", __func__));
		bp->bio_offset = sa * SECTOR_SIZE;
		g_io_request(bp, sc->consumer);
	}
	return sa;
}

// write one block
uint32_t
logstor_write(struct g_logstor_softc *sc, struct bio *bp)
{
	return _logstor_write(sc, bp, 0, NULL);
}

/*
Description:
  write data/metadata block to disk

Return:
  the sector address where the data is written
*/
// must call fbuf_clean_queue_check() before calling this function
static uint32_t
_logstor_write(struct g_logstor_softc *sc, struct bio *bp, uint32_t ba, void *data)
{
	static bool is_called = false;
	struct _seg_sum *seg_sum = &sc->seg_sum;

	KASSERT(sc->seg_allocp_sa >= SECTORS_PER_SEG, ("%s", __func__));
	if (bp) {
		ba = bp->bio_offset / SECTOR_SIZE;
		data = bp->bio_data;
		KASSERT(ba < sc->superblock.block_cnt_max, ("%s", __func__));
	} else {
		KASSERT(IS_META_ADDR(ba), ("%s", __func__));
		KASSERT(data != NULL, ("%s", __func__));
	}
	if (is_called) // recursive call is not allowed
		panic("%s", __func__);

	is_called = true;
	// record the starting segment
	// if the search for free sector rolls over to the starting segment
	// it means that there is no free sector in this disk
	sc->seg_allocp_start = sc->superblock.seg_allocp;
again:
	for (int i = seg_sum->ss_allocp; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t sa = sc->seg_allocp_sa + i;
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map

		if (is_sec_valid(sc, sa, ba_rev))
			continue;

		if (bp) {
			bp->bio_offset = sa * SECTOR_SIZE;
			g_io_request(bp, sc->consumer);
		} else { // metadata
			md_write(sc, data, sa);
		}
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		sc->ss_modified = true;
		seg_sum->ss_allocp = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_allocp == SEG_SUM_OFFSET)
			seg_alloc(sc);

		if (bp) {
			++sc->data_write_count;
			// record the forward mapping for the %ba
			// the forward mapping must be recorded after
			// the segment summary block write
			file_write_4byte(sc, sc->superblock.fd_cur, ba, sa);
		} else { // metadata
			++sc->other_write_count;
		}
		is_called = false;
		return sa;
	}
	seg_alloc(sc);
	goto again;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
static int
logstor_delete(struct g_logstor_softc *sc, struct bio *bp)
{
	uint32_t ba;	// block address
	int count;	// number of remaining sectors to process

	off_t offset = bp->bio_offset;
	off_t length = bp->bio_length;
	KASSERT((offset & (SECTOR_SIZE - 1)) == 0, ("%s", __func__));
	KASSERT((length & (SECTOR_SIZE - 1)) == 0, ("%s", __func__));
	ba = offset / SECTOR_SIZE;
	count = length / SECTOR_SIZE;
	KASSERT(ba + count <= sc->superblock.block_cnt_max, ("%s", __func__));

	for (int i = 0; i < count; ++i) {
		fbuf_clean_queue_check(sc);
		file_write_4byte(sc, sc->superblock.fd_cur, ba + i, SECTOR_DEL);
	}

	return (0);
}

static void
g_logstor_ctl_commit(struct gctl_req *req, struct g_class *mp)
{
	int *nargs;
	const char *geom_name;	/* geom to add a component to */

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Invalid number of arguments");
		return;
	}

	/* Find "our" geom */
	geom_name = gctl_get_asciiparam(req, "arg0");
	if (geom_name == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "geom_name (arg0)");
		return;
	}
	struct g_geom *gp = g_logstor_find_geom(mp, geom_name);
	if (gp == NULL) {
		gctl_error(req, "Don't know anything about '%s'", geom_name);
		return;
	}
	struct g_logstor_softc *sc = gp->softc;
	// lock metadata
	// move fd_cur to fd_prev
	sc->superblock.fd_prev = sc->superblock.fd_cur;
	// create new files fd_cur and fd_snap_new
	// fc_cur is either 0 or 2 and fd_snap always follows fd_cur
	sc->superblock.fd_cur = sc->superblock.fd_cur ^ 2;
	sc->superblock.fd_snap_new = sc->superblock.fd_cur + 1;
	sc->superblock.fd_root[sc->superblock.fd_cur] = SECTOR_NULL;
	sc->superblock.fd_root[sc->superblock.fd_snap_new] = SECTOR_NULL;

	sc->is_sec_valid_fp = is_sec_valid_during_commit;
	sc->ba2sa_fp = ba2sa_during_commit;
	// unlock metadata

	uint32_t block_max = sc->superblock.block_cnt_max;
	for (int ba = 0; ba < block_max; ++ba) {
		uint32_t sa;

		fbuf_clean_queue_check(sc);
		sa = file_read_4byte(sc, sc->superblock.fd_prev, ba);
		if (sa == SECTOR_NULL)
			sa = file_read_4byte(sc, sc->superblock.fd_snap, ba);
		else if (sa == SECTOR_DEL)
			sa = SECTOR_NULL;

		if (sa != SECTOR_NULL)
			file_write_4byte(sc, sc->superblock.fd_snap_new, ba, sa);
	}

	// lock metadata
	int fd_prev = sc->superblock.fd_prev;
	int fd_snap = sc->superblock.fd_snap;
	fbuf_cache_flush_and_invalidate_fd(sc, fd_prev, fd_snap);
	sc->superblock.fd_root[fd_prev] = SECTOR_DEL;
	sc->superblock.fd_root[fd_snap] = SECTOR_DEL;
	// move fd_snap_new to fd_snap
	sc->superblock.fd_snap = sc->superblock.fd_snap_new;
	// delete fd_prev and fd_snap
	sc->superblock.fd_prev = FD_INVALID;
	sc->superblock.fd_snap_new = FD_INVALID;
	sc->sb_modified = true;

	seg_sum_write(sc);
	superblock_write(sc);

	sc->is_sec_valid_fp = is_sec_valid_normal;
	sc->ba2sa_fp = ba2sa_normal;
	//unlock metadata
}

static void
g_logstor_ctl_revert(struct gctl_req *req, struct g_class *mp)
{
	int *nargs;
	const char *geom_name;	/* geom to add a component to */

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "nargs");
		return;
	}
	if (*nargs != 1) {
		gctl_error(req, "Invalid number of arguments");
		return;
	}

	/* Find "our" geom */
	geom_name = gctl_get_asciiparam(req, "arg0");
	if (geom_name == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "geom_name (arg0)");
		return;
	}
	struct g_geom *gp = g_logstor_find_geom(mp, geom_name);
	if (gp == NULL) {
		gctl_error(req, "Don't know anything about '%s'", geom_name);
		return;
	}
	struct g_logstor_softc *sc = gp->softc;
	fbuf_cache_flush_and_invalidate_fd(sc, sc->superblock.fd_cur, FD_INVALID);
	sc->superblock.fd_root[sc->superblock.fd_cur] = SECTOR_NULL;
	sc->sb_modified = true;
}

/*
 * Destroy a logstor device.
 */
static void
g_logstor_ctl_destroy(struct gctl_req *req, struct g_class *mp)
{
	int *nargs, *force, error, i;
	struct g_geom *gp;
	const char *name;
	char param[16];

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs <= 0) {
		gctl_error(req, "Missing device(s).");
		return;
	}
	force = gctl_get_paraml(req, "force", sizeof(*force));
	if (force == NULL) {
		gctl_error(req, "No 'force' argument.");
		return;
	}

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		name = gctl_get_asciiparam(req, param);
		if (name == NULL) {
			gctl_msg(req, EINVAL, "No '%s' argument.", param);
			continue;
		}
		if (strncmp(name, _PATH_DEV, strlen(_PATH_DEV)) == 0)
			name += strlen(_PATH_DEV);
		gp = g_logstor_find_geom(mp, name);
		if (gp == NULL) {
			gctl_msg(req, EINVAL, "Device %s is invalid.", name);
			continue;
		}
		struct g_logstor_softc *sc = gp->softc;
		md_update(sc);
		free(sc->fbufs, M_GLOGSTOR);

		error = g_logstor_destroy(req, gp, *force);
		if (error != 0)
			gctl_msg(req, error, "Error %d: "
			    "cannot destroy device %s.", error, gp->name);
	}
	gctl_post_messages(req);
}

// The common part of is_sec_valid
static bool
is_sec_valid_comm(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev, uint8_t fd[], int fd_cnt)
{
	uint32_t sa_rev; // the sector address for ba_rev

	KASSERT(ba_rev < BLOCK_MAX, ("%s", __func__));
	for (int i = 0; i < fd_cnt; ++i) {
		sa_rev = file_read_4byte(sc, fd[i], ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}

// Is a sector with a reverse ba valid?
// This function is called normally
static bool
is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return is_sec_valid_comm(sc, sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
// This function is called during commit
static bool
is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return is_sec_valid_comm(sc, sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
static bool
is_sec_valid(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	if (ba_rev < BLOCK_MAX) {
		return sc->is_sec_valid_fp(sc, sa, ba_rev);
#if defined(WYC)
		is_sec_valid_normal();
		is_sec_valid_during_commit();
#endif
	} else if (IS_META_ADDR(ba_rev)) {
		uint32_t sa_rev = ma2sa(sc, (union meta_addr)ba_rev);
		return (sa == sa_rev);
	} else if (ba_rev == BLOCK_INVALID) {
		return false;
	} else {
		panic("");
		return false;
	}
}

static uint32_t
ba2sa_comm(struct g_logstor_softc *sc, uint32_t ba, uint8_t fd[], int fd_cnt)
{
	uint32_t sa;

	KASSERT(ba < BLOCK_MAX, ("%s", __func__));
	for (int i = 0; i < fd_cnt; ++i) {
		sa = file_read_4byte(sc, fd[i], ba);
		if (sa == SECTOR_DEL) { // don't need to check further
			sa = SECTOR_NULL;
			break;
		}
		if (sa != SECTOR_NULL)
			break;
	}
	return sa;
}

/*
Description:
    Block address to sector address translation in normal state
*/
static uint32_t
ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

/*
Description:
    Block address to sector address translation in commit state
*/
static uint32_t __unused
ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

/*
  write out the segment summary
*/
static void
seg_sum_write(struct g_logstor_softc *sc)
{
	uint32_t sa;

	if (!sc->ss_modified)
		return;
	// segment summary is at the end of a segment
	KASSERT(sc->seg_allocp_sa >= SECTORS_PER_SEG, ("%s", __func__));
	sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	md_write(sc, (void *)&sc->seg_sum, sa);
	sc->ss_modified = false;
	sc->other_write_count++; // the write for the segment summary
}

static void
superblock_write(struct g_logstor_softc *sc)
{
	size_t sb_size = sizeof(sc->superblock);
	char buf[SECTOR_SIZE];

	//if (!sc->sb_modified)
	//	return;

	for (int i = 0; i < 4; ++i) {
		KASSERT(sc->superblock.fd_root[i] != SECTOR_CACHE, ("%s", __func__));
	}
	sc->superblock.sb_gen++;
	if (++sc->sb_sa == SECTORS_PER_SEG)
		sc->sb_sa = 0;
	memcpy(buf, &sc->superblock, sb_size);
	memset(buf + sb_size, 0, SECTOR_SIZE - sb_size);
	md_write(sc, buf, sc->sb_sa);
	sc->sb_modified = false;
	sc->other_write_count++;
}

__attribute__((optnone)) static int
_g_read_data(struct g_consumer *cp, off_t offset, void *ptr, off_t length)
{
	struct bio *bp;
	int errorc;

	KASSERT(length > 0 && length >= cp->provider->sectorsize &&
	    length <= maxphys, ("%s(): invalid length %jd", __func__,
	    (intmax_t)length));

	bp = g_alloc_bio();
	bp->bio_cmd = BIO_READ;
	bp->bio_done = NULL;
	bp->bio_offset = offset;
	bp->bio_data = ptr;
	bp->bio_length = length;
	g_io_request(bp, cp);
	errorc = biowait(bp, "gread");
	if (errorc == 0 && bp->bio_completed != length)
		errorc = EIO;
	g_destroy_bio(bp);

	return (errorc);
}

static void
md_read(struct g_logstor_softc *sc, void *buf, uint32_t sa)
{
	int rc __diagused;

	KASSERT(sa < sc->superblock.seg_cnt * SECTORS_PER_SEG, ("%s", __func__));
	rc = _g_read_data(sc->consumer, sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	KASSERT(rc == 0, ("%s", __func__));
}

static void
md_write(struct g_logstor_softc *sc, void *buf, uint32_t sa)
{
	int rc __diagused;

	KASSERT(sa < sc->superblock.seg_cnt * SECTORS_PER_SEG, ("%s", __func__));
	rc = g_write_data(sc->consumer, sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	KASSERT(rc == 0, ("%s", __func__));
}

/*
Description:
  Allocate a segment for writing

Output:
  Store the segment address into @seg_sum->sega
  Initialize @seg_sum->sum.alloc_p to 0
*/
static void
seg_alloc(struct g_logstor_softc *sc)
{
	// write the previous segment summary to disk if it has been modified
	seg_sum_write(sc);

	KASSERT(sc->superblock.seg_allocp < sc->superblock.seg_cnt, ("%s", __func__));
	if (++sc->superblock.seg_allocp == sc->superblock.seg_cnt)
		sc->superblock.seg_allocp = SEG_DATA_START;
	if (sc->superblock.seg_allocp == sc->seg_allocp_start)
		// has accessed all the segment summary blocks
		panic("");
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	md_read(sc, &sc->seg_sum, sc->seg_allocp_sa + SEG_SUM_OFFSET);
	sc->seg_sum.ss_allocp = 0;
}

/*********************************************************
 * The file buffer and indirect block cache              *
 *   Cache the the block to sector address translation   *
 *********************************************************/

/*
Description:
	Get the sector address of the corresponding @ba in @file

Parameters:
	@fd: file descriptor
	@ba: block address

Return:
	The sector address of the @ba
*/
static uint32_t
file_read_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba)
{
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data
	uint32_t sa;
	struct _fbuf *fbuf;

	KASSERT(fd < FD_COUNT, ("%s", __func__));

	// the initialized reverse map in the segment summary is BLOCK_MAX
	// so it is possible that a caller might pass a ba that is BLOCK_MAX
	if (ba >= BLOCK_MAX) {
		KASSERT(ba == BLOCK_INVALID, ("%s", __func__));
		return SECTOR_NULL;
	}
	// this file is all 0
	if (sc->superblock.fd_root[fd] == SECTOR_NULL ||
	    sc->superblock.fd_root[fd] == SECTOR_DEL)
		return SECTOR_NULL;

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
	if (fbuf)
		sa = fbuf->data[off_4byte];
	else
		sa = SECTOR_NULL;
	return sa;
}

/*
Description:
	Set the mapping of @ba to @sa in @file

Parameters:
	%fd: file descriptor
	%ba: block address
	%sa: sector address
*/
static void
file_write_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t sa)
{
	struct _fbuf *fbuf;
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data

	KASSERT(fd < FD_COUNT, ("%s", __func__));
	KASSERT(ba < BLOCK_MAX, ("%s", __func__));
	KASSERT(sc->superblock.fd_root[fd] != SECTOR_DEL, ("%s", __func__));

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
	KASSERT(fbuf != NULL, ("%s", __func__));
	fbuf->data[off_4byte] = sa;
	if (!fbuf->fc.modified) {
		// move to QUEUE_LEAF_DIRTY
		KASSERT(fbuf->queue_which == QUEUE_LEAF_CLEAN, ("%s", __func__));
		fbuf->fc.modified = true;
		if (fbuf == sc->fbuf_allocp)
			sc->fbuf_allocp = fbuf->fc.queue_next;
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, QUEUE_LEAF_DIRTY, fbuf);
	} else
		KASSERT(fbuf->queue_which == QUEUE_LEAF_DIRTY, ("%s", __func__));
}

/*
Description:
    The metadata is cached in memory. This function returns the address
    of the metadata in memory for the forward mapping of the block @ba

Parameters:
	%fd: file descriptor
	%ba: block address
	%off_4byte: the offset (in unit of 4 bytes) within the file buffer data

Return:
	the address of the file buffer data
*/
static struct _fbuf *
file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t *off_4byte)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *fbuf;

	// the sector address stored in file for this ba is 4 bytes
	*off_4byte = ((ba * 4) & (SECTOR_SIZE - 1)) / 4;

	// convert (%fd, %ba) to metadata address
	ma.index = (ba * 4) / SECTOR_SIZE;
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	ma.meta = 0xFF;	// for metadata address, bits 31:24 are all 1s
	fbuf = fbuf_access(sc, ma);
	return fbuf;
}

static inline unsigned
ma_index_get(union meta_addr ma, unsigned depth)
{
	switch (depth) {
	case 0:
		return ma.index0;
	case 1:
		return ma.index1;
	default:
		panic("");
		return 0;
	}
}

static union meta_addr
ma_index_set(union meta_addr ma, unsigned depth, unsigned index)
{
	KASSERT(index < 1024, ("%s", __func__));

	switch (depth) {
	case 0:
		ma.index0 = index;
		break;
	case 1:
		ma.index1 = index;
		break;
	default:
		panic("");
	}
	return ma;
}

/*
  to parent's metadata address

output:
  pindex_out: the index in parent's metadata

return:
  parent's metadata address
*/
static union meta_addr
ma2pma(union meta_addr ma, unsigned *pindex_out)
{
	switch (ma.depth)
	{
	case 1:
		*pindex_out = ma.index0;
		ma.index = 0;
		ma.depth = 0; // i.e. ma.depth - 1
		break;
	case 2:
		*pindex_out = ma.index1;
		ma.index1 = 0;
		ma.depth = 1; // i.e. ma.depth - 1
		break;
	default:
		panic("");
		break;
	}
	return ma;
}

// get the sector address where the metadata is stored on disk
static uint32_t
ma2sa(struct g_logstor_softc *sc, union meta_addr ma)
{
	uint32_t sa;

	switch (ma.depth)
	{
	case 0:
		sa = sc->superblock.fd_root[ma.fd];
		break;
	case 1:
	case 2:
		if (sc->superblock.fd_root[ma.fd] == SECTOR_NULL ||
		    sc->superblock.fd_root[ma.fd] == SECTOR_DEL)
			sa = SECTOR_NULL;
		else {
			struct _fbuf *parent;	// parent buffer
			union meta_addr pma;	// parent's metadata address
			unsigned pindex;	// index in the parent indirect block

			pma = ma2pma(ma, &pindex);
			parent = fbuf_access(sc, pma);
			KASSERT(parent != NULL, ("%s", __func__));
			sa = parent->data[pindex];
		}
		break;
	case 3: // it is an invalid metadata address
		sa = SECTOR_NULL;
		break;
	}
	return sa;
}

/*
  Initialize metadata file buffer
*/
static void
fbuf_mod_init(struct g_logstor_softc *sc)
{
	int fbuf_count;
	int i;

	//fbuf_count = sc->superblock.block_cnt_max / (SECTOR_SIZE / 4);
	fbuf_count = FBUF_MIN;
	if (fbuf_count < FBUF_MIN)
		fbuf_count = FBUF_MIN;
	if (fbuf_count > FBUF_MAX)
		fbuf_count = FBUF_MAX;
	sc->fbuf_count = fbuf_count;
	sc->fbufs = malloc(fbuf_count * sizeof(*sc->fbufs), M_GLOGSTOR, M_WAITOK);
	KASSERT(sc->fbufs != NULL, ("%s", __func__));

	for (i = 0; i < FBUF_BUCKET_CNT; ++i) {
		fbuf_bucket_init(sc, i);
	}
	for (i = 0; i < QUEUE_CNT; ++i) {
		fbuf_queue_init(sc, i);
	}
	// insert fbuf to both QUEUE_LEAF_CLEAN and the last hash bucket
	for (i = 0; i < fbuf_count; ++i) {
		struct _fbuf *fbuf = &sc->fbufs[i];
		fbuf->fc.is_sentinel = false;
		fbuf->fc.accessed = false;
		fbuf->fc.modified = false;
		fbuf_queue_insert_tail(sc, QUEUE_LEAF_CLEAN, fbuf);
		// insert fbuf to the last hash bucket
		// this bucket is not used in hash search
		// init parent, child_cnt and ma before inserting into FBUF_BUCKET_LAST
		fbuf->parent = NULL;
		fbuf->child_cnt = 0;
		fbuf->ma.uint32 = META_INVALID;
		fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
	}
	sc->fbuf_allocp = &sc->fbufs[0];;
	sc->fbuf_hit = sc->fbuf_miss = 0;
}

static inline bool
is_queue_empty(struct _fbuf_sentinel *sentinel)
{
	if (sentinel->fc.queue_next == (struct _fbuf *)sentinel) {
		KASSERT(sentinel->fc.queue_prev == (struct _fbuf *)sentinel, ("%s", __func__));
		return true;
	}
	return false;
}

static void
fbuf_clean_queue_check(struct g_logstor_softc *sc)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;

	if (sc->fbuf_queue_len[QUEUE_LEAF_CLEAN] > FBUF_CLEAN_THRESHOLD)
		return;

	md_update(sc);

	// move all parent nodes with child_cnt 0 to clean queue and last bucket
	for (int i = QUEUE_IND1; i >= QUEUE_IND0; --i) {
		queue_sentinel = &sc->fbuf_queue[i];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			KASSERT(fbuf->queue_which == i, ("%s", __func__));
			struct _fbuf *fbuf_next = fbuf->fc.queue_next;
			if (fbuf->child_cnt == 0) {
				fbuf_queue_remove(sc, fbuf);
				fbuf->fc.accessed = false; // so that it can be replaced faster
				fbuf_queue_insert_tail(sc, QUEUE_LEAF_CLEAN, fbuf);
				if (fbuf->parent) {
					KASSERT(i == QUEUE_IND1, ("%s", __func__));
					struct _fbuf *parent = fbuf->parent;
					--parent->child_cnt;
					KASSERT(parent->child_cnt <= SECTOR_SIZE/4, ("%s", __func__));
					fbuf->parent = NULL;
				}
				// move it to the last bucket so that it cannot be searched
				// fbufs on the last bucket will have the metadata address META_INVALID
				fbuf_bucket_remove(sc, fbuf);
				KASSERT(fbuf->parent == NULL, ("%s", __func__));
				KASSERT(fbuf->child_cnt == 0, ("%s", __func__));
				fbuf->ma.uint32 = META_INVALID;
				fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			}
			fbuf = fbuf_next;
		}
	}
}

// write back all the dirty fbufs to disk
static void
fbuf_cache_flush(struct g_logstor_softc *sc)
{
	int	i;
	struct _fbuf *fbuf;
	struct _fbuf *clean_next, *dirty_next, *dirty_prev;
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf_sentinel *dirty_sentinel;
	struct _fbuf_sentinel *clean_sentinel;

	// write back all the dirty leaf nodes to disk
	queue_sentinel = &sc->fbuf_queue[QUEUE_LEAF_DIRTY];
	fbuf = queue_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)queue_sentinel) {
		KASSERT(fbuf->queue_which == QUEUE_LEAF_DIRTY, ("%s", __func__));
		KASSERT(IS_META_ADDR(fbuf->ma.uint32), ("%s", __func__));
		KASSERT(fbuf->fc.modified, ("%s", __func__));
		// for dirty leaf nodes it's always dirty
		fbuf_write(sc, fbuf);
		fbuf = fbuf->fc.queue_next;
	}

	// write back all the modified internal nodes to disk
	for (i = QUEUE_IND1; i >= 0; --i) {
		queue_sentinel = &sc->fbuf_queue[i];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			KASSERT(fbuf->queue_which == i, ("%s", __func__));
			KASSERT(IS_META_ADDR(fbuf->ma.uint32), ("%s", __func__));
			// for non-leaf nodes the fbuf might not be modified
			if (__predict_true(fbuf->fc.modified))
				fbuf_write(sc, fbuf);
			fbuf = fbuf->fc.queue_next;
		}
	}

	dirty_sentinel = &sc->fbuf_queue[QUEUE_LEAF_DIRTY];
	if (is_queue_empty(dirty_sentinel))
		return;

	dirty_next = dirty_sentinel->fc.queue_next;
	dirty_prev = dirty_sentinel->fc.queue_prev;

	// set queue_which to QUEUE_LEAF_CLEAN for all fbufs on QUEUE_LEAF_DIRTY
	fbuf = dirty_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)dirty_sentinel) {
		fbuf->queue_which = QUEUE_LEAF_CLEAN;
		fbuf = fbuf->fc.queue_next;
	}

	// move all fbufs in QUEUE_LEAF_DIRTY to QUEUE_LEAF_CLEAN
	clean_sentinel = &sc->fbuf_queue[QUEUE_LEAF_CLEAN];
	clean_next = clean_sentinel->fc.queue_next;
	clean_sentinel->fc.queue_next = dirty_next;
	dirty_next->fc.queue_prev = (struct _fbuf *)clean_sentinel;
	dirty_prev->fc.queue_next = clean_next;
	clean_next->fc.queue_prev = dirty_prev;
	sc->fbuf_queue_len[QUEUE_LEAF_CLEAN] += sc->fbuf_queue_len[QUEUE_LEAF_DIRTY];

	fbuf_queue_init(sc, QUEUE_LEAF_DIRTY);
	// don't need to change clean queue's head
}

// flush the cache and invalid fbufs with file descriptors fd1 or fd2
static void
fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2)
{
	struct _fbuf *fbuf;

	md_update(sc);

	// invalidate fbufs with file descriptors fd1 or fd2
	for (int i = 0; i < sc->fbuf_count; ++i)
	{
		fbuf = &sc->fbufs[i];
		KASSERT(!fbuf->fc.modified, ("%s", __func__));
		if (fbuf->ma.uint32 == META_INVALID) {
			// the fbufs with metadata address META_INVALID are
			// linked in bucket FBUF_BUCKET_LAST
			KASSERT(fbuf->bucket_which == FBUF_BUCKET_LAST, ("%s", __func__));
			continue;
		}
		// move fbufs with fd equals to fd1 or fd2 to the last bucket
		if (fbuf->ma.fd == fd1 || fbuf->ma.fd == fd2) {
			KASSERT(fbuf->bucket_which != FBUF_BUCKET_LAST, ("%s", __func__));
			fbuf_bucket_remove(sc, fbuf);
			// init parent, child_cnt and ma before inserting to bucket FBUF_BUCKET_LAST
			fbuf->parent = NULL;
			fbuf->child_cnt = 0;
			fbuf->ma.uint32 = META_INVALID;
			fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			fbuf->fc.accessed = false; // so it will be recycled sooner
			if (fbuf->queue_which != QUEUE_LEAF_CLEAN) {
				// it is an internal node, move it to QUEUE_LEAF_CLEAN
				KASSERT(fbuf->queue_which != QUEUE_LEAF_DIRTY, ("%s", __func__));
				fbuf_queue_remove(sc, fbuf);
				fbuf_queue_insert_tail(sc, QUEUE_LEAF_CLEAN, fbuf);
			}
		}
	}
}

static void
fbuf_queue_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf_sentinel *queue_head;

	KASSERT(which < QUEUE_CNT, ("%s", __func__));
	sc->fbuf_queue_len[which] = 0;
	queue_head = &sc->fbuf_queue[which];
	queue_head->fc.queue_next = (struct _fbuf *)queue_head;
	queue_head->fc.queue_prev = (struct _fbuf *)queue_head;
	queue_head->fc.is_sentinel = true;
	queue_head->fc.accessed = true;
	queue_head->fc.modified = false;
}

static void
fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *queue_head;
	struct _fbuf *prev;

	KASSERT(which < QUEUE_CNT, ("%s", __func__));
	KASSERT(which != QUEUE_LEAF_CLEAN || !fbuf->fc.modified, ("%s", __func__));
	fbuf->queue_which = which;
	queue_head = &sc->fbuf_queue[which];
	prev = queue_head->fc.queue_prev;
	KASSERT(prev->fc.is_sentinel || prev->queue_which == which, ("%s", __func__));
	queue_head->fc.queue_prev = fbuf;
	fbuf->fc.queue_next = (struct _fbuf *)queue_head;
	fbuf->fc.queue_prev = prev;
	prev->fc.queue_next = fbuf;
	++sc->fbuf_queue_len[which];
}

static void
fbuf_queue_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;
	int which = fbuf->queue_which;

	KASSERT(fbuf != (struct _fbuf *)&sc->fbuf_queue[which], ("%s", __func__));
	prev = fbuf->fc.queue_prev;
	next = fbuf->fc.queue_next;
	KASSERT(prev->fc.is_sentinel || prev->queue_which == which, ("%s", __func__));
	KASSERT(next->fc.is_sentinel || next->queue_which == which, ("%s", __func__));
	prev->fc.queue_next = next;
	next->fc.queue_prev = prev;
	--sc->fbuf_queue_len[which];
}

// insert to the head of the hashed bucket
static void
fbuf_hash_insert_head(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	unsigned hash;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = fbuf->ma.uint32 % FBUF_BUCKET_LAST;
	fbuf_bucket_insert_head(sc, hash, fbuf);
}

static void
fbuf_bucket_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf_sentinel *bucket_head;

	bucket_head = &sc->fbuf_bucket[which];
	bucket_head->fc.queue_next = (struct _fbuf *)bucket_head;
	bucket_head->fc.queue_prev = (struct _fbuf *)bucket_head;
	bucket_head->fc.is_sentinel = true;
}

static void
fbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *bucket_head;
	struct _fbuf *next;

	bucket_head = &sc->fbuf_bucket[which];
	next = bucket_head->fc.queue_next;
	bucket_head->fc.queue_next = fbuf;
	fbuf->bucket_next = next;
	fbuf->bucket_prev = (struct _fbuf *)bucket_head;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = fbuf;
	else
		next->bucket_prev = fbuf;
}

static void
fbuf_bucket_remove(struct g_logstor_softc *sc __unused, struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;

	KASSERT(!fbuf->fc.is_sentinel, ("%s", __func__));
	prev = fbuf->bucket_prev;
	next = fbuf->bucket_next;
	if (prev->fc.is_sentinel)
		prev->fc.queue_next = next;
	else
		prev->bucket_next = next;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = prev;
	else
		next->bucket_prev = prev;
}

/*
Description:
    Search the file buffer with the tag value of @ma. Return NULL if not found
*/
static struct _fbuf *
fbuf_search(struct g_logstor_softc *sc, union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf	*fbuf;
	struct _fbuf_sentinel	*bucket_sentinel;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = ma.uint32 % FBUF_BUCKET_LAST;
	bucket_sentinel = &sc->fbuf_bucket[hash];
	fbuf = bucket_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)bucket_sentinel) {
		if (fbuf->ma.uint32 == ma.uint32) { // cache hit
			++sc->fbuf_hit;
			return fbuf;
		}
		fbuf = fbuf->bucket_next;
	}
	++sc->fbuf_miss;
	return NULL;	// cache miss
}

/*
Description:
  using the second chance replace policy to choose a fbuf in QUEUE_LEAF_CLEAN
*/
struct _fbuf *
fbuf_alloc(struct g_logstor_softc *sc, union meta_addr ma, int depth)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf, *parent;

	queue_sentinel = &sc->fbuf_queue[QUEUE_LEAF_CLEAN];
	fbuf = sc->fbuf_allocp;
again:
	while (true) {
		if (!fbuf->fc.accessed)
			break;

		fbuf->fc.accessed = false;	// give this fbuf a second chance
		fbuf = fbuf->fc.queue_next;
	}
	if (fbuf == (struct _fbuf *)queue_sentinel) {
		fbuf->fc.accessed = true;
		fbuf = fbuf->fc.queue_next;
		KASSERT(fbuf != (struct _fbuf *)queue_sentinel, ("%s", __func__));
		goto again;
	}

	KASSERT(!fbuf->fc.modified, ("%s", __func__));
	KASSERT(fbuf->child_cnt == 0, ("%s", __func__));
	sc->fbuf_allocp = fbuf->fc.queue_next;
	if (depth != META_LEAF_DEPTH) {
		// for fbuf allocated for internal nodes insert it immediately
		// to its internal queue
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, depth, fbuf);
	}
	fbuf_bucket_remove(sc, fbuf);
	fbuf->ma = ma;
	fbuf_hash_insert_head(sc, fbuf);
	parent = fbuf->parent;
	if (parent) {
		// parent with child_cnt == 0 will stay in its queue
		// it will only be moved to QUEUE_LEAF_CLEAN in fbuf_clean_queue_check()
		--parent->child_cnt;
		KASSERT(parent->child_cnt <= SECTOR_SIZE/4, ("%s", __func__));
		KASSERT(parent->queue_which == parent->ma.depth, ("%s", __func__));
	}
	return fbuf;
}

/*
Description:
    Read or write the file buffer with metadata address @ma
*/
static struct _fbuf *
fbuf_access(struct g_logstor_softc *sc, union meta_addr ma)
{
	uint32_t sa;	// sector address where the metadata is stored
	unsigned index;
	union meta_addr	ima;	// the intermediate metadata address
	struct _fbuf *parent;	// parent buffer
	struct _fbuf *fbuf;

	KASSERT(IS_META_ADDR(ma.uint32), ("%s", __func__));
	KASSERT(ma.depth <= META_LEAF_DEPTH, ("%s", __func__));

	// get the root sector address of the file %ma.fd
	sa = sc->superblock.fd_root[ma.fd];
	KASSERT(sa != SECTOR_DEL, ("%s", __func__));

	fbuf = fbuf_search(sc, ma);
	if (fbuf != NULL) // cache hit
		goto end;

	// cache miss
	parent = NULL;	// parent for root is NULL
	ima = (union meta_addr){.meta = 0xFF};	// set .meta to 0xFF and all others to 0
	ima.fd = ma.fd;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		ima.depth = i;
		fbuf = fbuf_search(sc, ima);
		if (fbuf == NULL) {
			fbuf = fbuf_alloc(sc, ima, i);	// allocate a fbuf from clean queue
			fbuf->parent = parent;
			if (parent) {
				// parent with child_cnt == 0 will stay in its queue
				// it will only be moved to QUEUE_LEAF_CLEAN in fbuf_clean_queue_check()
				++parent->child_cnt;
				KASSERT(parent->child_cnt <= SECTOR_SIZE/4, ("%s", __func__));
			} else {
				KASSERT(i == 0, ("%s", __func__));
			}
			if (sa == SECTOR_NULL) {
				bzero(fbuf->data, sizeof(fbuf->data));
				if (i == 0)
					sc->superblock.fd_root[ma.fd] = SECTOR_CACHE;
			} else {
				KASSERT(sa >= SECTORS_PER_SEG, ("%s", __func__));
				md_read(sc, fbuf->data, sa);
			}
		} else {
			KASSERT(fbuf->parent == parent, ("%s", __func__));
			KASSERT(fbuf->sa == sa ||
				(i == 0 && sa == SECTOR_CACHE), ("%s", __func__));
		}
		if (i == ma.depth) // reach the intended depth
			break;

		parent = fbuf;		// %fbuf is the parent of next level indirect block
		index = ma_index_get(ma, i);// the index to next level's indirect block
		sa = parent->data[index];	// the sector address of the next level indirect block
		ima = ma_index_set(ima, i, index); // set the next level's index for @ima
	} // for
end:
	fbuf->fc.accessed = true;
	return fbuf;
}

static void
fbuf_write(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	struct _fbuf *parent;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address

	KASSERT(fbuf->fc.modified, ("%s", __func__));
	sa = _logstor_write(sc, NULL, fbuf->ma.uint32, fbuf->data);
	fbuf->fc.modified = false;

	// update the sector address of this fbuf in its parent's fbuf
	parent = fbuf->parent;
	if (parent) {
		KASSERT(fbuf->ma.depth != 0, ("%s", __func__));
		KASSERT(parent->ma.depth == fbuf->ma.depth - 1, ("%s", __func__));
		pindex = ma_index_get(fbuf->ma, fbuf->ma.depth - 1);
		parent->data[pindex] = sa;
		parent->fc.modified = true;
	} else {
		KASSERT(fbuf->ma.depth == 0, ("%s", __func__));
		// store the root sector address to the corresponding file table in super block
		sc->superblock.fd_root[fbuf->ma.fd] = sa;
		sc->sb_modified = true;
	}
}

DECLARE_GEOM_CLASS(g_logstor_class, g_logstor); /* Let there be light */
MODULE_VERSION(geom_logstor, 0);
