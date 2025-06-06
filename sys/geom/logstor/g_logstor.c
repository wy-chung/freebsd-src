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
#include <geom/logstor/g_logstor_md.h>

FEATURE(g_logstor, "GEOM virtual storage support");

/* Declare malloc(9) label */
static MALLOC_DEFINE(M_GLOGSTOR, "glogstor", "GEOM_LOGSTOR Data");
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
	.init =		g_logstor_init,	// empty
	.fini =		g_logstor_fini,	// empty
	.taste =	g_logstor_taste,
	.ctlreq =	g_logstor_config,
	.destroy_geom = g_logstor_destroy_geom
	/* The .dumpconf and the rest are only usable for a geom instance, so
	 * they will be set when such instance is created. */
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

static int read_metadata(struct g_consumer *, struct g_logstor_metadata *);
static void write_metadata(struct g_consumer *, struct g_logstor_metadata *);
static int clear_metadata(struct g_logstor_component *);
static int add_provider_to_geom(struct g_logstor_softc *, struct g_provider *,
    struct g_logstor_metadata *);
static struct g_geom *create_logstor_geom(struct g_class *,
    struct g_logstor_metadata *);
static void logstor_check_and_run(struct g_logstor_softc *);
static u_int logstor_valid_components(struct g_logstor_softc *);
static int logstor_geom_destroy(struct g_logstor_softc *, boolean_t,
    boolean_t);
static void remove_component(struct g_logstor_softc *,
    struct g_logstor_component *, boolean_t);
static void bioq_dismantle(struct bio_queue_head *);
static int allocate_chunk(struct g_logstor_softc *,
    struct g_logstor_component **, u_int *, u_int *);
static void delay_destroy_consumer(void *, int);
static void dump_component(struct g_logstor_component *comp);
#if 0
static void dump_me(struct logstor_map_entry *me, unsigned int nr);
#endif

static void logstor_ctl_stop(struct gctl_req *, struct g_class *);
static void logstor_ctl_add(struct gctl_req *, struct g_class *);
static void logstor_ctl_remove(struct gctl_req *, struct g_class *);
static void logstor_ctl_commit(struct gctl_req *, struct g_class *);
static void logstor_ctl_revert(struct gctl_req *, struct g_class *);

static struct g_logstor_softc * logstor_find_geom(const struct g_class *,
    const char *);
static void update_metadata(struct g_logstor_softc *);
static void fill_metadata(struct g_logstor_softc *, struct g_logstor_metadata *,
    u_int, u_int);

static void g_logstor_orphan(struct g_consumer *);
static int g_logstor_access(struct g_provider *, int, int, int);
static void g_logstor_start(struct bio *);
static void g_logstor_dumpconf(struct sbuf *, const char *, struct g_geom *,
    struct g_consumer *, struct g_provider *);
static void g_logstor_done(struct bio *);

static void invalid_call(void);

//=========================
#define RAM_DISK_SIZE		0x180000000UL // 6G

/*
	logstor soft control
*/
struct logstor_softc {
	uint32_t seg_alloc_start;// the starting segment for _logstor_write
	uint32_t seg_alloc_sa;	// the sector address of the segment for allocation
	struct _seg_sum seg_sum;// segment summary for the hot segment
	uint32_t sb_sa; 	// superblock's sector address
	bool sb_modified;	// is the super block modified
	bool ss_modified;	// is segment summary modified

	int fbuf_count;
	struct _fbuf *fbufs;	// an array of fbufs
	struct _fbuf *fbuf_allocp; // point to the fbuf candidate for replacement
	struct _fbuf_sentinel fbuf_queue[QUEUE_CNT];
	int fbuf_queue_len[QUEUE_CNT];

	// buffer hash queue
	struct _fbuf_sentinel fbuf_bucket[FBUF_BUCKET_CNT];

	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;

	/*
	  The macro RAM_DISK_SIZE is used for debug.
	  By using RAM as the storage device, the test can run way much faster.
	*/
#if !defined(RAM_DISK_SIZE)
	int disk_fd;
#endif
	struct _superblock superblock;
};

uint32_t gdb_cond0 = -1;
uint32_t gdb_cond1 = -1;

#if defined(RAM_DISK_SIZE)
static char *ram_disk;
#endif
static struct logstor_softc sc;

static uint32_t _logstor_read(struct g_logstor_softc *sc, struct bio *bp);
static uint32_t _logstor_write(struct g_logstor_softc *sc, struct bio *bp, uint32_t ba, void *data);

static void _seg_alloc(struct g_logstor_softc *sc);
static void seg_sum_write(struct g_logstor_softc *sc);

static uint32_t disk_init(struct g_logstor_softc *sc, int fd);
static int  superblock_read(struct g_logstor_softc *sc);
static void superblock_write(struct g_logstor_softc *sc);

static struct _fbuf *file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t offset, uint32_t *off_4byte);
static uint32_t file_read_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba);
static void file_write_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba, uint32_t sa);

static void fbuf_mod_init(struct g_logstor_softc *sc);
static void fbuf_mod_fini(struct g_logstor_softc *sc);
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

static int _g_read_data(struct g_consumer *cp, off_t offset, void *ptr, off_t length);
static void md_read (struct g_logstor_softc *sc, uint32_t sa, void *buf);
static void md_write(struct g_logstor_softc *sc, uint32_t sa, const void *buf);

static uint32_t logstor_ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba);
static uint32_t logstor_ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba);
static bool is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);

static bool (*is_sec_valid_fp)(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev) = is_sec_valid_normal;
static uint32_t (*logstor_ba2sa_fp)(struct g_logstor_softc *sc, uint32_t ba) = logstor_ba2sa_normal;

//=========================

/*
 * Initialise GEOM class (per-class callback)
 */
static void
g_logstor_init(struct g_class *mp __unused)
{

	/* Catch map struct size mismatch at compile time; Map entries must
	 * fit into maxphys exactly, with no wasted space. */
	MPASS(LOGSTOR_MAP_BLOCK_ENTRIES * LOGSTOR_MAP_ENTRY_SIZE == maxphys);

	/* Init UMA zones, TAILQ's, other global vars */
}

/*
 * Finalise GEOM class (per-class callback)
 */
static void
g_logstor_fini(struct g_class *mp __unused)
{

	/* Deinit UMA zones & global vars */
}

/*
 * Config (per-class callback)
 */
static void
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
	if (strcmp(verb, "add") == 0)
		logstor_ctl_add(req, mp);
	else if (strcmp(verb, "stop") == 0 || strcmp(verb, "destroy") == 0)
		logstor_ctl_stop(req, mp);
	else if (strcmp(verb, "remove") == 0)
		logstor_ctl_remove(req, mp);
	else if (strcmp(verb, "commit") == 0)
		logstor_ctl_commit(req, mp);
	else if (strcmp(verb, "revert") == 0)
		logstor_ctl_revert(req, mp);
	else
		gctl_error(req, "unknown verb: '%s'", verb);
	g_topology_lock();
}

/*
 * "stop" verb from userland
 */
static void
logstor_ctl_stop(struct gctl_req *req, struct g_class *cp)
{
	int *force, *nargs;
	int i;

	nargs = gctl_get_paraml(req, "nargs", sizeof *nargs);
	if (nargs == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "nargs");
		return;
	}
	if (*nargs < 1) {
		gctl_error(req, "Invalid number of arguments");
		return;
	}
	force = gctl_get_paraml(req, "force", sizeof *force);
	if (force == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "force");
		return;
	}

	g_topology_lock();
	for (i = 0; i < *nargs; i++) {
		char param[8];
		const char *name;
		struct g_logstor_softc *sc;
		int error;

		snprintf(param, sizeof(param), "arg%d", i);
		name = gctl_get_asciiparam(req, param);
		if (name == NULL) {
			gctl_error(req, "No 'arg%d' argument", i);
			g_topology_unlock();
			return;
		}
		sc = logstor_find_geom(cp, name);
		if (sc == NULL) {
			gctl_error(req, "Don't know anything about '%s'", name);
			g_topology_unlock();
			return;
		}

		LOG_MSG(LVL_INFO, "Stopping %s by the userland command",
		    sc->geom->name);
		update_metadata(sc);
		if ((error = logstor_geom_destroy(sc, TRUE, TRUE)) != 0) {
			LOG_MSG(LVL_ERROR, "Cannot destroy %s: %d",
			    sc->geom->name, error);
		}
	}
	g_topology_unlock();
}

/*
 * "add" verb from userland - add new component(s) to the structure.
 * This will be done all at once in here, without going through the
 * .taste function for new components.
 */
static void
logstor_ctl_add(struct gctl_req *req, struct g_class *cp)
{
	/* Note: while this is going on, I/O is being done on
	 * the g_up and g_down threads. The idea is to make changes
	 * to softc members in a way that can atomically activate
	 * them all at once. */
	struct g_logstor_softc *sc;
	int *hardcode, *nargs;
	const char *geom_name;	/* geom to add a component to */
	struct g_consumer *fcp;
	struct g_logstor_bio_q *bq;
	u_int added;
	int error;
	int i;

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "nargs");
		return;
	}
	if (*nargs < 2) {
		gctl_error(req, "Invalid number of arguments");
		return;
	}
	hardcode = gctl_get_paraml(req, "hardcode", sizeof(*hardcode));
	if (hardcode == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "hardcode");
		return;
	}

	/* Find "our" geom */
	geom_name = gctl_get_asciiparam(req, "arg0");
	if (geom_name == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "geom_name (arg0)");
		return;
	}
	sc = logstor_find_geom(cp, geom_name);
	if (sc == NULL) {
		gctl_error(req, "Don't know anything about '%s'", geom_name);
		return;
	}

	if (logstor_valid_components(sc) != sc->n_components) {
		LOG_MSG(LVL_ERROR, "Cannot add components to incomplete "
		    "logstor %s", sc->geom->name);
		gctl_error(req, "Logstor %s is incomplete", sc->geom->name);
		return;
	}

	fcp = sc->components[0].gcons;
	added = 0;
	g_topology_lock();
	for (i = 1; i < *nargs; i++) {
		struct g_logstor_metadata md;
		char aname[8];
		struct g_provider *pp;
		struct g_consumer *cp;
		u_int nc;
		u_int j;

		snprintf(aname, sizeof aname, "arg%d", i);
		pp = gctl_get_provider(req, aname);
		if (pp == NULL) {
			/* This is the most common error so be verbose about it */
			if (added != 0) {
				gctl_error(req, "Invalid provider. (added"
				    " %u components)", added);
				update_metadata(sc);
			}
			g_topology_unlock();
			return;
		}
		cp = g_new_consumer(sc->geom);
		if (cp == NULL) {
			gctl_error(req, "Cannot create consumer");
			g_topology_unlock();
			return;
		}
		error = g_attach(cp, pp);
		if (error != 0) {
			gctl_error(req, "Cannot attach a consumer to %s",
			    pp->name);
			g_destroy_consumer(cp);
			g_topology_unlock();
			return;
		}
		if (fcp->acr != 0 || fcp->acw != 0 || fcp->ace != 0) {
			error = g_access(cp, fcp->acr, fcp->acw, fcp->ace);
			if (error != 0) {
				gctl_error(req, "Access request failed for %s",
				    pp->name);
				g_destroy_consumer(cp);
				g_topology_unlock();
				return;
			}
		}
		if (fcp->provider->sectorsize != pp->sectorsize) {
			gctl_error(req, "Sector size doesn't fit for %s",
			    pp->name);
			g_destroy_consumer(cp);
			g_topology_unlock();
			return;
		}
		for (j = 0; j < sc->n_components; j++) {
			if (strcmp(sc->components[j].gcons->provider->name,
			    pp->name) == 0) {
				gctl_error(req, "Component %s already in %s",
				    pp->name, sc->geom->name);
				g_destroy_consumer(cp);
				g_topology_unlock();
				return;
			}
		}
		sc->components = realloc(sc->components,
		    sizeof(*sc->components) * (sc->n_components + 1),
		    M_GLOGSTOR, M_WAITOK);

		nc = sc->n_components;
		sc->components[nc].gcons = cp;
		sc->components[nc].sc = sc;
		sc->components[nc].index = nc;
		sc->components[nc].chunk_count = cp->provider->mediasize /
		    sc->chunk_size;
		sc->components[nc].chunk_next = 0;
		sc->components[nc].chunk_reserved = 0;

		if (sc->components[nc].chunk_count < 4) {
			gctl_error(req, "Provider too small: %s",
			    cp->provider->name);
			g_destroy_consumer(cp);
			g_topology_unlock();
			return;
		}
		fill_metadata(sc, &md, nc, *hardcode);
		write_metadata(cp, &md);
		/* The new component becomes visible when n_components is
		 * incremented */
		sc->n_components++;
		added++;
	}
	/* This call to update_metadata() is critical. In case there's a
	 * power failure in the middle of it and some components are updated
	 * while others are not, there will be trouble on next .taste() iff
	 * a non-updated component is detected first */
	update_metadata(sc);
	g_topology_unlock();
	LOG_MSG(LVL_INFO, "Added %d component(s) to %s", added,
	    sc->geom->name);
	/* Fire off BIOs previously queued because there wasn't any
	 * physical space left. If the BIOs still can't be satisfied
	 * they will again be added to the end of the queue (during
	 * which the mutex will be recursed) */
	bq = malloc(sizeof(*bq), M_GLOGSTOR, M_WAITOK);
	bq->bio = NULL;
	mtx_lock(&sc->delayed_bio_q_mtx);
	/* First, insert a sentinel to the queue end, so we don't
	 * end up in an infinite loop if there's still no free
	 * space available. */
	STAILQ_INSERT_TAIL(&sc->delayed_bio_q, bq, linkage);
	while (!STAILQ_EMPTY(&sc->delayed_bio_q)) {
		bq = STAILQ_FIRST(&sc->delayed_bio_q);
		if (bq->bio != NULL) {
			g_logstor_start(bq->bio);
			STAILQ_REMOVE_HEAD(&sc->delayed_bio_q, linkage);
			free(bq, M_GLOGSTOR);
		} else {
			STAILQ_REMOVE_HEAD(&sc->delayed_bio_q, linkage);
			free(bq, M_GLOGSTOR);
			break;
		}
	}
	mtx_unlock(&sc->delayed_bio_q_mtx);

}

/*
 * Find a geom handled by the class
 */
static struct g_logstor_softc *
logstor_find_geom(const struct g_class *cp, const char *name)
{
	struct g_geom *gp;

	LIST_FOREACH(gp, &cp->geom, geom) {
		if (strcmp(name, gp->name) == 0)
			return (gp->softc);
	}
	return (NULL);
}

/*
 * Update metadata on all components to reflect the current state
 * of these fields:
 *    - chunk_next
 *    - flags
 *    - md_count
 * Expects things to be set up so write_metadata() can work, i.e.
 * the topology lock must be held.
 */
static void
update_metadata(struct g_logstor_softc *sc)
{
	struct g_logstor_metadata md;
	u_int n;

	if (logstor_valid_components(sc) != sc->n_components)
		return; /* Incomplete device */
	LOG_MSG(LVL_DEBUG, "Updating metadata on components for %s",
	    sc->geom->name);
	/* Update metadata on components */
	g_trace(G_T_TOPOLOGY, "%s(%s, %s)", __func__,
	    sc->geom->class->name, sc->geom->name);
	g_topology_assert();
	for (n = 0; n < sc->n_components; n++) {
		read_metadata(sc->components[n].gcons, &md);
		md.chunk_next = sc->components[n].chunk_next;
		md.flags = sc->components[n].flags;
		md.md_count = sc->n_components;
		write_metadata(sc->components[n].gcons, &md);
	}
}

/*
 * Fills metadata (struct md) from information stored in softc and the nc'th
 * component of logstor
 */
static void
fill_metadata(struct g_logstor_softc *sc, struct g_logstor_metadata *md,
    u_int nc, u_int hardcode)
{
	struct g_logstor_component *c;

	bzero(md, sizeof *md);
	c = &sc->components[nc];

	strncpy(md->md_magic, G_LOGSTOR_MAGIC, sizeof md->md_magic);
	md->md_version = G_LOGSTOR_VERSION;
	strncpy(md->md_name, sc->geom->name, sizeof md->md_name);
	md->md_id = sc->id;
	md->md_virsize = sc->virsize;
	md->md_chunk_size = sc->chunk_size;
	md->md_count = sc->n_components;

	if (hardcode) {
		strncpy(md->provider, c->gcons->provider->name,
		    sizeof md->provider);
	}
	md->no = nc;
	md->provsize = c->gcons->provider->mediasize;
	md->chunk_count = c->chunk_count;
	md->chunk_next = c->chunk_next;
	md->chunk_reserved = c->chunk_reserved;
	md->flags = c->flags;
}

/*
 * Remove a component from logstor device.
 * Can only be done if the component is unallocated.
 */
static void
logstor_ctl_remove(struct gctl_req *req, struct g_class *cp)
{
	/* As this is executed in parallel to I/O, operations on logstor
	 * structures must be as atomic as possible. */
	struct g_logstor_softc *sc;
	int *nargs;
	const char *geom_name;
	u_int removed;
	int i;

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "Error fetching argument '%s'", "nargs");
		return;
	}
	if (*nargs < 2) {
		gctl_error(req, "Invalid number of arguments");
		return;
	}
	/* Find "our" geom */
	geom_name = gctl_get_asciiparam(req, "arg0");
	if (geom_name == NULL) {
		gctl_error(req, "Error fetching argument '%s'",
		    "geom_name (arg0)");
		return;
	}
	sc = logstor_find_geom(cp, geom_name);
	if (sc == NULL) {
		gctl_error(req, "Don't know anything about '%s'", geom_name);
		return;
	}

	if (logstor_valid_components(sc) != sc->n_components) {
		LOG_MSG(LVL_ERROR, "Cannot remove components from incomplete "
		    "logstor %s", sc->geom->name);
		gctl_error(req, "Logstor %s is incomplete", sc->geom->name);
		return;
	}

	removed = 0;
	for (i = 1; i < *nargs; i++) {
		char param[8];
		const char *prov_name;
		int j, found;
		struct g_logstor_component *newcomp, *compbak;

		snprintf(param, sizeof(param), "arg%d", i);
		prov_name = gctl_get_asciiparam(req, param);
		if (prov_name == NULL) {
			gctl_error(req, "Error fetching argument '%s'", param);
			return;
		}
		if (strncmp(prov_name, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
			prov_name += sizeof(_PATH_DEV) - 1;

		found = -1;
		for (j = 0; j < sc->n_components; j++) {
			if (strcmp(sc->components[j].gcons->provider->name,
			    prov_name) == 0) {
				found = j;
				break;
			}
		}
		if (found == -1) {
			LOG_MSG(LVL_ERROR, "No %s component in %s",
			    prov_name, sc->geom->name);
			continue;
		}

		compbak = sc->components;
		newcomp = malloc(sc->n_components * sizeof(*sc->components),
		    M_GLOGSTOR, M_WAITOK | M_ZERO);
		bcopy(sc->components, newcomp, found * sizeof(*sc->components));
		bcopy(&sc->components[found + 1], newcomp + found,
		    found * sizeof(*sc->components));
		if ((sc->components[j].flags & LOGSTOR_PROVIDER_ALLOCATED) != 0) {
			LOG_MSG(LVL_ERROR, "Allocated provider %s cannot be "
			    "removed from %s",
			    prov_name, sc->geom->name);
			free(newcomp, M_GLOGSTOR);
			/* We'll consider this non-fatal error */
			continue;
		}
		/* Renumerate unallocated components */
		for (j = 0; j < sc->n_components-1; j++) {
			if ((sc->components[j].flags &
			    LOGSTOR_PROVIDER_ALLOCATED) == 0) {
				sc->components[j].index = j;
			}
		}
		/* This is the critical section. If a component allocation
		 * event happens while both variables are not yet set,
		 * there will be trouble. Something will panic on encountering
		 * NULL sc->components[x].gcomp member.
		 * Luckily, component allocation happens very rarely and
		 * removing components is an abnormal action in any case. */
		sc->components = newcomp;
		sc->n_components--;
		/* End critical section */

		g_topology_lock();
		if (clear_metadata(&compbak[found]) != 0) {
			LOG_MSG(LVL_WARNING, "Trouble ahead: cannot clear "
			    "metadata on %s", prov_name);
		}
		g_detach(compbak[found].gcons);
		g_destroy_consumer(compbak[found].gcons);
		g_topology_unlock();

		free(compbak, M_GLOGSTOR);

		removed++;
	}

	/* This call to update_metadata() is critical. In case there's a
	 * power failure in the middle of it and some components are updated
	 * while others are not, there will be trouble on next .taste() iff
	 * a non-updated component is detected first */
	g_topology_lock();
	update_metadata(sc);
	g_topology_unlock();
	LOG_MSG(LVL_INFO, "Removed %d component(s) from %s", removed,
	    sc->geom->name);
}

/*
 * Clear metadata sector on component
 */
static int
clear_metadata(struct g_logstor_component *comp)
{
	char *buf;
	int error;

	LOG_MSG(LVL_INFO, "Clearing metadata on %s",
	    comp->gcons->provider->name);
	g_topology_assert();
	error = g_access(comp->gcons, 0, 1, 0);
	if (error != 0)
		return (error);
	buf = malloc(comp->gcons->provider->sectorsize, M_GLOGSTOR,
	    M_WAITOK | M_ZERO);
	error = g_write_data(comp->gcons,
	    comp->gcons->provider->mediasize -
	    comp->gcons->provider->sectorsize,
	    buf,
	    comp->gcons->provider->sectorsize);
	free(buf, M_GLOGSTOR);
	g_access(comp->gcons, 0, -1, 0);
	return (error);
}

/*
 * Destroy geom forcibly.
 */
static int
g_logstor_destroy_geom(struct gctl_req *req __unused, struct g_class *mp,
    struct g_geom *gp)
{
	struct g_logstor_softc *sc;
	int exitval;

	sc = gp->softc;
	KASSERT(sc != NULL, ("%s: NULL sc", __func__));

	exitval = 0;
	LOG_MSG(LVL_DEBUG, "%s called for %s, sc=%p", __func__, gp->name,
	    gp->softc);

	if (sc != NULL) {
#ifdef INVARIANTS
		char *buf;
		int error;
		off_t off;
		int isclean, count;
		int n;

		LOG_MSG(LVL_INFO, "INVARIANTS detected");
		LOG_MSG(LVL_INFO, "Verifying allocation "
		    "table for %s", sc->geom->name);
		count = 0;
		for (n = 0; n < sc->chunk_count; n++) {
			if (sc->map[n].flags || LOGSTOR_MAP_ALLOCATED != 0)
				count++;
		}
		LOG_MSG(LVL_INFO, "Device %s has %d allocated chunks",
		    sc->geom->name, count);
		n = off = count = 0;
		isclean = 1;
		if (logstor_valid_components(sc) != sc->n_components) {
			/* This is a incomplete logstor device (not all
			 * components have been found) */
			LOG_MSG(LVL_ERROR, "Device %s is incomplete",
			    sc->geom->name);
			goto bailout;
		}
		error = g_access(sc->components[0].gcons, 1, 0, 0);
		KASSERT(error == 0, ("%s: g_access failed (%d)", __func__,
		    error));
		/* Compare the whole on-disk allocation table with what's
		 * currently in memory */
		while (n < sc->chunk_count) {
			buf = g_read_data(sc->components[0].gcons, off,
			    sc->sectorsize, &error);
			KASSERT(buf != NULL, ("g_read_data returned NULL (%d) "
			    "for read at %jd", error, off));
			if (bcmp(buf, &sc->map[n], sc->sectorsize) != 0) {
				LOG_MSG(LVL_ERROR, "ERROR in allocation table, "
				    "entry %d, offset %jd", n, off);
				isclean = 0;
				count++;
			}
			n += sc->me_per_sector;
			off += sc->sectorsize;
			g_free(buf);
		}
		error = g_access(sc->components[0].gcons, -1, 0, 0);
		KASSERT(error == 0, ("%s: g_access failed (%d) on exit",
		    __func__, error));
		if (isclean != 1) {
			LOG_MSG(LVL_ERROR, "ALLOCATION TABLE CORRUPTED FOR %s "
			    "(%d sectors don't match, max %zu allocations)",
			    sc->geom->name, count,
			    count * sc->me_per_sector);
		} else {
			LOG_MSG(LVL_INFO, "Allocation table ok for %s",
			    sc->geom->name);
		}
bailout:
#endif
		update_metadata(sc);
		logstor_geom_destroy(sc, FALSE, FALSE);
		exitval = EAGAIN;
	} else
		exitval = 0;
	return (exitval);
}

/*
 * Taste event (per-class callback)
 * Examines a provider and creates geom instances if needed
 */
static struct g_geom *
g_logstor_taste(struct g_class *mp, struct g_provider *pp, int flags)
{
	struct g_logstor_metadata md;
	struct g_geom *gp;
	struct g_consumer *cp;
	struct g_logstor_softc *sc;
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
	if (error == 0) {
		error = read_metadata(cp, &md);
		g_detach(cp);
	}
	g_destroy_consumer(cp);
	g_destroy_geom(gp);

	if (error != 0)
		return (NULL);

	if (strcmp(md.md_magic, G_LOGSTOR_MAGIC) != 0)
		return (NULL);
	if (md.md_version != G_LOGSTOR_VERSION) {
		LOG_MSG(LVL_ERROR, "Kernel module version invalid "
		    "to handle %s (%s) : %d should be %d",
		    md.md_name, pp->name, md.md_version, G_LOGSTOR_VERSION);
		return (NULL);
	}
	if (md.provsize != pp->mediasize)
		return (NULL);

	/* If the provider name is hardcoded, use the offered provider only
	 * if it's been offered with its proper name (the one used in
	 * the label command). */
	if (md.provider[0] != '\0' &&
	    !g_compare_names(md.provider, pp->name))
		return (NULL);

	/* Iterate all geoms this class already knows about to see if a new
	 * geom instance of this class needs to be created (in case the provider
	 * is first from a (possibly) multi-consumer geom) or it just needs
	 * to be added to an existing instance. */
	sc = NULL;
	//gp = NULL;
	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc == NULL)
			continue;
		if (strcmp(md.md_name, sc->geom->name) != 0)
			continue;
		if (md.md_id != sc->id)
			continue;
		break;
	}
	if (gp != NULL) { /* We found an existing geom instance; add to it */
		LOG_MSG(LVL_INFO, "Adding %s to %s", pp->name, md.md_name);
		error = add_provider_to_geom(sc, pp, &md);
		if (error != 0) {
			LOG_MSG(LVL_ERROR, "Error adding %s to %s (error %d)",
			    pp->name, md.md_name, error);
			return (NULL);
		}
	} else { /* New geom instance needs to be created */
		gp = create_logstor_geom(mp, &md);
		if (gp == NULL) {
			LOG_MSG(LVL_ERROR, "Error creating new instance of "
			    "class %s: %s", mp->name, md.md_name);
			LOG_MSG(LVL_DEBUG, "Error creating %s at %s",
			    md.md_name, pp->name);
			return (NULL);
		}
		sc = gp->softc;
		LOG_MSG(LVL_INFO, "Adding %s to %s (first found)", pp->name,
		    md.md_name);
		error = add_provider_to_geom(sc, pp, &md);
		if (error != 0) {
			LOG_MSG(LVL_ERROR, "Error adding %s to %s (error %d)",
			    pp->name, md.md_name, error);
			logstor_geom_destroy(sc, TRUE, FALSE);
			return (NULL);
		}
	}

	return (gp);
}

/*
 * Destroyes consumer passed to it in arguments. Used as a callback
 * on g_event queue.
 */
static void
delay_destroy_consumer(void *arg, int flags __unused)
{
	struct g_consumer *c = arg;
	KASSERT(c != NULL, ("%s: invalid consumer", __func__));
	LOG_MSG(LVL_DEBUG, "Consumer %s destroyed with delay",
	    c->provider->name);
	g_detach(c);
	g_destroy_consumer(c);
}

/*
 * Remove a component (consumer) from geom instance; If it's the first
 * component being removed, orphan the provider to announce geom's being
 * dismantled
 */
static void
remove_component(struct g_logstor_softc *sc, struct g_logstor_component *comp,
    boolean_t delay)
{
	struct g_consumer *c;

	KASSERT(comp->gcons != NULL, ("Component with no consumer in %s",
	    sc->geom->name));
	c = comp->gcons;

	comp->gcons = NULL;
	KASSERT(c->provider != NULL, ("%s: no provider", __func__));
	LOG_MSG(LVL_DEBUG, "Component %s removed from %s", c->provider->name,
	    sc->geom->name);
	if (sc->provider != NULL) {
		LOG_MSG(LVL_INFO, "Removing provider %s", sc->provider->name);
		g_wither_provider(sc->provider, ENXIO);
		sc->provider = NULL;
	}

	if (c->acr > 0 || c->acw > 0 || c->ace > 0)
		return;
	if (delay) {
		/* Destroy consumer after it's tasted */
		g_post_event(delay_destroy_consumer, c, M_WAITOK, NULL);
	} else {
		g_detach(c);
		g_destroy_consumer(c);
	}
}

/*
 * Destroy geom - called internally
 * See g_logstor_destroy_geom for the other one
 */
static int
logstor_geom_destroy(struct g_logstor_softc *sc, boolean_t force,
    boolean_t delay)
{
	struct g_provider *pp;
	struct g_geom *gp;
	u_int n;

	g_topology_assert();

	if (sc == NULL)
		return (ENXIO);

	pp = sc->provider;
	if (pp != NULL && (pp->acr != 0 || pp->acw != 0 || pp->ace != 0)) {
		LOG_MSG(force ? LVL_WARNING : LVL_ERROR,
		    "Device %s is still open.", pp->name);
		if (!force)
			return (EBUSY);
	}

	for (n = 0; n < sc->n_components; n++) {
		if (sc->components[n].gcons != NULL)
			remove_component(sc, &sc->components[n], delay);
	}

	gp = sc->geom;
	gp->softc = NULL;

	KASSERT(sc->provider == NULL, ("Provider still exists for %s",
	    gp->name));

	/* XXX: This might or might not work, since we're called with
	 * the topology lock held. Also, it might panic the kernel if
	 * the error'd BIO is in softupdates code. */
	mtx_lock(&sc->delayed_bio_q_mtx);
	while (!STAILQ_EMPTY(&sc->delayed_bio_q)) {
		struct g_logstor_bio_q *bq;
		bq = STAILQ_FIRST(&sc->delayed_bio_q);
		bq->bio->bio_error = ENOSPC;
		g_io_deliver(bq->bio, EIO);
		STAILQ_REMOVE_HEAD(&sc->delayed_bio_q, linkage);
		free(bq, M_GLOGSTOR);
	}
	mtx_unlock(&sc->delayed_bio_q_mtx);
	mtx_destroy(&sc->delayed_bio_q_mtx);

	free(sc->map, M_GLOGSTOR);
	free(sc->components, M_GLOGSTOR);
	bzero(sc, sizeof *sc);
	free(sc, M_GLOGSTOR);

	pp = LIST_FIRST(&gp->provider); /* We only offer one provider */
	if (pp == NULL || (pp->acr == 0 && pp->acw == 0 && pp->ace == 0))
		LOG_MSG(LVL_DEBUG, "Device %s destroyed", gp->name);

	g_wither_geom(gp, ENXIO);

	return (0);
}

/*
 * Utility function: read metadata & decode. Wants topology lock to be
 * held.
 */
static int
read_metadata(struct g_consumer *cp, struct g_logstor_metadata *md)
{
	struct g_provider *pp;
	char *buf;
	int error;

	g_topology_assert();
	error = g_access(cp, 1, 0, 0);
	if (error != 0)
		return (error);
	pp = cp->provider;
	g_topology_unlock();
	buf = g_read_data(cp, pp->mediasize - pp->sectorsize, pp->sectorsize,
	    &error);
	g_topology_lock();
	g_access(cp, -1, 0, 0);
	if (buf == NULL)
		return (error);

	logstor_metadata_decode(buf, md);
	g_free(buf);

	return (0);
}

/**
 * Utility function: encode & write metadata. Assumes topology lock is
 * held.
 *
 * There is no useful way of recovering from errors in this function,
 * not involving panicking the kernel. If the metadata cannot be written
 * the most we can do is notify the operator and hope he spots it and
 * replaces the broken drive.
 */
static void
write_metadata(struct g_consumer *cp, struct g_logstor_metadata *md)
{
	struct g_provider *pp;
	char *buf;
	int error;

	KASSERT(cp != NULL && md != NULL && cp->provider != NULL,
	    ("Something's fishy in %s", __func__));
	LOG_MSG(LVL_DEBUG, "Writing metadata on %s", cp->provider->name);
	g_topology_assert();
	error = g_access(cp, 0, 1, 0);
	if (error != 0) {
		LOG_MSG(LVL_ERROR, "g_access(0,1,0) failed for %s: %d",
		    cp->provider->name, error);
		return;
	}
	pp = cp->provider;

	buf = malloc(pp->sectorsize, M_GLOGSTOR, M_WAITOK);
	bzero(buf, pp->sectorsize);
	logstor_metadata_encode(md, buf);
	g_topology_unlock();
	error = g_write_data(cp, pp->mediasize - pp->sectorsize, buf,
	    pp->sectorsize);
	g_topology_lock();
	g_access(cp, 0, -1, 0);
	free(buf, M_GLOGSTOR);

	if (error != 0)
		LOG_MSG(LVL_ERROR, "Error %d writing metadata to %s",
		    error, cp->provider->name);
}

/*
 * Creates a new instance of this GEOM class, initialise softc
 */
static struct g_geom *
create_logstor_geom(struct g_class *mp, struct g_logstor_metadata *md)
{
	struct g_geom *gp;
	struct g_logstor_softc *sc;

	LOG_MSG(LVL_DEBUG, "Creating geom instance for %s (id=%u)",
	    md->md_name, md->md_id);

	if (md->md_count < 1 || md->md_chunk_size < 1 ||
	    md->md_virsize < md->md_chunk_size) {
		/* This is bogus configuration, and probably means data is
		 * somehow corrupted. Panic, maybe? */
		LOG_MSG(LVL_ERROR, "Nonsensical metadata information for %s",
		    md->md_name);
		return (NULL);
	}

	/* Check if it's already created */
	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc != NULL && strcmp(sc->geom->name, md->md_name) == 0) {
			LOG_MSG(LVL_WARNING, "Geom %s already exists",
			    md->md_name);
			if (sc->id != md->md_id) {
				LOG_MSG(LVL_ERROR,
				    "Some stale or invalid components "
				    "exist for logstor device named %s. "
				    "You will need to <CLEAR> all stale "
				    "components and maybe reconfigure "
				    "the logstor device. Tune "
				    "kern.geom.logstor.debug sysctl up "
				    "for more information.",
				    sc->geom->name);
			}
			return (NULL);
		}
	}
	gp = g_new_geomf(mp, "%s", md->md_name);
	gp->softc = NULL; /* to circumevent races that test softc */

	gp->start = g_logstor_start;
	gp->spoiled = g_logstor_orphan;
	gp->orphan = g_logstor_orphan;
	gp->access = g_logstor_access;
	gp->dumpconf = g_logstor_dumpconf;

	sc = malloc(sizeof(*sc), M_GLOGSTOR, M_WAITOK | M_ZERO);
	sc->id = md->md_id;
	sc->n_components = md->md_count;
	sc->components = malloc(sizeof(struct g_logstor_component) * md->md_count,
	    M_GLOGSTOR, M_WAITOK | M_ZERO);
	sc->chunk_size = md->md_chunk_size;
	sc->virsize = md->md_virsize;
	STAILQ_INIT(&sc->delayed_bio_q);
	mtx_init(&sc->delayed_bio_q_mtx, "glogstor_delayed_bio_q_mtx",
	    "glogstor", MTX_DEF | MTX_RECURSE);

	sc->geom = gp;
	sc->provider = NULL; /* logstor_check_and_run will create it */
	gp->softc = sc;

	LOG_MSG(LVL_ANNOUNCE, "Device %s created", sc->geom->name);

	return (gp);
}

/*
 * Add provider to a GEOM class instance
 */
static int
add_provider_to_geom(struct g_logstor_softc *sc, struct g_provider *pp,
    struct g_logstor_metadata *md)
{
	struct g_logstor_component *component;
	struct g_consumer *cp, *fcp;
	struct g_geom *gp;
	int error;

	if (md->no >= sc->n_components)
		return (EINVAL);

	/* "Current" compontent */
	component = &(sc->components[md->no]);
	if (component->gcons != NULL)
		return (EEXIST);

	gp = sc->geom;
	fcp = LIST_FIRST(&gp->consumer);

	cp = g_new_consumer(gp);
	error = g_attach(cp, pp);

	if (error != 0) {
		g_destroy_consumer(cp);
		return (error);
	}

	if (fcp != NULL) {
		if (fcp->provider->sectorsize != pp->sectorsize) {
			/* TODO: this can be made to work */
			LOG_MSG(LVL_ERROR, "Provider %s of %s has invalid "
			    "sector size (%d)", pp->name, sc->geom->name,
			    pp->sectorsize);
			return (EINVAL);
		}
		if (fcp->acr > 0 || fcp->acw || fcp->ace > 0) {
			/* Replicate access permissions from first "live" consumer
			 * to the new one */
			error = g_access(cp, fcp->acr, fcp->acw, fcp->ace);
			if (error != 0) {
				g_detach(cp);
				g_destroy_consumer(cp);
				return (error);
			}
		}
	}

	/* Bring up a new component */
	cp->private = component;
	component->gcons = cp;
	component->sc = sc;
	component->index = md->no;
	component->chunk_count = md->chunk_count;
	component->chunk_next = md->chunk_next;
	component->chunk_reserved = md->chunk_reserved;
	component->flags = md->flags;

	LOG_MSG(LVL_DEBUG, "%s attached to %s", pp->name, sc->geom->name);

	logstor_check_and_run(sc);
	return (0);
}

/*
 * Check if everything's ready to create the geom provider & device entry,
 * create and start provider.
 * Called ultimately by .taste, from g_event thread
 */
static void
logstor_check_and_run(struct g_logstor_softc *sc)
{
	off_t off;
	size_t n, count;
	int index;
	int error;

	if (logstor_valid_components(sc) != sc->n_components)
		return;

	if (logstor_valid_components(sc) == 0) {
		/* This is actually a candidate for panic() */
		LOG_MSG(LVL_ERROR, "No valid components for %s?",
		    sc->provider->name);
		return;
	}

	sc->sectorsize = sc->components[0].gcons->provider->sectorsize;

	/* Initialise allocation map from the first consumer */
	sc->chunk_count = sc->virsize / sc->chunk_size;
	if (sc->chunk_count * (off_t)sc->chunk_size != sc->virsize) {
		LOG_MSG(LVL_WARNING, "Device %s truncated to %ju bytes",
		    sc->provider->name,
		    sc->chunk_count * (off_t)sc->chunk_size);
	}
	sc->map_size = sc->chunk_count * sizeof *(sc->map);
	/* The following allocation is in order of 4MB - 8MB */
	sc->map = malloc(sc->map_size, M_GLOGSTOR, M_WAITOK);
	KASSERT(sc->map != NULL, ("%s: Memory allocation error (%zu bytes) for %s",
	    __func__, sc->map_size, sc->provider->name));
	sc->map_sectors = sc->map_size / sc->sectorsize;

	count = 0;
	for (n = 0; n < sc->n_components; n++)
		count += sc->components[n].chunk_count;
	LOG_MSG(LVL_INFO, "Device %s has %zu physical chunks and %zu virtual "
	    "(%zu KB chunks)",
	    sc->geom->name, count, sc->chunk_count, sc->chunk_size / 1024);

	error = g_access(sc->components[0].gcons, 1, 0, 0);
	if (error != 0) {
		LOG_MSG(LVL_ERROR, "Cannot acquire read access for %s to "
		    "read allocation map for %s",
		    sc->components[0].gcons->provider->name,
		    sc->geom->name);
		return;
	}
	/* Read in the allocation map */
	LOG_MSG(LVL_DEBUG, "Reading map for %s from %s", sc->geom->name,
	    sc->components[0].gcons->provider->name);
	off = count = n = 0;
	while (count < sc->map_size) {
		struct g_logstor_map_entry *mapbuf;
		size_t bs;

		bs = MIN(maxphys, sc->map_size - count);
		if (bs % sc->sectorsize != 0) {
			/* Check for alignment errors */
			bs = rounddown(bs, sc->sectorsize);
			if (bs == 0)
				break;
			LOG_MSG(LVL_ERROR, "Trouble: map is not sector-aligned "
			    "for %s on %s", sc->geom->name,
			    sc->components[0].gcons->provider->name);
		}
		mapbuf = g_read_data(sc->components[0].gcons, off, bs, &error);
		if (mapbuf == NULL) {
			free(sc->map, M_GLOGSTOR);
			LOG_MSG(LVL_ERROR, "Error reading allocation map "
			    "for %s from %s (offset %ju) (error %d)",
			    sc->geom->name,
			    sc->components[0].gcons->provider->name,
			    off, error);
			return;
		}

		bcopy(mapbuf, &sc->map[n], bs);
		off += bs;
		count += bs;
		n += bs / sizeof *(sc->map);
		g_free(mapbuf);
	}
	g_access(sc->components[0].gcons, -1, 0, 0);
	LOG_MSG(LVL_DEBUG, "Read map for %s", sc->geom->name);

	/* find first component with allocatable chunks */
	index = -1;
	for (n = 0; n < sc->n_components; n++) {
		if (sc->components[n].chunk_next <
		    sc->components[n].chunk_count) {
			index = n;
			break;
		}
	}
	if (index == -1)
		/* not found? set it to the last component and handle it
		 * later */
		index = sc->n_components - 1;

	if (index >= sc->n_components - g_logstor_component_watermark - 1) {
		LOG_MSG(LVL_WARNING, "Device %s running out of components "
		    "(%d/%u: %s)", sc->geom->name,
		    index+1,
		    sc->n_components,
		    sc->components[index].gcons->provider->name);
	}
	sc->curr_component = index;

	if (sc->components[index].chunk_next >=
	    sc->components[index].chunk_count - g_logstor_chunk_watermark) {
		LOG_MSG(LVL_WARNING,
		    "Component %s of %s is running out of free space "
		    "(%u chunks left)",
		    sc->components[index].gcons->provider->name,
		    sc->geom->name, sc->components[index].chunk_count -
		    sc->components[index].chunk_next);
	}

	sc->me_per_sector = sc->sectorsize / sizeof *(sc->map);
	if (sc->sectorsize % sizeof *(sc->map) != 0) {
		LOG_MSG(LVL_ERROR,
		    "%s: Map entries don't fit exactly in a sector (%s)",
		    __func__, sc->geom->name);
		return;
	}

	/* Recalculate allocated chunks in components & at the same time
	 * verify map data is sane. We could trust metadata on this, but
	 * we want to make sure. */
	for (n = 0; n < sc->n_components; n++)
		sc->components[n].chunk_next = sc->components[n].chunk_reserved;

	for (n = 0; n < sc->chunk_count; n++) {
		if (sc->map[n].provider_no >= sc->n_components ||
			sc->map[n].provider_chunk >=
			sc->components[sc->map[n].provider_no].chunk_count) {
			LOG_MSG(LVL_ERROR, "%s: Invalid entry %u in map for %s",
			    __func__, (u_int)n, sc->geom->name);
			LOG_MSG(LVL_ERROR, "%s: provider_no: %u, n_components: %u"
			    " provider_chunk: %u, chunk_count: %u", __func__,
			    sc->map[n].provider_no, sc->n_components,
			    sc->map[n].provider_chunk,
			    sc->components[sc->map[n].provider_no].chunk_count);
			return;
		}
		if (sc->map[n].flags & LOGSTOR_MAP_ALLOCATED)
			sc->components[sc->map[n].provider_no].chunk_next++;
	}

	sc->provider = g_new_providerf(sc->geom, "logstor/%s",
	    sc->geom->name);

	sc->provider->sectorsize = sc->sectorsize;
	sc->provider->mediasize = sc->virsize;
	g_error_provider(sc->provider, 0);

	LOG_MSG(LVL_INFO, "%s activated", sc->provider->name);
	LOG_MSG(LVL_DEBUG, "%s starting with current component %u, starting "
	    "chunk %u", sc->provider->name, sc->curr_component,
	    sc->components[sc->curr_component].chunk_next);
}

/*
 * Returns count of active providers in this geom instance
 */
static u_int
logstor_valid_components(struct g_logstor_softc *sc)
{
	unsigned int nc, i;

	nc = 0;
	KASSERT(sc != NULL, ("%s: softc is NULL", __func__));
	KASSERT(sc->components != NULL, ("%s: sc->components is NULL", __func__));
	for (i = 0; i < sc->n_components; i++)
		if (sc->components[i].gcons != NULL)
			nc++;
	return (nc);
}

/*
 * Called when the consumer gets orphaned (?)
 */
static void
g_logstor_orphan(struct g_consumer *cp)
{
	struct g_logstor_softc *sc;
	struct g_logstor_component *comp;
	struct g_geom *gp;

	g_topology_assert();
	gp = cp->geom;
	sc = gp->softc;
	if (sc == NULL)
		return;

	comp = cp->private;
	KASSERT(comp != NULL, ("%s: No component in private part of consumer",
	    __func__));
	remove_component(sc, comp, FALSE);
	if (LIST_EMPTY(&gp->consumer))
		logstor_geom_destroy(sc, TRUE, FALSE);
}

/*
 * Called to notify geom when it's been opened, and for what intent
 */
static int
g_logstor_access(struct g_provider *pp, int dr, int dw, int de)
{
	struct g_consumer *c, *c2, *tmp;
	struct g_logstor_softc *sc;
	struct g_geom *gp;
	int error;

	KASSERT(pp != NULL, ("%s: NULL provider", __func__));
	gp = pp->geom;
	KASSERT(gp != NULL, ("%s: NULL geom", __func__));
	sc = gp->softc;

	/* Grab an exclusive bit to propagate on our consumers on first open */
	if (pp->acr == 0 && pp->acw == 0 && pp->ace == 0)
		de++;
	/* ... drop it on close */
	if (pp->acr + dr == 0 && pp->acw + dw == 0 && pp->ace + de == 0) {
		de--;
		if (sc != NULL)
			update_metadata(sc);
	}

	error = ENXIO;
	LIST_FOREACH_SAFE(c, &gp->consumer, consumer, tmp) {
		error = g_access(c, dr, dw, de);
		if (error != 0)
			goto fail;
		if (c->acr == 0 && c->acw == 0 && c->ace == 0 &&
		    c->flags & G_CF_ORPHAN) {
			g_detach(c);
			g_destroy_consumer(c);
		}
	}

	if (sc != NULL && LIST_EMPTY(&gp->consumer))
		logstor_geom_destroy(sc, TRUE, FALSE);

	return (error);

fail:
	/* Backout earlier changes */
	LIST_FOREACH(c2, &gp->consumer, consumer) {
		if (c2 == c)
			break;
		g_access(c2, -dr, -dw, -de);
	}
	return (error);
}

/*
 * Generate XML dump of current state
 */
static void
g_logstor_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
	struct g_logstor_softc *sc;

	g_topology_assert();
	sc = gp->softc;

	if (sc == NULL || pp != NULL)
		return;

	if (cp != NULL) {
		/* For each component */
		struct g_logstor_component *comp;

		comp = cp->private;
		if (comp == NULL)
			return;
		sbuf_printf(sb, "%s<ComponentIndex>%u</ComponentIndex>\n",
		    indent, comp->index);
		sbuf_printf(sb, "%s<ChunkCount>%u</ChunkCount>\n",
		    indent, comp->chunk_count);
		sbuf_printf(sb, "%s<ChunksUsed>%u</ChunksUsed>\n",
		    indent, comp->chunk_next);
		sbuf_printf(sb, "%s<ChunksReserved>%u</ChunksReserved>\n",
		    indent, comp->chunk_reserved);
		sbuf_printf(sb, "%s<StorageFree>%u%%</StorageFree>\n",
		    indent,
		    comp->chunk_next > 0 ? 100 -
		    ((comp->chunk_next + comp->chunk_reserved) * 100) /
		    comp->chunk_count : 100);
	} else {
		/* For the whole thing */
		u_int count, used, i;
		off_t size;

		count = used = size = 0;
		for (i = 0; i < sc->n_components; i++) {
			if (sc->components[i].gcons != NULL) {
				count += sc->components[i].chunk_count;
				used += sc->components[i].chunk_next +
				    sc->components[i].chunk_reserved;
				size += sc->components[i].gcons->
				    provider->mediasize;
			}
		}

		sbuf_printf(sb, "%s<Status>"
		    "Components=%u, Online=%u</Status>\n", indent,
		    sc->n_components, logstor_valid_components(sc));
		sbuf_printf(sb, "%s<State>%u%% physical free</State>\n",
		    indent, 100-(used * 100) / count);
		sbuf_printf(sb, "%s<ChunkSize>%zu</ChunkSize>\n", indent,
		    sc->chunk_size);
		sbuf_printf(sb, "%s<PhysicalFree>%u%%</PhysicalFree>\n",
		    indent, used > 0 ? 100 - (used * 100) / count : 100);
		sbuf_printf(sb, "%s<ChunkPhysicalCount>%u</ChunkPhysicalCount>\n",
		    indent, count);
		sbuf_printf(sb, "%s<ChunkVirtualCount>%zu</ChunkVirtualCount>\n",
		    indent, sc->chunk_count);
		sbuf_printf(sb, "%s<PhysicalBacking>%zu%%</PhysicalBacking>\n",
		    indent,
		    (count * 100) / sc->chunk_count);
		sbuf_printf(sb, "%s<PhysicalBackingSize>%jd</PhysicalBackingSize>\n",
		    indent, size);
		sbuf_printf(sb, "%s<VirtualSize>%jd</VirtualSize>\n", indent,
		    sc->virsize);
	}
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

	KASSERT(bp->bio_completed == SECTOR_SIZE);
	bp2 = bp->bio_parent;
	if (bp2->bio_error == 0)
		bp2->bio_error = bp->bio_error;
	bp2->bio_completed += bp->bio_completed;
	g_destroy_bio(bp);
	bp2->bio_inbed++;
	if (bp2->bio_completed == bp2->bio_length) {
		KASSERT(bp2->bio_children == bp2->bio_inbed, "");
		g_io_deliver(bp2, bp2->bio_error);
	}
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
	uint32_t (*logstor_access)(struct g_logstor_softc *sc, struct bio *bp);

	pp = bp->bio_to;
	sc = pp->geom->softc;
	KASSERT(sc != NULL, ("%s: no softc (error=%d, device=%s)", __func__,
	    bp->bio_to->error, bp->bio_to->name));

	LOG_REQ(LVL_MOREDEBUG, bp, "%s", __func__);

	switch (bp->bio_cmd) {
	case BIO_READ:
		logstor_access = logstor_read;
		break;
	case BIO_WRITE:
		logstor_access = logstor_write;
		break;
	case BIO_DELETE:
		KASSERT(false, "not implemented yet");
		return;
	default:
		g_io_deliver(bp, EOPNOTSUPP);
		return;
	}

	LOG_MSG(LVL_DEBUG2, "BIO arrived, size=%ju", bp->bio_length);

	KASSERT(bp->bio_offset % SECTOR_SIZE == 0, "");
	KASSERT(bp->bio_length % SECTOR_SIZE == 0, "");
	int sec_cnt = bp->bio_length / SECTOR_SIZE;

	for (int i = 0; i < sec_cnt; ++i) {
		struct bio *cb = g_clone_bio(bp);
		if (cb == NULL) {
			if (bp->bio_error == 0)
				bp->bio_error = ENOMEM;
			g_io_deliver(bp, bp->bio_error);
			return;
		}
		cb->bio_to = sc->provider;
		cb->bio_done = g_logstor_done;
		cb->bio_offset = bp->bio_offset + i * SECTOR_SIZE;
		cb->bio_length = SECTOR_SIZE;
		cb->bio_data = bp->bio_data + i * SECTOR_SIZE;
		logstor_access(sc, cb);
	}

//=========================
	struct g_logstor_component *comp;
	struct bio *cb;
	char *addr;
	off_t offset, length;
	struct bio_queue_head bq;
	size_t chunk_size;	/* cached for convenience */
	u_int count;
	struct bio *b = bp;

	bioq_init(&bq);

	chunk_size = sc->chunk_size;
	addr = b->bio_data;
	offset = b->bio_offset;	/* virtual offset and length */
	length = b->bio_length;

	while (length > 0) {
		size_t chunk_index, in_chunk_offset, in_chunk_length;
		struct logstor_map_entry *me;

		chunk_index = offset / chunk_size; /* round downwards */
		in_chunk_offset = offset % chunk_size;
		in_chunk_length = min(length, chunk_size - in_chunk_offset);
		LOG_MSG(LVL_DEBUG, "Mapped %s(%ju, %ju) to (%zu,%zu,%zu)",
		    b->bio_cmd == BIO_READ ? "R" : "W",
		    offset, length,
		    chunk_index, in_chunk_offset, in_chunk_length);
		me = &sc->map[chunk_index];

		if (b->bio_cmd == BIO_READ || b->bio_cmd == BIO_DELETE) {
			if ((me->flags & LOGSTOR_MAP_ALLOCATED) == 0) {
				/* Reads from unallocated chunks return zeroed
				 * buffers */
				if (b->bio_cmd == BIO_READ)
					bzero(addr, in_chunk_length);
			} else {
				comp = &sc->components[me->provider_no];

				cb = g_clone_bio(b);
				if (cb == NULL) {
					bioq_dismantle(&bq);
					if (b->bio_error == 0)
						b->bio_error = ENOMEM;
					g_io_deliver(b, b->bio_error);
					return;
				}
				cb->bio_to = comp->gcons->provider;
				cb->bio_done = g_logstor_done;
				cb->bio_offset =
				    (off_t)me->provider_chunk * (off_t)chunk_size
				    + in_chunk_offset;
				cb->bio_length = in_chunk_length;
				cb->bio_data = addr;
				cb->bio_caller1 = comp;
				bioq_disksort(&bq, cb);
			}
		} else { /* handle BIO_WRITE */
			KASSERT(b->bio_cmd == BIO_WRITE,
			    ("%s: Unknown command %d", __func__,
			    b->bio_cmd));

			if ((me->flags & LOGSTOR_MAP_ALLOCATED) == 0) {
				/* We have a virtual chunk, represented by
				 * the "me" entry, but it's not yet allocated
				 * (tied to) a physical chunk. So do it now. */
				struct logstor_map_entry *data_me;
				u_int phys_chunk, comp_no;
				off_t s_offset;
				int error;

				error = allocate_chunk(sc, &comp, &comp_no,
				    &phys_chunk);
				if (error != 0) {
					/* We cannot allocate a physical chunk
					 * to satisfy this request, so we'll
					 * delay it to when we can...
					 * XXX: this will prevent the fs from
					 * being umounted! */
					struct g_logstor_bio_q *biq;
					biq = malloc(sizeof *biq, M_GLOGSTOR,
					    M_NOWAIT);
					if (biq == NULL) {
						bioq_dismantle(&bq);
						if (b->bio_error == 0)
							b->bio_error = ENOMEM;
						g_io_deliver(b, b->bio_error);
						return;
					}
					biq->bio = b;
					mtx_lock(&sc->delayed_bio_q_mtx);
					STAILQ_INSERT_TAIL(&sc->delayed_bio_q,
					    biq, linkage);
					mtx_unlock(&sc->delayed_bio_q_mtx);
					LOG_MSG(LVL_WARNING, "Delaying BIO "
					    "(size=%ju) until free physical "
					    "space can be found on %s",
					    b->bio_length,
					    sc->provider->name);
					return;
				}
				LOG_MSG(LVL_DEBUG, "Allocated chunk %u on %s "
				    "for %s",
				    phys_chunk,
				    comp->gcons->provider->name,
				    sc->provider->name);

				me->provider_no = comp_no;
				me->provider_chunk = phys_chunk;
				me->flags |= LOGSTOR_MAP_ALLOCATED;

				cb = g_clone_bio(b);
				if (cb == NULL) {
					me->flags &= ~LOGSTOR_MAP_ALLOCATED;
					me->provider_no = 0;
					me->provider_chunk = 0;
					bioq_dismantle(&bq);
					if (b->bio_error == 0)
						b->bio_error = ENOMEM;
					g_io_deliver(b, b->bio_error);
					return;
				}

				/* The allocation table is stored continuously
				 * at the start of the drive. We need to
				 * calculate the offset of the sector that holds
				 * this map entry both on the drive and in the
				 * map array.
				 * sc_offset will end up pointing to the drive
				 * sector. */
				s_offset = chunk_index * sizeof *me;
				s_offset = rounddown(s_offset, sc->sectorsize);

				/* data_me points to map entry sector
				 * in memory (analogous to offset) */
				data_me = &sc->map[rounddown(chunk_index,
				    sc->me_per_sector)];

				/* Commit sector with map entry to storage */
				cb->bio_to = sc->components[0].gcons->provider;
				cb->bio_done = g_logstor_done;
				cb->bio_offset = s_offset;
				cb->bio_data = (char *)data_me;
				cb->bio_length = sc->sectorsize;
				cb->bio_caller1 = &sc->components[0];
				bioq_disksort(&bq, cb);
			} // (me->flags & LOGSTOR_MAP_ALLOCATED) == 0

			comp = &sc->components[me->provider_no];
			cb = g_clone_bio(b);
			if (cb == NULL) {
				bioq_dismantle(&bq);
				if (b->bio_error == 0)
					b->bio_error = ENOMEM;
				g_io_deliver(b, b->bio_error);
				return;
			}
			/* Finally, handle the data */
			cb->bio_to = comp->gcons->provider;
			cb->bio_done = g_logstor_done;
			cb->bio_offset = (off_t)me->provider_chunk*(off_t)chunk_size +
			    in_chunk_offset;
			cb->bio_length = in_chunk_length;
			cb->bio_data = addr;
			cb->bio_caller1 = comp;
			bioq_disksort(&bq, cb);
		} /* handle BIO_WRITE */
		addr += in_chunk_length;
		length -= in_chunk_length;
		offset += in_chunk_length;
	} // while

	/* Fire off bio's here */
	count = 0;
	for (cb = bioq_first(&bq); cb != NULL; cb = bioq_first(&bq)) {
		bioq_remove(&bq, cb);
		LOG_REQ(LVL_MOREDEBUG, cb, "Firing request");
		comp = cb->bio_caller1;
		cb->bio_caller1 = NULL;
		LOG_MSG(LVL_DEBUG, " firing bio, offset=%ju, length=%ju",
		    cb->bio_offset, cb->bio_length);
		g_io_request(cb, comp->gcons);
		count++;
	}
	if (count == 0) { /* We handled everything locally */
		b->bio_completed = b->bio_length;
		g_io_deliver(b, 0);
	}

}

/*
 * Allocate a chunk from a physical provider. Returns physical component,
 * chunk index relative to the component and the component's index.
 */
static int
allocate_chunk(struct g_logstor_softc *sc, struct g_logstor_component **comp,
    u_int *comp_no_p, u_int *chunk)
{
	u_int comp_no;

	KASSERT(sc->curr_component < sc->n_components,
	    ("%s: Invalid curr_component: %u",  __func__, sc->curr_component));

	comp_no = sc->curr_component;
	*comp = &sc->components[comp_no];
	dump_component(*comp);
	if ((*comp)->chunk_next >= (*comp)->chunk_count) {
		/* This component is full. Allocate next component */
		if (comp_no >= sc->n_components-1) {
			LOG_MSG(LVL_ERROR, "All physical space allocated for %s",
			    sc->geom->name);
			return (-1);
		}
		(*comp)->flags &= ~LOGSTOR_PROVIDER_CURRENT;
		sc->curr_component = ++comp_no;

		*comp = &sc->components[comp_no];
		if (comp_no >= sc->n_components - g_logstor_component_watermark-1)
			LOG_MSG(LVL_WARNING, "Device %s running out of components "
			    "(switching to %u/%u: %s)", sc->geom->name,
			    comp_no+1, sc->n_components,
			    (*comp)->gcons->provider->name);
		/* Take care not to overwrite reserved chunks */
		if ( (*comp)->chunk_reserved > 0 &&
		    (*comp)->chunk_next < (*comp)->chunk_reserved)
			(*comp)->chunk_next = (*comp)->chunk_reserved;

		(*comp)->flags |=
		    LOGSTOR_PROVIDER_ALLOCATED | LOGSTOR_PROVIDER_CURRENT;
		dump_component(*comp);
		*comp_no_p = comp_no;
		*chunk = (*comp)->chunk_next++;
	} else {
		*comp_no_p = comp_no;
		*chunk = (*comp)->chunk_next++;
	}
	return (0);
}

/* Dump a component */
static void
dump_component(struct g_logstor_component *comp)
{

	if (g_logstor_debug < LVL_DEBUG2)
		return;
	printf("Component %d: %s\n", comp->index, comp->gcons->provider->name);
	printf("  chunk_count: %u\n", comp->chunk_count);
	printf("   chunk_next: %u\n", comp->chunk_next);
	printf("        flags: %u\n", comp->flags);
}

#if 0
/* Dump a map entry */
static void
dump_me(struct logstor_map_entry *me, unsigned int nr)
{
	if (g_logstor_debug < LVL_DEBUG)
		return;
	printf("VIRT. CHUNK #%d: ", nr);
	if ((me->flags & LOGSTOR_MAP_ALLOCATED) == 0)
		printf("(unallocated)\n");
	else
		printf("allocated at provider %u, provider_chunk %u\n",
		    me->provider_no, me->provider_chunk);
}
#endif

/*
 * Dismantle bio_queue and destroy its components
 */
static void
bioq_dismantle(struct bio_queue_head *bq)
{
	struct bio *b;

	for (b = bioq_first(bq); b != NULL; b = bioq_first(bq)) {
		bioq_remove(bq, b);
		g_destroy_bio(b);
	}
}

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
	panic("invalid_call() has just been called. Something's fishy here.");
}

//=========================
static int
logstor_read_data(struct g_consumer *cp, off_t offset, void *ptr, off_t length)
{
	struct bio *bp;
	int errorc;

	KASSERT(length > 0 && length >= cp->provider->sectorsize &&
	    length <= maxphys, ("g_read_data(): invalid length %jd",
	    (intmax_t)length));

	bp = g_alloc_bio();
	bp->bio_cmd = BIO_READ;
	bp->bio_done = NULL;
	bp->bio_offset = offset;
	bp->bio_length = length;
	bp->bio_data = ptr;
	g_io_request(bp, cp);
	errorc = biowait(bp, "gread");
	if (errorc == 0 && bp->bio_completed != length)
		errorc = EIO;
	g_destroy_bio(bp);

	return errorc;
}

#if defined(RAM_DISK_SIZE)
static off_t
get_mediasize(int fd)
{
	return RAM_DISK_SIZE;
}
#endif
/*******************************
 *        logstor              *
 *******************************/

/*
Description:
    segment address to sector address
*/
static uint32_t
sega2sa(uint32_t sega)
{
	return sega << SA2SEGA_SHIFT;
}

/*
Return the max number of blocks for this disk
*/
uint32_t logstor_init(struct g_logstor_softc *sc)
{
	int disk_fd;

#if defined(RAM_DISK_SIZE)
	ram_disk = malloc(RAM_DISK_SIZE);
	KASSERT(ram_disk != NULL, "");
	disk_fd = -1;
#endif
	return disk_init(sc, disk_fd);
}

void
logstor_fini(struct g_logstor_softc *sc)
{
#if defined(RAM_DISK_SIZE)
	free(ram_disk);
#endif
}

int
logstor_open(struct g_logstor_softc *sc, const char *disk_file)
{
	bzero(sc, sizeof(*sc));
	int error __unused;

	error = superblock_read(sc);
	KASSERT(error == 0, "");
	sc->sb_modified = false;

	// read the segment summary block
	KASSERT(sc->superblock.seg_alloc >= SEG_DATA_START, "");
	sc->seg_alloc_sa = sega2sa(sc->superblock.seg_alloc);
	uint32_t sa = sc->seg_alloc_sa + SEG_SUM_OFFSET;
	md_read(sc, sa, &sc->seg_sum);
	KASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET, "");
	sc->ss_modified = false;
	sc->data_write_count = sc->other_write_count = 0;

	fbuf_mod_init(sc);

	return 0;
}

void
logstor_close(struct g_logstor_softc *sc)
{

	fbuf_mod_fini(sc);
	seg_sum_write(sc);
	superblock_write(sc);
}

uint32_t
logstor_read(struct g_logstor_softc *sc, struct bio *bp)
{
	fbuf_clean_queue_check(sc);
	uint32_t sa = _logstor_read(sc, bp);
	return sa;
}

uint32_t
logstor_write(struct g_logstor_softc *sc, struct bio *bp)
{
	fbuf_clean_queue_check(sc);
	uint32_t sa = _logstor_write(sc, bp, 0, NULL);
	return sa;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
int logstor_delete(struct g_logstor_softc *sc, off_t offset, void *data __unused, off_t length)
{
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process
	int i;

	KASSERT((offset & (SECTOR_SIZE - 1)) == 0, "");
	KASSERT((length & (SECTOR_SIZE - 1)) == 0, "");
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;
	KASSERT(ba < sc->superblock.block_cnt_max, "");

	for (i = 0; i < size; ++i) {
		fbuf_clean_queue_check(sc);
		file_write_4byte(sc, sc->superblock.fd_cur, ba + i, SECTOR_DEL);
	}

	return (0);
}

void
logstor_commit(struct g_logstor_softc *sc)
{
	// lock metadata
	// move fd_cur to fd_prev
	sc->superblock.fd_prev = sc->superblock.fd_cur;
	// create new files fd_cur and fd_snap_new
	// fc_cur is either 0 or 2 and fd_snap always follows fd_cur
	sc->superblock.fd_cur = sc->superblock.fd_cur ^ 2;
	sc->superblock.fd_snap_new = sc->superblock.fd_cur + 1;
	sc->superblock.fd_root[sc->superblock.fd_cur] = SECTOR_NULL;
	sc->superblock.fd_root[sc->superblock.fd_snap_new] = SECTOR_NULL;

	is_sec_valid_fp = is_sec_valid_during_commit;
	logstor_ba2sa_fp = logstor_ba2sa_during_commit;
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
	superblock_write(sc);

	is_sec_valid_fp = is_sec_valid_normal;
	logstor_ba2sa_fp = logstor_ba2sa_normal;
	//unlock metadata
}

uint32_t
_logstor_read(struct g_logstor_softc *sc, struct bio *bp)
{
	uint32_t ba;	// block address
	uint32_t sa;	// sector address

	uint32_t ba = bp->bio_offset / SECTOR_SIZE;
	KASSERT(ba < sc->superblock.block_cnt_max, "");

	sa = logstor_ba2sa_fp(sc, ba);
#if defined(WYC)
	logstor_ba2sa_normal();
	logstor_ba2sa_during_commit();
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
		KASSERT(sa >= SECTORS_PER_SEG, "");
		bp->bio_offset = sa * SECTOR_SIZE;
		g_io_request(bp, sc->consumer);
	}
	return sa;
}

// The common part of is_sec_valid
static bool
is_sec_valid_comm(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev, uint8_t fd[], int fd_cnt)
{
	uint32_t sa_rev; // the sector address for ba_rev

	KASSERT(ba_rev < BLOCK_MAX, "");
	for (int i = 0; i < fd_cnt; ++i) {
		uint8_t _fd = fd[i];
		sa_rev = file_read_4byte(sc, _fd, ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

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
		return is_sec_valid_fp(sc, sa, ba_rev);
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
		MY_PANIC();
		return false;
	}
}

/*
Description:
  write data/metadata block to disk

Return:
  the sector address where the data is written
*/
static uint32_t
_logstor_write(struct g_logstor_softc *sc, struct bio *bp, uint32_t ba, void *data)
{
	static bool is_called = false;
	struct _seg_sum *seg_sum = &sc->seg_sum;

	KASSERT(sc->seg_alloc_sa >= SECTORS_PER_SEG, "");
	if (bp) {
		ba = bp->bio_offset / SECTOR_SIZE;
		KASSERT(ba < sc->superblock.block_cnt_max, "");
		data = bp->bio_data;
	} else {
		KASSERT(IS_META_ADDR(ba), "");
	}
	if (is_called) // recursive call is not allowed
		exit(1);
	is_called = true;

	// record the starting segment
	// if the search for free sector rolls over to the starting segment
	// it means that there is no free sector in this disk
	sc->seg_alloc_start = sc->superblock.seg_alloc;
again:
	for (int i = seg_sum->ss_allocp; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t sa = sc->seg_alloc_sa + i;
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map

		if (is_sec_valid(sa, ba_rev))
			continue;

		if (bp) {
			bp->bio_offset = sa * SECTOR_SIZE;
			g_io_request(bp, sc->consumer);
		} else { // metadata
			md_write(sc, sa, data);
		}
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		sc->ss_modified = true;
		seg_sum->ss_allocp = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_allocp == SEG_SUM_OFFSET)
			_seg_alloc(sc);

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
	_seg_alloc(sc);
	goto again;
}

static uint32_t
logstor_ba2sa_comm(uint32_t ba, uint8_t fd[], int fd_cnt)
{
	uint32_t sa;

	KASSERT(ba < BLOCK_MAX, "");
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
logstor_ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return logstor_ba2sa_comm(ba, fd, NUM_OF_ELEMS(fd));
}

/*
Description:
    Block address to sector address translation in commit state
*/
static uint32_t __unused
logstor_ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return logstor_ba2sa_comm(ba, fd, NUM_OF_ELEMS(fd));
}

uint32_t
logstor_get_block_cnt(struct g_logstor_softc *sc)
{
	return sc->superblock.block_cnt_max;
}

unsigned
logstor_get_data_write_count(struct g_logstor_softc *sc)
{
	return sc->data_write_count;
}

unsigned
logstor_get_other_write_count(struct g_logstor_softc *sc)
{
	return sc->other_write_count;
}

unsigned
logstor_get_fbuf_hit(struct g_logstor_softc *sc)
{
	return sc->fbuf_hit;
}

unsigned
logstor_get_fbuf_miss(struct g_logstor_softc *sc)
{
	return sc->fbuf_miss;
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
	KASSERT(sc->seg_alloc_sa >= SECTORS_PER_SEG, "");
	sa = sc->seg_alloc_sa + SEG_SUM_OFFSET;
	md_write(sc, sa, (void *)&sc->seg_sum);
	sc->ss_modified = false;
	sc->other_write_count++; // the write for the segment summary
}

/*
Description:
    Write the initialized supeblock to the downstream disk

Return:
    The max number of blocks for this disk
*/
static uint32_t
disk_init(struct g_logstor_softc *sc, int fd)
{
	int32_t seg_cnt;
	uint32_t sector_cnt;
	struct _superblock *sb;
	off_t media_size;
	char buf[SECTOR_SIZE] __attribute__ ((aligned));

	media_size = get_mediasize(fd);
	sector_cnt = media_size / SECTOR_SIZE;

	sb = (struct _superblock *)buf;
	sb->sig = SIG_LOGSTOR;
	sb->ver_major = VER_MAJOR;
	sb->ver_minor = VER_MINOR;
#if __BSD_VISIBLE
	sb->sb_gen = arc4random();
#else
	sb->sb_gen = random();
#endif
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	if (sizeof(struct _superblock) + sb->seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct _superblock), (int)sb->seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct _superblock)) * (long long)SEG_SIZE);
		MY_PANIC();
	}
	seg_cnt = sb->seg_cnt;
	uint32_t max_block =
	    (seg_cnt - SEG_DATA_START) * BLOCKS_PER_SEG -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT * 4;
	KASSERT(max_block < 0x40000000, ""); // 1G
	sb->block_cnt_max = max_block;

	sb->seg_alloc = SEG_DATA_START;	// start allocate from here

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
#if defined(RAM_DISK_SIZE)
	memcpy(ram_disk, sb, SECTOR_SIZE);
#endif

	// clear the rest of the supeblock's segment
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SECTORS_PER_SEG; i++) {
#if defined(RAM_DISK_SIZE)
		memcpy(ram_disk + i * SECTOR_SIZE, buf, SECTOR_SIZE);
#endif
	}
	struct _seg_sum ss;
	for (int i = 0; i < SECTORS_PER_SEG - 1; ++i)
		ss.ss_rm[i] = BLOCK_INVALID;
	sc->superblock.seg_cnt = seg_cnt; // to silence the assert fail in md_write
	// initialize all segment summary blocks
	for (int i = SEG_DATA_START; i < seg_cnt; ++i)
	{	uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		md_write(sc, sa, &ss);
	}
	return max_block;
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
static int
superblock_read(struct g_logstor_softc *sc)
{
	int	i;
	uint16_t sb_gen;
	struct _superblock *sb;
	char buf[2][SECTOR_SIZE];

	_Static_assert(sizeof(sb_gen) == sizeof(sc->superblock.sb_gen), "sb_gen");

	// get the superblock
	sb = (struct _superblock *)buf[0];
#if defined(RAM_DISK_SIZE)
	memcpy(sb, ram_disk, SECTOR_SIZE);
#endif
	if (sb->sig != SIG_LOGSTOR ||
	    sb->seg_alloc >= sb->seg_cnt)
		return EINVAL;

	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SECTORS_PER_SEG; i++) {
		sb = (struct _superblock *)buf[i%2];
#if defined(RAM_DISK_SIZE)
		memcpy(sb, ram_disk + i * SECTOR_SIZE, SECTOR_SIZE);
#endif
		if (sb->sig != SIG_LOGSTOR)
			break;
		if (sb->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	sc->sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2];
	if (sb->seg_alloc >= sb->seg_cnt)
		return EINVAL;

	for (i=0; i<FD_COUNT; ++i)
		if (sb->fd_root[i] == SECTOR_CACHE)
			sb->fd_root[i] = SECTOR_NULL;
	memcpy(&sc->superblock, sb, sizeof(sc->superblock));

	return 0;
}

static void
superblock_write(struct g_logstor_softc *sc)
{
	size_t sb_size = sizeof(sc->superblock);
	char buf[SECTOR_SIZE];

	//if (!sc->sb_modified)
	//	return;

	for (int i = 0; i < 4; ++i) {
		KASSERT(sc->superblock.fd_root[i] != SECTOR_CACHE, "");
	}
	sc->superblock.sb_gen++;
	if (++sc->sb_sa == SECTORS_PER_SEG)
		sc->sb_sa = 0;
	memcpy(buf, &sc->superblock, sb_size);
	memset(buf + sb_size, 0, SECTOR_SIZE - sb_size);
	md_write(sc, sc->sb_sa, buf);
	sc->sb_modified = false;
	sc->other_write_count++;
}

static int
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
md_read(struct g_logstor_softc *sc, uint32_t sa, void *buf)
{
	int rc;

	KASSERT(sa < sc->superblock.seg_cnt * SECTORS_PER_SEG, "");
	rc = _g_read_data(sc->consumr, sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	KASSERT(rc == 0, "");
}

static void
md_write(struct g_logstor_softc *sc, uint32_t sa, const void *buf)
{
	int rc;

	KASSERT(sa < sc->superblock.seg_cnt * SECTORS_PER_SEG, "");
	rc = g_write_data(sc->consumer, sa * SECTOR_SIZE, buf, SECTOR_SIZE);
	KASSERT(rc == 0, "");
}

/*
Description:
  Allocate a segment for writing

Output:
  Store the segment address into @seg_sum->sega
  Initialize @seg_sum->sum.alloc_p to 0
*/
static void
_seg_alloc(struct g_logstor_softc *sc)
{
	// write the previous segment summary to disk if it has been modified
	seg_sum_write(sc);

	KASSERT(sc->superblock.seg_alloc < sc->superblock.seg_cnt, "");
	if (++sc->superblock.seg_alloc == sc->superblock.seg_cnt)
		sc->superblock.seg_alloc = SEG_DATA_START;
	if (sc->superblock.seg_alloc == sc->seg_alloc_start)
		// has accessed all the segment summary blocks
		MY_PANIC();
	sc->seg_alloc_sa = sega2sa(sc->superblock.seg_alloc);
	md_read(sc, sc->seg_alloc_sa + SEG_SUM_OFFSET, &sc->seg_sum);
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

	KASSERT(fd < FD_COUNT, "");

	// the initialized reverse map in the segment summary is BLOCK_MAX
	// so it is possible that a caller might pass a ba that is BLOCK_MAX
	if (ba >= BLOCK_MAX) {
		KASSERT(ba == BLOCK_INVALID, "");
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

	KASSERT(fd < FD_COUNT, "");
	KASSERT(ba < BLOCK_MAX, "");
	KASSERT(sc->superblock.fd_root[fd] != SECTOR_DEL, "");

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
	KASSERT(fbuf != NULL, "");
	fbuf->data[off_4byte] = sa;
	if (!fbuf->fc.modified) {
		// move to QUEUE_LEAF_DIRTY
		KASSERT(fbuf->queue_which == QUEUE_LEAF_CLEAN, "");
		fbuf->fc.modified = true;
		if (fbuf == sc->fbuf_allocp)
			sc->fbuf_allocp = fbuf->fc.queue_next;
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, QUEUE_LEAF_DIRTY, fbuf);
	} else
		KASSERT(fbuf->queue_which == QUEUE_LEAF_DIRTY, "");
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

static unsigned
ma_index_get(union meta_addr ma, unsigned depth)
{
	unsigned index;

	switch (depth) {
	case 0:
		index = ma.index0;
		break;
	case 1:
		index = ma.index1;
		break;
	default:
		MY_PANIC();
	}
	return (index);
}

static union meta_addr
ma_index_set(union meta_addr ma, unsigned depth, unsigned index)
{
	KASSERT(index < 1024, "");

	switch (depth) {
	case 0:
		ma.index0 = index;
		break;
	case 1:
		ma.index1 = index;
		break;
	default:
		MY_PANIC();
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
		MY_PANIC();
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
			KASSERT(parent != NULL, "");
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
	sc->fbufs = malloc(fbuf_count * sizeof(*sc->fbufs));
	KASSERT(sc->fbufs != NULL, "");

	for (i = 0; i < FBUF_BUCKET_CNT; ++i) {
		fbuf_bucket_init(sc, i);
	}
	for (i = 0; i < QUEUE_CNT; ++i) {
		fbuf_queue_init(sc, i);
	}
	// insert fbuf to both QUEUE_LEAF_CLEAN and hash queue
	for (i = 0; i < fbuf_count; ++i) {
		struct _fbuf *fbuf = &sc->fbufs[i];
		fbuf->fc.is_sentinel = false;
		fbuf->fc.accessed = false;
		fbuf->fc.modified = false;
		fbuf_queue_insert_tail(sc, QUEUE_LEAF_CLEAN, fbuf);
		// insert fbuf to the last fbuf bucket
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

static void
fbuf_mod_fini(struct g_logstor_softc *sc)
{
	fbuf_cache_flush(sc);
	free(sc->fbufs);
}

static inline bool
is_queue_empty(struct _fbuf_sentinel *sentinel)
{
	if (sentinel->fc.queue_next == (struct _fbuf *)sentinel) {
		KASSERT(sentinel->fc.queue_prev == (struct _fbuf *)sentinel, "");
		return true;
	}
	return false;
}

static inline void
queue_init(struct _fbuf_sentinel *sentinel)
{
	sentinel->fc.queue_next = (struct _fbuf *)sentinel;
	sentinel->fc.queue_prev = (struct _fbuf *)sentinel;
}

static void
fbuf_clean_queue_check(struct g_logstor_softc *sc)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;

	if (sc->fbuf_queue_len[QUEUE_LEAF_CLEAN] > FBUF_CLEAN_THRESHOLD)
		return;

	fbuf_cache_flush(sc);
	// move all parent nodes with child_cnt 0 to clean queue and last bucket
	for (int i = QUEUE_IND1; i >= QUEUE_IND0; --i) {
		queue_sentinel = &sc->fbuf_queue[i];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			KASSERT(fbuf->queue_which == i, "");
			struct _fbuf *fbuf_next = fbuf->fc.queue_next;
			if (fbuf->child_cnt == 0) {
				fbuf_queue_remove(sc, fbuf);
				fbuf->fc.accessed = false; // so that it can be replaced faster
				fbuf_queue_insert_tail(sc, QUEUE_LEAF_CLEAN, fbuf);
				if (fbuf->parent) {
					KASSERT(i == QUEUE_IND1, "");
					struct _fbuf *parent = fbuf->parent;
					--parent->child_cnt;
					KASSERT(parent->child_cnt <= SECTOR_SIZE/4, "");
					fbuf->parent = NULL;
				}
				// move it to the last bucket so that it cannot be searched
				// fbufs on the last bucket will have the metadata address META_INVALID
				fbuf_bucket_remove(sc, fbuf);
				KASSERT(fbuf->parent == NULL, "");
				KASSERT(fbuf->child_cnt == 0, "");
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
		KASSERT(fbuf->queue_which == QUEUE_LEAF_DIRTY, "");
		KASSERT(IS_META_ADDR(fbuf->ma.uint32), "");
		KASSERT(fbuf->fc.modified, "");
		// for dirty leaf nodes it's always dirty
		fbuf_write(sc, fbuf);
		fbuf = fbuf->fc.queue_next;
	}

	// write back all the modified internal nodes to disk
	for (i = QUEUE_IND1; i >= 0; --i) {
		queue_sentinel = &sc->fbuf_queue[i];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			KASSERT(fbuf->queue_which == i, "");
			KASSERT(IS_META_ADDR(fbuf->ma.uint32), "");
			// for non-leaf nodes the fbuf might not be modified
			if (__predict_true(fbuf->fc.modified))
				fbuf_write(sc, fbuf);
			fbuf = fbuf->fc.queue_next;
		}
	}
	seg_sum_write(sc);
	superblock_write(sc);

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
	sc->fbuf_queue_len[QUEUE_LEAF_DIRTY] = 0;
	queue_init(dirty_sentinel);
	// don't need to change clean queue's head
}

// flush the cache and invalid fbufs with file descriptors fd1 or fd2
static void
fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2)
{
	struct _fbuf *fbuf;

	fbuf_cache_flush(sc);
	for (int i = 0; i < sc->fbuf_count; ++i)
	{
		fbuf = &sc->fbufs[i];
		KASSERT(!fbuf->fc.modified, "");
		if (fbuf->ma.uint32 == META_INVALID) {
			// the fbufs with metadata address META_INVALID are
			// linked in bucket FBUF_BUCKET_LAST
			KASSERT(fbuf->bucket_which == FBUF_BUCKET_LAST, "");
			continue;
		}
		// move fbufs with fd equals to fd1 or fd2 to the last bucket
		if (fbuf->ma.fd == fd1 || fbuf->ma.fd == fd2) {
			KASSERT(fbuf->bucket_which != FBUF_BUCKET_LAST, "");
			fbuf_bucket_remove(sc, fbuf);
			// init parent, child_cnt and ma before inserting to bucket FBUF_BUCKET_LAST
			fbuf->parent = NULL;
			fbuf->child_cnt = 0;
			fbuf->ma.uint32 = META_INVALID;
			fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			fbuf->fc.accessed = false; // so it will be recycled sooner
			if (fbuf->queue_which != QUEUE_LEAF_CLEAN) {
				// it is an internal node, move it to QUEUE_LEAF_CLEAN
				KASSERT(fbuf->queue_which != QUEUE_LEAF_DIRTY, "");
				fbuf_queue_remove(sc, fbuf);
				fbuf_queue_insert_tail(sc, QUEUE_LEAF_CLEAN, fbuf);
			}
		}
	}
}

static void
fbuf_queue_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf *fbuf;

	KASSERT(which < QUEUE_CNT, "");
	sc->fbuf_queue_len[which] = 0;
	fbuf = (struct _fbuf *)&sc->fbuf_queue[which];
	fbuf->fc.queue_next = fbuf;
	fbuf->fc.queue_prev = fbuf;
	fbuf->fc.is_sentinel = true;
	fbuf->fc.accessed = true;
	fbuf->fc.modified = false;
}

static void
fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *queue_head;
	struct _fbuf *prev;

	KASSERT(which < QUEUE_CNT, "");
	KASSERT(which != QUEUE_LEAF_CLEAN || !fbuf->fc.modified, "");
	fbuf->queue_which = which;
	queue_head = &sc->fbuf_queue[which];
	prev = queue_head->fc.queue_prev;
	KASSERT(prev->fc.is_sentinel || prev->queue_which == which, "");
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

	KASSERT(fbuf != (struct _fbuf *)&sc->fbuf_queue[which], "");
	prev = fbuf->fc.queue_prev;
	next = fbuf->fc.queue_next;
	KASSERT(prev->fc.is_sentinel || prev->queue_which == which, "");
	KASSERT(next->fc.is_sentinel || next->queue_which == which, "");
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

	KASSERT(!fbuf->fc.is_sentinel, "");
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
		KASSERT(fbuf != (struct _fbuf *)queue_sentinel, "");
		goto again;
	}

	KASSERT(!fbuf->fc.modified, "");
	KASSERT(fbuf->child_cnt == 0, "");
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
		KASSERT(parent->child_cnt <= SECTOR_SIZE/4, "");
		KASSERT(parent->queue_which == parent->ma.depth, "");
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

	KASSERT(IS_META_ADDR(ma.uint32), "");
	KASSERT(ma.depth <= META_LEAF_DEPTH, "");

	// get the root sector address of the file %ma.fd
	sa = sc->superblock.fd_root[ma.fd];
	KASSERT(sa != SECTOR_DEL, "");

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
				KASSERT(parent->child_cnt <= SECTOR_SIZE/4, "");
			} else {
				KASSERT(i == 0, "");
			}
			if (sa == SECTOR_NULL) {
				bzero(fbuf->data, sizeof(fbuf->data));
				if (i == 0)
					sc->superblock.fd_root[ma.fd] = SECTOR_CACHE;
			} else {
				KASSERT(sa >= SECTORS_PER_SEG, "");
				md_read(sc, sa, fbuf->data);
			}
		} else {
			KASSERT(fbuf->parent == parent, "");
			KASSERT(fbuf->sa == sa ||
				(i == 0 && sa == SECTOR_CACHE), "");
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

	KASSERT(fbuf->fc.modified, "");
	sa = _logstor_write(sc, NULL, fbuf->ma.uint32, fbuf->data);
	fbuf->fc.modified = false;

	// update the sector address of this fbuf in its parent's fbuf
	parent = fbuf->parent;
	if (parent) {
		KASSERT(fbuf->ma.depth != 0, "");
		KASSERT(parent->ma.depth == fbuf->ma.depth - 1, "");
		pindex = ma_index_get(fbuf->ma, fbuf->ma.depth - 1);
		parent->data[pindex] = sa;
		parent->fc.modified = true;
	} else {
		KASSERT(fbuf->ma.depth == 0, "");
		// store the root sector address to the corresponding file table in super block
		sc->superblock.fd_root[fbuf->ma.fd] = sa;
		sc->sb_modified = true;
	}
}

DECLARE_GEOM_CLASS(g_logstor_class, g_logstor); /* Let there be light */
MODULE_VERSION(geom_logstor, 0);
