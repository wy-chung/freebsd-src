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
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/ctype.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/reboot.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sysctl.h>

#include <geom/geom.h>
#include <geom/geom_dbg.h>
#include <geom/logstor/g_logstor.h>

SYSCTL_DECL(_kern_geom);
static SYSCTL_NODE(_kern_geom, OID_AUTO, logstor, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "GEOM_LOGSTOR stuff");
static u_int g_logstor_debug = 0;
SYSCTL_UINT(_kern_geom_logstor, OID_AUTO, debug, CTLFLAG_RW, &g_logstor_debug, 0,
    "Debug level");

static void g_logstor_config(struct gctl_req *req, struct g_class *mp,
    const char *verb);
#if !defined(WYC)
//static g_taste_t g_logstor_taste; // from virstor
static g_access_t g_logstor_access;
static g_start_t g_logstor_start;
static g_dumpconf_t g_logstor_dumpconf;
static g_orphan_t g_logstor_orphan;
static int g_logstor_destroy_geom(struct gctl_req *req, struct g_class *mp,
    struct g_geom *gp);
static g_provgone_t g_logstor_providergone;
static g_resize_t g_logstor_resize;
#endif
struct g_class g_logstor_class = {
	.name = G_LOGSTOR_CLASS_NAME,
	.version = G_VERSION,
	.ctlreq = g_logstor_config,
	.access = g_logstor_access,
	.start = g_logstor_start,
	.dumpconf = g_logstor_dumpconf,
	.orphan = g_logstor_orphan,
	.destroy_geom = g_logstor_destroy_geom,
	.providergone = g_logstor_providergone,
	.resize = g_logstor_resize,
};

static void g_logstor_ctl_create(struct gctl_req *req, struct g_class *mp, bool);
static intmax_t g_logstor_fetcharg(struct gctl_req *req, const char *name);
static void g_logstor_ctl_destroy(struct gctl_req *req, struct g_class *mp, bool);
static struct g_geom *g_logstor_find_geom(struct g_class *mp, const char *name);
static void g_logstor_ctl_reset(struct gctl_req *req, struct g_class *mp, bool);
static void g_logstor_ctl_revert(struct gctl_req *req, struct g_class *mp, bool);
static void g_logstor_revert(struct g_logstor_softc *sc);
static void g_logstor_doio(struct g_logstor_wip *wip);
static void g_logstor_ctl_commit(struct gctl_req *req, struct g_class *mp, bool);
static void g_logstor_setmap(struct bio *bp, struct g_logstor_softc *sc);
static bool g_logstor_getmap(struct bio *bp, struct g_logstor_softc *sc,
	off_t *len2read);
static void g_logstor_done(struct bio *bp);
static void g_logstor_kerneldump(struct bio *bp, struct g_logstor_softc *sc);
static int g_logstor_dumper(void *, void *, off_t, size_t);
static int g_logstor_destroy(struct gctl_req *req, struct g_geom *gp, bool force);

static uint32_t _logstor_read(uint32_t ba, void *data);
static uint32_t _logstor_write(uint32_t ba, void *data);

static void _seg_alloc(void);
static void seg_sum_write(void);

static uint32_t disk_init(int fd);
static int  superblock_read(void);
static void superblock_write(void);

static struct _fbuf *file_access_4byte(uint8_t fd, uint32_t offset, uint32_t *off_4byte);
static uint32_t file_read_4byte(uint8_t fh, uint32_t ba);
static void file_write_4byte(uint8_t fh, uint32_t ba, uint32_t sa);

static void fbuf_mod_init(void);
static void fbuf_mod_fini(void);
static void fbuf_queue_init(int which);
static void fbuf_queue_insert_tail(int which, struct _fbuf *fbuf);
static void fbuf_queue_remove(struct _fbuf *fbuf);
static struct _fbuf *fbuf_search(union meta_addr ma);
static void fbuf_hash_insert_head(struct _fbuf *fbuf);
static void fbuf_bucket_init(int which);
static void fbuf_bucket_insert_head(int which, struct _fbuf *fbuf);
static void fbuf_bucket_remove(struct _fbuf *fbuf);
static void fbuf_write(struct _fbuf *fbuf);
static struct _fbuf *fbuf_alloc(union meta_addr ma, int depth);
static struct _fbuf *fbuf_access(union meta_addr ma);
static void fbuf_cache_flush(void);
static void fbuf_cache_flush_and_invalidate_fd(int fd1, int fd2);
static void fbuf_clean_queue_check(void);

static union meta_addr ma2pma(union meta_addr ma, unsigned *pindex_out);
static uint32_t ma2sa(union meta_addr ma);

static void my_read (uint32_t sa, void *buf);
static void my_write(uint32_t sa, const void *buf);

static void logstor_check(void);

static uint32_t logstor_ba2sa_normal(uint32_t ba);
static uint32_t logstor_ba2sa_during_commit(uint32_t ba);
static bool is_sec_valid_normal(uint32_t sa, uint32_t ba_rev);
static bool is_sec_valid_during_commit(uint32_t sa, uint32_t ba_rev);

static bool (*is_sec_valid_fp)(uint32_t sa, uint32_t ba_rev) = is_sec_valid_normal;
static uint32_t (*logstor_ba2sa_fp)(uint32_t ba) = logstor_ba2sa_normal;

/*
 * Operate on logstor-specific configuration commands.
 */
static void
g_logstor_config(struct gctl_req *req, struct g_class *mp, const char *verb)
{
	uint32_t *version, *verbose;

	g_topology_assert();

	version = gctl_get_paraml(req, "version", sizeof(*version));
	if (version == NULL) {
		gctl_error(req, "No '%s' argument.", "version");
		return;
	}
	if (*version != G_LOGSTOR_VERSION) {
		gctl_error(req, "Userland and kernel parts are out of sync.");
		return;
	}
	verbose = gctl_get_paraml(req, "verbose", sizeof(*verbose));
	if (verbose == NULL) {
		gctl_error(req, "No '%s' argument.", "verbose");
		return;
	}
	if (strcmp(verb, "create") == 0) {
		g_logstor_ctl_create(req, mp, *verbose);
		return;
	} else if (strcmp(verb, "destroy") == 0) {
		g_logstor_ctl_destroy(req, mp, *verbose);
		return;
	} else if (strcmp(verb, "reset") == 0) {
		g_logstor_ctl_reset(req, mp, *verbose);
		return;
	} else if (strcmp(verb, "revert") == 0) {
		g_logstor_ctl_revert(req, mp, *verbose);
		return;
	} else if (strcmp(verb, "commit") == 0) {
		g_logstor_ctl_commit(req, mp, *verbose);
		return;
	}

	gctl_error(req, "Unknown verb.");
}

/*
 * Create a logstor device.
 */
static void
g_logstor_ctl_create(struct gctl_req *req, struct g_class *mp, bool verbose)
{
	struct g_provider *pp, *newpp;
	struct g_logstor_softc *sc;
	struct g_geom_alias *gap;
	struct g_geom *gp;
	int *nargs;
	char name[64];

	g_topology_assert();

	nargs = gctl_get_paraml(req, "nargs", sizeof(*nargs));
	if (nargs == NULL) {
		gctl_error(req, "No '%s' argument.", "nargs");
		return;
	}
	if (*nargs != 2) {
		gctl_error(req, "Extra device(s).");
		return;
	}
	pp = gctl_get_provider(req, "arg0");
	if (pp == NULL)
		/* error message provided by gctl_get_provider() */
		return;
	/* Create the logstor */
	intmax_t secsize = 4096;
	if (secsize % pp->sectorsize != 0) {
		gctl_error(req, "Sector size %jd is not a multiple of upper "
		    "provider %s's %jd sector size.", (intmax_t)secsize,
		    pp->name, (intmax_t)pp->sectorsize);
		return;
	}
	intmax_t size = g_logstor_fetcharg(req, "size");
	if (size == 0)
		size = pp->mediasize;

	if ((size % secsize) != 0) {
		gctl_error(req, "Size %jd is not a multiple of sector size "
		    "%jd.", (intmax_t)size, (intmax_t)secsize);
		return;
	}
	if (size > pp->mediasize) {
		gctl_error(req, "Upper provider %s size (%jd) is too small, "
		    "needs %jd.", pp->name, (intmax_t)pp->mediasize,
		    (intmax_t)size);
		return;
	}
	int n = snprintf(name, sizeof(name), "%s%s", pp->name, G_LOGSTOR_SUFFIX);
	if (n <= 0 || n >= sizeof(name)) {
		gctl_error(req, "Invalid provider name.");
		return;
	}
	LIST_FOREACH(gp, &mp->geom, geom) {
		if (strcmp(gp->name, name) == 0) {
			gctl_error(req, "Provider %s already exists.", name);
			return;
		}
	}
	gp = g_new_geomf(mp, "%s", name);
	sc = g_malloc(sizeof(*sc), M_WAITOK | M_ZERO);
	rw_init(&sc->sc_rwlock, "glogstor");
	TAILQ_INIT(&sc->sc_wiplist);
	sc->sc_size = size;
	sc->sc_sectorsize = secsize;
	sc->sc_reads = 0;
	sc->sc_writes = 0;
	sc->sc_deletes = 0;
	sc->sc_getattrs = 0;
	sc->sc_flushes = 0;
	sc->sc_speedups = 0;
	sc->sc_cmd0s = 0;
	sc->sc_cmd1s = 0;
	sc->sc_cmd2s = 0;
	sc->sc_readbytes = 0;
	sc->sc_wrotebytes = 0;
	sc->sc_writemap_memory = 0;
	gp->softc = sc;

	newpp = g_new_providerf(gp, "%s", gp->name);
	newpp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE;
	newpp->mediasize = size; //wyctodo
	newpp->sectorsize = secsize;
	LIST_FOREACH(gap, &pp->aliases, ga_next) {
		g_provider_add_alias(newpp, "%s%s", gap->ga_alias,
		    G_LOGSTOR_SUFFIX);
	}
	struct g_consumer *cp = g_new_consumer(gp);
	cp->flags |= G_CF_DIRECT_SEND | G_CF_DIRECT_RECEIVE;
	int error;
	if ((error = g_attach(cp, pp)) != 0) {
		gctl_error(req, "Error %d: cannot attach to provider %s.",
		    error, pp->name);
		goto fail;
	}
	/* request read, write, and exclusive access for lower */
	if ((error = g_access(cp, 1, 1, 1)) != 0) {
		gctl_error(req, "Error %d: cannot obtain write access to %s.",
		    error, pp->name);
		goto fail;
	}
	newpp->flags |= (pp->flags & G_PF_ACCEPT_UNMAPPED);
	g_error_provider(newpp, 0);
	/*
	 * Allocate the map that tracks the sectors that have been written
	 * to the top layer. We use a 2-level hierarchy as that lets us
	 * map up to 1 petabyte using allocations of less than 33 Mb
	 * when using 4K byte sectors (or 268 Mb with 512 byte sectors).
	 *
	 * We totally populate the leaf nodes rather than allocating them
	 * as they are first used because their usage occurs in the
	 * g_logstor_start() routine that may be running in the g_down
	 * thread which cannot sleep.
	 */
	sc->sc_map_size = roundup(size / secsize, BITS_PER_ENTRY);
	intmax_t needed = sc->sc_map_size / BITS_PER_ENTRY;
	for (sc->sc_root_size = 1;
	     sc->sc_root_size * sc->sc_root_size < needed;
	     sc->sc_root_size++)
		continue;
	sc->sc_writemap_root = g_malloc(sc->sc_root_size * sizeof(uint64_t *),
	    M_WAITOK | M_ZERO);
	sc->sc_leaf_size = sc->sc_root_size;
	sc->sc_bits_per_leaf = sc->sc_leaf_size * BITS_PER_ENTRY;
	sc->sc_leafused = g_malloc(roundup(sc->sc_root_size, BITS_PER_ENTRY),
	    M_WAITOK | M_ZERO);
	for (int i = 0; i < sc->sc_root_size; i++)
		sc->sc_writemap_root[i] =
		    g_malloc(sc->sc_leaf_size * sizeof(uint64_t),
		    M_WAITOK | M_ZERO);
	sc->sc_writemap_memory =
	    (sc->sc_root_size + sc->sc_root_size * sc->sc_leaf_size) *
	    sizeof(uint64_t) + roundup(sc->sc_root_size, BITS_PER_ENTRY);
	if (verbose)
		gctl_msg(req, 0, "Device %s created with memory map size %jd.",
		    gp->name, (intmax_t)sc->sc_writemap_memory);
	gctl_post_messages(req);
	G_LOGSTOR_DEBUG(1, "Device %s created with memory map size %jd.",
	    gp->name, (intmax_t)sc->sc_writemap_memory);
	return;

fail:
	g_destroy_provider(newpp);
	g_destroy_geom(gp);
}

/*
 * Fetch named option and verify that it is positive.
 */
static intmax_t
g_logstor_fetcharg(struct gctl_req *req, const char *name)
{
	intmax_t *val;

	val = gctl_get_paraml_opt(req, name, sizeof(*val));
	if (val == NULL)
		return (0);
	if (*val >= 0)
		return (*val);
	gctl_msg(req, EINVAL, "Invalid '%s' (%jd): negative value, "
	    "using default.", name, *val);
	return (0);
}

/*
 * Destroy a logstor device.
 */
static void
g_logstor_ctl_destroy(struct gctl_req *req, struct g_class *mp, bool verbose)
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
		error = g_logstor_destroy(verbose ? req : NULL, gp, *force);
		if (error != 0)
			gctl_msg(req, error, "Error %d: "
			    "cannot destroy device %s.", error, gp->name);
	}
	gctl_post_messages(req);
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

/*
 * Zero out all the statistics associated with a logstor device.
 */
static void
g_logstor_ctl_reset(struct gctl_req *req, struct g_class *mp, bool verbose)
{
	struct g_logstor_softc *sc;
	struct g_provider *pp;
	struct g_geom *gp;
	char param[16];
	int i, *nargs;

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

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		pp = gctl_get_provider(req, param);
		if (pp == NULL) {
			gctl_msg(req, EINVAL, "No '%s' argument.", param);
			continue;
		}
		gp = pp->geom;
		if (gp->class != mp) {
			gctl_msg(req, EINVAL, "Provider %s is invalid.",
			    pp->name);
			continue;
		}
		sc = gp->softc;
		sc->sc_reads = 0;
		sc->sc_writes = 0;
		sc->sc_deletes = 0;
		sc->sc_getattrs = 0;
		sc->sc_flushes = 0;
		sc->sc_speedups = 0;
		sc->sc_cmd0s = 0;
		sc->sc_cmd1s = 0;
		sc->sc_cmd2s = 0;
		sc->sc_readbytes = 0;
		sc->sc_wrotebytes = 0;
		if (verbose)
			gctl_msg(req, 0, "Device %s has been reset.", pp->name);
		G_LOGSTOR_DEBUG(1, "Device %s has been reset.", pp->name);
	}
	gctl_post_messages(req);
}

/*
 * Revert all write requests made to the top layer of the logstor.
 */
static void
g_logstor_ctl_revert(struct gctl_req *req, struct g_class *mp, bool verbose)
{
	struct g_logstor_softc *sc;
	struct g_provider *pp;
	struct g_geom *gp;
	char param[16];
	int i, *nargs;

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

	for (i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		pp = gctl_get_provider(req, param);
		if (pp == NULL) {
			gctl_msg(req, EINVAL, "No '%s' argument.", param);
			continue;
		}
		gp = pp->geom;
		if (gp->class != mp) {
			gctl_msg(req, EINVAL, "Provider %s is invalid.",
			    pp->name);
			continue;
		}
		sc = gp->softc;
		if (g_logstor_get_writelock(sc) != 0) {
			gctl_msg(req, EINVAL, "Revert already in progress for "
			    "provider %s.", pp->name);
			continue;
		}
		/*
		 * No mount or other use of logstor is allowed.
		 */
		if (pp->acr > 0 || pp->acw > 0 || pp->ace > 0) {
			gctl_msg(req, EPERM,
			    "Unable to get exclusive access for reverting of %s;\n"
				"\t%s cannot be mounted or otherwise open during a revert.",
			     pp->name, pp->name);
			g_logstor_rel_writelock(sc);
			continue;
		}
		g_logstor_revert(sc);
		g_logstor_rel_writelock(sc);
		if (verbose)
			gctl_msg(req, 0, "Device %s has been reverted.",
			    pp->name);
		G_LOGSTOR_DEBUG(1, "Device %s has been reverted.", pp->name);
	}
	gctl_post_messages(req);
}

/*
 * Revert logstor writes by zero'ing out the writemap.
 */
static void
g_logstor_revert(struct g_logstor_softc *sc)
{
	int i;

	GL_WLOCK(sc);
	for (i = 0; i < sc->sc_root_size; i++)
		memset(sc->sc_writemap_root[i], 0,
		    sc->sc_leaf_size * sizeof(uint64_t));
	memset(sc->sc_leafused, 0, roundup(sc->sc_root_size, BITS_PER_ENTRY));
	GL_WUNLOCK(sc);
}

/*
 * Commit all the writes made in the top layer to the lower layer.
 */
static void
g_logstor_ctl_commit(struct gctl_req *req, struct g_class *mp, bool verbose)
{
	struct g_logstor_softc *sc;
	struct g_provider *pp, *lowerpp;
	struct g_consumer *cp;
	struct g_geom *gp;
	struct bio *bp;
	char param[16];
	off_t len2rd, len2wt, savelen;
	int error, error1, *nargs, *force, *reboot;

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
	reboot = gctl_get_paraml(req, "reboot", sizeof(*reboot));
	if (reboot == NULL) {
		gctl_error(req, "No 'reboot' argument.");
		return;
	}

	/* Get a bio buffer to do our I/O */
	bp = g_alloc_bio();
	bp->bio_data = g_malloc(MAXBSIZE, M_WAITOK);
	bp->bio_done = biodone;
	for (int i = 0; i < *nargs; i++) {
		snprintf(param, sizeof(param), "arg%d", i);
		pp = gctl_get_provider(req, param);
		if (pp == NULL) {
			gctl_msg(req, EINVAL, "Provider %s does not exist.",
			    param);
			continue;
		}
		gp = pp->geom;
		if (gp->class != mp) {
			gctl_msg(req, EINVAL, "Provider %s is invalid.",
			    pp->name);
			continue;
		}
		sc = gp->softc;
		if (g_logstor_get_writelock(sc) != 0) {
			gctl_msg(req, EINVAL, "Commit already in progress for "
			    "provider %s.", pp->name);
			continue;
		}
	
		/* upgrade to write access for lower */
		cp = sc->sc_lowercp;
		lowerpp = cp->provider;
		/*
		 * No mount or other use of logstor is allowed, unless the
		 * -f flag is given which allows read-only mount or usage.
		 */
		if ((*force == false && pp->acr > 0) || pp->acw > 0 ||
		     pp->ace > 0) {
			gctl_msg(req, EPERM,
			    "Unable to get exclusive access for writing of %s.\n"
				"\tNote that %s cannot be mounted or otherwise\n"
				"\topen during a commit unless the -f flag is used.",
			    pp->name, pp->name);
			g_logstor_rel_writelock(sc);
			continue;
		}
		/*
		 * No mount or other use of lower media is allowed, unless the
		 * -f flag is given which allows read-only mount or usage.
		 */
		if ((*force == false && lowerpp->acr > cp->acr) ||
		     lowerpp->acw > cp->acw ||
		     lowerpp->ace > cp->ace) {
			gctl_msg(req, EPERM,
			    "provider %s is unable to get exclusive access to %s\n"
				"\tfor writing. Note that %s cannot be mounted or otherwise open\n"
				"\tduring a commit unless the -f flag is used.",
			    pp->name, lowerpp->name, lowerpp->name);
			g_logstor_rel_writelock(sc);
			continue;
		}
		if ((error = g_access(cp, 0, 1, 0)) != 0) {
			gctl_msg(req, error, "Error %d: provider %s is unable "
			    "to access %s for writing.", error, pp->name,
			    lowerpp->name);
			g_logstor_rel_writelock(sc);
			continue;
		}
		g_topology_unlock();
		/* Loop over write map copying across written blocks */
		bp->bio_offset = 0;
		bp->bio_length = sc->sc_map_size * sc->sc_sectorsize;
		GL_RLOCK(sc);
		error = 0;
		while (bp->bio_length > 0) {
			if (!g_logstor_getmap(bp, sc, &len2rd)) {
				/* not written, so skip */
				bp->bio_offset += len2rd;
				bp->bio_length -= len2rd;
				continue;
			}
			GL_RUNLOCK(sc);
			/* need to read then write len2rd sectors */
			for ( ; len2rd > 0; len2rd -= len2wt) {
				/* limit ourselves to MAXBSIZE size I/Os */
				len2wt = len2rd;
				if (len2wt > MAXBSIZE)
					len2wt = MAXBSIZE;
				savelen = bp->bio_length;
				bp->bio_length = len2wt;
				bp->bio_cmd = BIO_READ;
				g_io_request(bp, sc->sc_uppercp);
				if ((error = biowait(bp, "rdlogstor")) != 0) {
					gctl_msg(req, error, "Commit read "
					    "error %d in provider %s, commit "
					    "aborted.", error, pp->name);
					goto cleanup;
				}
				bp->bio_flags &= ~BIO_DONE;
				bp->bio_cmd = BIO_WRITE;
				g_io_request(bp, cp);
				if ((error = biowait(bp, "wtlogstor")) != 0) {
					gctl_msg(req, error, "Commit write "
					    "error %d in provider %s, commit "
					    "aborted.", error, pp->name);
					goto cleanup;
				}
				bp->bio_flags &= ~BIO_DONE;
				bp->bio_offset += len2wt;
				bp->bio_length = savelen - len2wt;
			}
			GL_RLOCK(sc);
		}
		GL_RUNLOCK(sc);
		/* clear the write map */
		g_logstor_revert(sc);
cleanup:
		g_topology_lock();
		/* return lower to previous access */
		if ((error1 = g_access(cp, 0, -1, 0)) != 0) {
			G_LOGSTOR_DEBUG(2, "Error %d: device %s could not reset "
			    "access to %s (r=0 w=-1 e=0).", error1, pp->name,
			    lowerpp->name);
		}
		g_logstor_rel_writelock(sc);
		if (error == 0 && verbose)
			gctl_msg(req, 0, "Device %s has been committed.",
			    pp->name);
		G_LOGSTOR_DEBUG(1, "Device %s has been committed.", pp->name);
	}
	gctl_post_messages(req);
	g_free(bp->bio_data);
	g_destroy_bio(bp);
	if (*reboot)
		kern_reboot(RB_AUTOBOOT);
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
#if defined(WYC)
/*
 * Taste event (per-class callback)
 * Examines a provider and creates geom instances if needed
 */
static struct g_geom *
g_logstor_taste(struct g_class *mp, struct g_provider *pp, int flags)
{
	struct g_virstor_metadata md;
	struct g_geom *gp;
	struct g_consumer *cp;
	struct g_virstor_softc *sc;
	int error;

	g_trace(G_T_TOPOLOGY, "%s(%s, %s)", __func__, mp->name, pp->name);
	g_topology_assert();
	LOG_MSG(LVL_DEBUG, "Tasting %s", pp->name);

	/* We need a dummy geom to attach a consumer to the given provider */
	gp = g_new_geomf(mp, "virstor:taste.helper");
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

	if (strcmp(md.md_magic, G_VIRSTOR_MAGIC) != 0)
		return (NULL);
	if (md.md_version != G_VIRSTOR_VERSION) {
		LOG_MSG(LVL_ERROR, "Kernel module version invalid "
		    "to handle %s (%s) : %d should be %d",
		    md.md_name, pp->name, md.md_version, G_VIRSTOR_VERSION);
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
		gp = create_virstor_geom(mp, &md);
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
			virstor_geom_destroy(sc, TRUE, FALSE);
			return (NULL);
		}
	}

	return (gp);
}
#endif
/*
 * Initiate an I/O operation on the logstor device.
 */
static void
g_logstor_start(struct bio *bp)
{
	struct g_logstor_softc *sc;
	struct g_logstor_wip *wip;
	struct bio *cbp;

	sc = bp->bio_to->geom->softc;
	if (bp->bio_cmd == BIO_READ || bp->bio_cmd == BIO_WRITE) {
		wip = g_malloc(sizeof(*wip), M_NOWAIT);
		if (wip == NULL) {
			g_io_deliver(bp, ENOMEM);
			return;
		}
		TAILQ_INIT(&wip->wip_waiting);
		wip->wip_bp = bp;
		wip->wip_sc = sc;
		wip->wip_start = bp->bio_offset + sc->sc_offset;
		wip->wip_end = wip->wip_start + bp->bio_length - 1;
		wip->wip_numios = 1;
		wip->wip_error = 0;
		g_logstor_doio(wip);
		return;
	}

	/*
	 * All commands other than read and write are passed through to
	 * the upper-level device since it is writable and thus able to
	 * respond to delete, flush, and speedup requests.
	 */
	cbp = g_clone_bio(bp);
	if (cbp == NULL) {
		g_io_deliver(bp, ENOMEM);
		return;
	}
	cbp->bio_offset = bp->bio_offset + sc->sc_offset;
	cbp->bio_done = g_std_done;

	switch (cbp->bio_cmd) {
	case BIO_DELETE:
		G_LOGSTOR_LOGREQ(cbp, "Delete request received.");
		atomic_add_long(&sc->sc_deletes, 1);
		break;
	case BIO_GETATTR:
		G_LOGSTOR_LOGREQ(cbp, "Getattr request received.");
		atomic_add_long(&sc->sc_getattrs, 1);
		if (strcmp(cbp->bio_attribute, "GEOM::kerneldump") != 0)
			/* forward the GETATTR to the lower-level device */
			break;
		g_logstor_kerneldump(bp, sc);
		return;
	case BIO_FLUSH:
		G_LOGSTOR_LOGREQ(cbp, "Flush request received.");
		atomic_add_long(&sc->sc_flushes, 1);
		break;
	case BIO_SPEEDUP:
		G_LOGSTOR_LOGREQ(cbp, "Speedup request received.");
		atomic_add_long(&sc->sc_speedups, 1);
		break;
	case BIO_CMD0:
		G_LOGSTOR_LOGREQ(cbp, "Cmd0 request received.");
		atomic_add_long(&sc->sc_cmd0s, 1);
		break;
	case BIO_CMD1:
		G_LOGSTOR_LOGREQ(cbp, "Cmd1 request received.");
		atomic_add_long(&sc->sc_cmd1s, 1);
		break;
	case BIO_CMD2:
		G_LOGSTOR_LOGREQ(cbp, "Cmd2 request received.");
		atomic_add_long(&sc->sc_cmd2s, 1);
		break;
	default:
		G_LOGSTOR_LOGREQ(cbp, "Unknown (%d) request received.",
		    cbp->bio_cmd);
		break;
	}
	g_io_request(cbp, sc->sc_uppercp);
}

/*
 * Initiate a read or write operation on the logstor device.
 */
static void
g_logstor_doio(struct g_logstor_wip *wip)
{
	struct g_logstor_softc *sc;
	struct g_consumer *cp, *firstcp;
	struct g_logstor_wip *activewip;
	struct bio *cbp, *firstbp;
	off_t rdlen, len2rd, offset;
	int iocnt;
	char *level;

	/*
	 * To maintain consistency, we cannot allow concurrent reads
	 * or writes to the same block.
	 *
	 * A work-in-progress (wip) structure is allocated for each
	 * read or write request. All active requests are kept on the
	 * softc sc_wiplist. As each request arrives, it is checked to
	 * see if it overlaps any of the active entries. If it does not
	 * overlap, then it is added to the active list and initiated.
	 * If it does overlap an active entry, it is added to the
	 * wip_waiting list for the active entry that it overlaps.
	 * When an active entry completes, it restarts all the requests
	 * on its wip_waiting list.
	 */
	sc = wip->wip_sc;
	GL_WLOCK(sc);
	TAILQ_FOREACH(activewip, &sc->sc_wiplist, wip_next) {
		if (wip->wip_end < activewip->wip_start ||
		    wip->wip_start > activewip->wip_end)
			continue;
		bool needstoblock = true;
		if (wip->wip_bp->bio_cmd == BIO_WRITE)
			if (activewip->wip_bp->bio_cmd == BIO_WRITE)
				sc->sc_writeblockwrite += 1;
			else
				sc->sc_readblockwrite += 1;
		else
			if (activewip->wip_bp->bio_cmd == BIO_WRITE)
				sc->sc_writeblockread += 1;
			else {
				sc->sc_readcurrentread += 1;
				needstoblock = false;
			}
		/* Put request on a waiting list if necessary */
		if (needstoblock) {
			TAILQ_INSERT_TAIL(&activewip->wip_waiting, wip,
			    wip_next);
			GL_WUNLOCK(sc);
			return;
		}
	}
	/* Put request on the active list */
	TAILQ_INSERT_TAIL(&sc->sc_wiplist, wip, wip_next);

	/*
	 * Process I/O requests that have been cleared to go.
	 */
	cbp = g_clone_bio(wip->wip_bp);
	if (cbp == NULL) {
		TAILQ_REMOVE(&sc->sc_wiplist, wip, wip_next);
		GL_WUNLOCK(sc);
		KASSERT(TAILQ_FIRST(&wip->wip_waiting) == NULL,
		    ("g_logstor_doio: non-empty work-in-progress waiting queue"));
		g_io_deliver(wip->wip_bp, ENOMEM);
		g_free(wip);
		return;
	}
	GL_WUNLOCK(sc);
	cbp->bio_caller1 = wip;
	cbp->bio_done = g_logstor_done;
	cbp->bio_offset = wip->wip_start;

	/*
	 * Writes are always done to the top level. The blocks that
	 * are written are recorded in the bitmap when the I/O completes.
	 */
	if (cbp->bio_cmd == BIO_WRITE) {
		G_LOGSTOR_LOGREQ(cbp, "Sending %jd byte write request to upper "
		    "level.", cbp->bio_length);
		atomic_add_long(&sc->sc_writes, 1);
		atomic_add_long(&sc->sc_wrotebytes, cbp->bio_length);
		g_io_request(cbp, sc->sc_uppercp);
		return;
	}
	/*
	 * The usual read case is that we either read the top layer
	 * if the block has been previously written or the bottom layer
	 * if it has not been written. However, it is possible that
	 * only part of the block has been written, For example we may
	 * have written a UFS/FFS file fragment comprising several
	 * sectors out of an 8-sector block.  Here, if the entire
	 * 8-sector block is read for example by a snapshot needing
	 * to copy the full block, then we need to read the written
	 * sectors from the upper level and the unwritten sectors from
	 * the lower level. We do this by alternately reading from the
	 * top and bottom layers until we complete the read. We
	 * simplify for the common case to just do the I/O and return.
	 */
	atomic_add_long(&sc->sc_reads, 1);
	atomic_add_long(&sc->sc_readbytes, cbp->bio_length);
	rdlen = cbp->bio_length;
	offset = 0;
	for (iocnt = 0; ; iocnt++) {
		if (g_logstor_getmap(cbp, sc, &len2rd)) {
			/* read top */
			cp = sc->sc_uppercp;
			level = "upper";
		} else {
			/* read bottom */
			cp = sc->sc_lowercp;
			level = "lower";
		}
		/* Check if only a single read is required */
		if (iocnt == 0 && rdlen == len2rd) {
			G_LOGSTOR_LOGREQLVL((cp == sc->sc_uppercp) ?
			    3 : 4, cbp, "Sending %jd byte read "
			    "request to %s level.", len2rd, level);
			g_io_request(cbp, cp);
			return;
		}
		cbp->bio_length = len2rd;
		if ((cbp->bio_flags & BIO_UNMAPPED) != 0)
			cbp->bio_ma_offset += offset;
		else
			cbp->bio_data += offset;
		offset += len2rd;
		rdlen -= len2rd;
		G_LOGSTOR_LOGREQLVL(3, cbp, "Sending %jd byte read "
		    "request to %s level.", len2rd, level);
		/*
		 * To avoid prematurely notifying our consumer
		 * that their I/O has completed, we have to delay
		 * issuing our first I/O request until we have
		 * issued all the additional I/O requests.
		 */
		if (iocnt > 0) {
			atomic_add_long(&wip->wip_numios, 1);
			g_io_request(cbp, cp);
		} else {
			firstbp = cbp;
			firstcp = cp;
		}
		if (rdlen == 0)
			break;
		/* set up for next read */
		cbp = g_clone_bio(wip->wip_bp);
		if (cbp == NULL) {
			wip->wip_error = ENOMEM;
			atomic_add_long(&wip->wip_numios, -1);
			break;
		}
		cbp->bio_caller1 = wip;
		cbp->bio_done = g_logstor_done;
		cbp->bio_offset += offset;
		cbp->bio_length = rdlen;
		atomic_add_long(&sc->sc_reads, 1);
	}
	/* We have issued all our I/O, so start the first one */
	g_io_request(firstbp, firstcp);
	return;
}

/*
 * Used when completing a logstor I/O operation.
 */
static void
g_logstor_done(struct bio *bp)
{
	struct g_logstor_wip *wip, *waitingwip;
	struct g_logstor_softc *sc;

	wip = bp->bio_caller1;
	if (wip->wip_error != 0 && bp->bio_error == 0)
		bp->bio_error = wip->wip_error;
	wip->wip_error = 0;
	if (atomic_fetchadd_long(&wip->wip_numios, -1) == 1) {
		sc = wip->wip_sc;
		GL_WLOCK(sc);
		if (bp->bio_cmd == BIO_WRITE)
			g_logstor_setmap(bp, sc);
		TAILQ_REMOVE(&sc->sc_wiplist, wip, wip_next);
		GL_WUNLOCK(sc);
		while ((waitingwip = TAILQ_FIRST(&wip->wip_waiting)) != NULL) {
			TAILQ_REMOVE(&wip->wip_waiting, waitingwip, wip_next);
			g_logstor_doio(waitingwip);
		}
		g_free(wip);
	}
	g_std_done(bp);
}

/*
 * Record blocks that have been written in the map.
 */
static void
g_logstor_setmap(struct bio *bp, struct g_logstor_softc *sc)
{
	size_t root_idx;
	uint64_t **leaf;
	uint64_t *wordp;
	off_t start, numsec;

	GL_WLOCKOWNED(sc);
	KASSERT(bp->bio_offset % sc->sc_sectorsize == 0,
	    ("g_logstor_setmap: offset not on sector boundry"));
	KASSERT(bp->bio_length % sc->sc_sectorsize == 0,
	    ("g_logstor_setmap: length not a multiple of sectors"));
	start = bp->bio_offset / sc->sc_sectorsize;
	numsec = bp->bio_length / sc->sc_sectorsize;
	KASSERT(start + numsec <= sc->sc_map_size,
	    ("g_logstor_setmap: block %jd is out of range", start + numsec));
	for ( ; numsec > 0; numsec--, start++) {
		root_idx = start / sc->sc_bits_per_leaf;
		leaf = &sc->sc_writemap_root[root_idx];
		wordp = &(*leaf)
		    [(start % sc->sc_bits_per_leaf) / BITS_PER_ENTRY];
		*wordp |= 1ULL << (start % BITS_PER_ENTRY);
		sc->sc_leafused[root_idx / BITS_PER_ENTRY] |=
		    1ULL << (root_idx % BITS_PER_ENTRY);
	}
}

/*
 * Check map to determine whether blocks have been written.
 *
 * Return true if they have been written so should be read from the top
 * layer. Return false if they have not been written so should be read
 * from the bottom layer. Return in len2read the bytes to be read. See
 * the comment above the BIO_READ implementation in g_logstor_start() for
 * an explantion of why len2read may be shorter than the buffer length.
 */
static bool
g_logstor_getmap(struct bio *bp, struct g_logstor_softc *sc, off_t *len2read)
{
	off_t start, numsec, bitloc;
	bool first, maptype, retval;
	uint64_t *leaf, word;
	size_t root_idx;

	KASSERT(bp->bio_offset % sc->sc_sectorsize == 0,
	    ("%s: offset not on sector boundry", __func__));
	KASSERT(bp->bio_length % sc->sc_sectorsize == 0,
	    ("%s: length not a multiple of sectors", __func__));
	start = bp->bio_offset / sc->sc_sectorsize;
	numsec = bp->bio_length / sc->sc_sectorsize;
	G_LOGSTOR_DEBUG(4, "%s: check %jd sectors starting at %jd\n",
	    __func__, numsec, start);
	KASSERT(start + numsec <= sc->sc_map_size,
	    ("%s: block %jd is out of range", __func__, start + numsec));
	root_idx = start / sc->sc_bits_per_leaf;
	first = true;
	maptype = false;
	while (numsec > 0) {
		/* Check first if the leaf records any written sectors */
		root_idx = start / sc->sc_bits_per_leaf;
		off_t leafresid = sc->sc_bits_per_leaf -
		    (start % sc->sc_bits_per_leaf);
		if (((sc->sc_leafused[root_idx / BITS_PER_ENTRY]) &
		    (1ULL << (root_idx % BITS_PER_ENTRY))) == 0) {
			if (first) {
				maptype = false;
				first = false;
			}
			if (maptype)
				break;
			numsec -= leafresid;
			start += leafresid;
			continue;
		}
		/* Check up to a word boundry, then check word by word */
		leaf = sc->sc_writemap_root[root_idx];
		word = leaf[(start % sc->sc_bits_per_leaf) / BITS_PER_ENTRY];
		bitloc = start % BITS_PER_ENTRY;
		if (bitloc == 0 && (word == 0 || word == ~0)) {
			if (first) {
				if (word == 0)
					maptype = false;
				else
					maptype = true;
				first = false;
			}
			if ((word == 0 && maptype) ||
			    (word == ~0 && !maptype))
				break;
			numsec -= BITS_PER_ENTRY;
			start += BITS_PER_ENTRY;
			continue;
		}
		for ( ; bitloc < BITS_PER_ENTRY; bitloc ++) {
			retval = (word & (1ULL << bitloc)) != 0;
			if (first) {
				maptype = retval;
				first = false;
			}
			if (maptype == retval) {
				numsec--;
				start++;
				continue;
			}
			goto out;
		}
	}
out:
	if (numsec < 0) {
		start += numsec;
		numsec = 0;
	}
	*len2read = bp->bio_length - (numsec * sc->sc_sectorsize);
	G_LOGSTOR_DEBUG(maptype ? 3 : 4,
	    "g_logstor_getmap: return maptype %swritten for %jd "
	    "sectors ending at %jd\n", maptype ? "" : "NOT ",
	    *len2read / sc->sc_sectorsize, start - 1);
	return (maptype);
}

/*
 * Fill in details for a BIO_GETATTR request.
 */
static void
g_logstor_kerneldump(struct bio *bp, struct g_logstor_softc *sc)
{
	struct g_kerneldump *gkd;
	struct g_geom *gp;
	struct g_provider *pp;

	gkd = (struct g_kerneldump *)bp->bio_data;
	gp = bp->bio_to->geom;
	g_trace(G_T_TOPOLOGY, "%s(%s, %jd, %jd)", __func__, gp->name,
	    (intmax_t)gkd->offset, (intmax_t)gkd->length);

	pp = LIST_FIRST(&gp->provider);

	gkd->di.dumper = g_logstor_dumper;
	gkd->di.priv = sc;
	gkd->di.blocksize = pp->sectorsize;
	gkd->di.maxiosize = DFLTPHYS;
	gkd->di.mediaoffset = sc->sc_offset + gkd->offset;
	if (gkd->offset > sc->sc_size) {
		g_io_deliver(bp, ENODEV);
		return;
	}
	if (gkd->offset + gkd->length > sc->sc_size)
		gkd->length = sc->sc_size - gkd->offset;
	gkd->di.mediasize = gkd->length;
	g_io_deliver(bp, 0);
}

/*
 * Handler for g_logstor_kerneldump().
 */
static int
g_logstor_dumper(void *priv, void *virtual, off_t offset, size_t length)
{

	return (0);
}

/*
 * List logstor statistics.
 */
static void
g_logstor_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
	struct g_logstor_softc *sc;

	if (pp != NULL || cp != NULL || gp->softc == NULL)
		return;
	sc = gp->softc;
	sbuf_printf(sb, "%s<Reads>%ju</Reads>\n", indent,
	    (uintmax_t)sc->sc_reads);
	sbuf_printf(sb, "%s<Writes>%ju</Writes>\n", indent,
	    (uintmax_t)sc->sc_writes);
	sbuf_printf(sb, "%s<Deletes>%ju</Deletes>\n", indent,
	    (uintmax_t)sc->sc_deletes);
	sbuf_printf(sb, "%s<Getattrs>%ju</Getattrs>\n", indent,
	    (uintmax_t)sc->sc_getattrs);
	sbuf_printf(sb, "%s<Flushes>%ju</Flushes>\n", indent,
	    (uintmax_t)sc->sc_flushes);
	sbuf_printf(sb, "%s<Speedups>%ju</Speedups>\n", indent,
	    (uintmax_t)sc->sc_speedups);
	sbuf_printf(sb, "%s<Cmd0s>%ju</Cmd0s>\n", indent,
	    (uintmax_t)sc->sc_cmd0s);
	sbuf_printf(sb, "%s<Cmd1s>%ju</Cmd1s>\n", indent,
	    (uintmax_t)sc->sc_cmd1s);
	sbuf_printf(sb, "%s<Cmd2s>%ju</Cmd2s>\n", indent,
	    (uintmax_t)sc->sc_cmd2s);
	sbuf_printf(sb, "%s<ReadCurrentRead>%ju</ReadCurrentRead>\n", indent,
	    (uintmax_t)sc->sc_readcurrentread);
	sbuf_printf(sb, "%s<ReadBlockWrite>%ju</ReadBlockWrite>\n", indent,
	    (uintmax_t)sc->sc_readblockwrite);
	sbuf_printf(sb, "%s<WriteBlockRead>%ju</WriteBlockRead>\n", indent,
	    (uintmax_t)sc->sc_writeblockread);
	sbuf_printf(sb, "%s<WriteBlockWrite>%ju</WriteBlockWrite>\n", indent,
	    (uintmax_t)sc->sc_writeblockwrite);
	sbuf_printf(sb, "%s<ReadBytes>%ju</ReadBytes>\n", indent,
	    (uintmax_t)sc->sc_readbytes);
	sbuf_printf(sb, "%s<WroteBytes>%ju</WroteBytes>\n", indent,
	    (uintmax_t)sc->sc_wrotebytes);
	sbuf_printf(sb, "%s<Offset>%jd</Offset>\n", indent,
	    (intmax_t)sc->sc_offset);
}

/*
 * Clean up an orphaned geom.
 */
static void
g_logstor_orphan(struct g_consumer *cp)
{

	g_topology_assert();
	g_logstor_destroy(NULL, cp->geom, true);
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
			G_LOGSTOR_DEBUG(1, "Device %s is still in use, so "
			    "is being forcibly removed.", gp->name);
		} else {
			if (req != NULL)
				gctl_msg(req, EBUSY, "Device %s is still open "
				    "(r=%d w=%d e=%d).", gp->name, pp->acr,
				    pp->acw, pp->ace);
			G_LOGSTOR_DEBUG(1, "Device %s is still open "
			    "(r=%d w=%d e=%d).", gp->name, pp->acr,
			    pp->acw, pp->ace);
			return (EBUSY);
		}
	} else {
		if (req != NULL)
			gctl_msg(req, 0, "Device %s removed.", gp->name);
		G_LOGSTOR_DEBUG(1, "Device %s removed.", gp->name);
	}
	/* Close consumers */
	if ((error = g_access(sc->sc_lowercp, -1, 0, -1)) != 0)
		G_LOGSTOR_DEBUG(2, "Error %d: device %s could not reset access "
		    "to %s.", error, gp->name, sc->sc_lowercp->provider->name);
	if ((error = g_access(sc->sc_uppercp, -1, -1, -1)) != 0)
		G_LOGSTOR_DEBUG(2, "Error %d: device %s could not reset access "
		    "to %s.", error, gp->name, sc->sc_uppercp->provider->name);

	g_wither_geom(gp, ENXIO);

	return (0);
}

/*
 * Clean up a logstor provider.
 */
static void
g_logstor_providergone(struct g_provider *pp)
{
	struct g_geom *gp;
	struct g_logstor_softc *sc;
	size_t i;

	gp = pp->geom;
	sc = gp->softc;
	gp->softc = NULL;
	for (i = 0; i < sc->sc_root_size; i++)
		g_free(sc->sc_writemap_root[i]);
	g_free(sc->sc_writemap_root);
	g_free(sc->sc_leafused);
	rw_destroy(&sc->sc_rwlock);
	g_free(sc);
}

/*
 * Respond to a resized provider.
 */
static void
g_logstor_resize(struct g_consumer *cp)
{
	struct g_logstor_softc *sc;
	struct g_geom *gp;

	g_topology_assert();

	gp = cp->geom;
	sc = gp->softc;

	/*
	 * If size has gotten bigger, ignore it and just keep using
	 * the space we already had. Otherwise we are done.
	 */
	if (sc->sc_size < cp->provider->mediasize - sc->sc_offset)
		return;
	g_logstor_destroy(NULL, gp, true);
}

//=======================================================================
static struct g_logstor_softc sc;

/*
Description:
    segment address to sector address
*/
static inline uint32_t
sega2sa(uint32_t sega)
{
	return sega << SA2SEGA_SHIFT;
}

int
logstor_open(const char *disk_file)
{
	bzero(&sc, sizeof(sc));
	int error __unused;

	error = superblock_read();
	KASSERT(error == 0, "");
	sc.sb_modified = false;

	// read the segment summary block
	KASSERT(sc.superblock.seg_alloc >= SEG_DATA_START, "");
	sc.seg_alloc_sa = sega2sa(sc.superblock.seg_alloc);
	uint32_t sa = sc.seg_alloc_sa + SEG_SUM_OFFSET;
	my_read(sa, &sc.seg_sum);
	KASSERT(sc.seg_sum.ss_alloc < SEG_SUM_OFFSET, "");
	sc.ss_modified = false;
	sc.data_write_count = sc.other_write_count = 0;

	fbuf_mod_init();
	logstor_check();

	return 0;
}

void
logstor_close(void)
{

	fbuf_mod_fini();
	seg_sum_write();
	superblock_write();
}

uint32_t
logstor_read(uint32_t ba, void *data)
{
	fbuf_clean_queue_check();
	uint32_t sa = _logstor_read(ba, data);
	return sa;
}

uint32_t
logstor_write(uint32_t ba, void *data)
{
	fbuf_clean_queue_check();
	uint32_t sa = _logstor_write(ba, data);
	return sa;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
int logstor_delete(off_t offset, void *data __unused, off_t length)
{
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process
	int i;

	KASSERT((offset & (SECTOR_SIZE - 1)) == 0, "");
	KASSERT((length & (SECTOR_SIZE - 1)) == 0, "");
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;
	KASSERT(ba < sc.superblock.block_cnt_max, "");

	for (i = 0; i < size; ++i) {
		fbuf_clean_queue_check();
		file_write_4byte(sc.superblock.fd_cur, ba + i, SECTOR_DEL);
	}

	return (0);
}

void
logstor_commit(void)
{
#if 0
	fbuf_cache_flush_and_invalidate_fd(sc.superblock.fd_cur, FD_INVALID);
#else
	// lock metadata
	// move fd_cur to fd_prev
	sc.superblock.fd_prev = sc.superblock.fd_cur;
	// create new files fd_cur and fd_snap_new
	// fc_cur is either 0 or 2 and fd_snap always follows fd_cur
	sc.superblock.fd_cur = sc.superblock.fd_cur ^ 2;
	sc.superblock.fd_snap_new = sc.superblock.fd_cur + 1;
	sc.superblock.fd_root[sc.superblock.fd_cur] = SECTOR_NULL;
	sc.superblock.fd_root[sc.superblock.fd_snap_new] = SECTOR_NULL;

	is_sec_valid_fp = is_sec_valid_during_commit;
	logstor_ba2sa_fp = logstor_ba2sa_during_commit;
	// unlock metadata

	uint32_t block_max = sc.superblock.block_cnt_max;
	for (int ba = 0; ba < block_max; ++ba) {
		uint32_t sa;

		fbuf_clean_queue_check();
		sa = file_read_4byte(sc.superblock.fd_prev, ba);
		if (sa == SECTOR_NULL)
			sa = file_read_4byte(sc.superblock.fd_snap, ba);
		else if (sa == SECTOR_DEL)
			sa = SECTOR_NULL;

		if (sa != SECTOR_NULL)
			file_write_4byte(sc.superblock.fd_snap_new, ba, sa);
	}

	// lock metadata
	int fd_prev = sc.superblock.fd_prev;
	int fd_snap = sc.superblock.fd_snap;
	fbuf_cache_flush_and_invalidate_fd(fd_prev, fd_snap);
	sc.superblock.fd_root[fd_prev] = SECTOR_DEL;
	sc.superblock.fd_root[fd_snap] = SECTOR_DEL;
	// move fd_snap_new to fd_snap
	sc.superblock.fd_snap = sc.superblock.fd_snap_new;
	// delete fd_prev and fd_snap
	sc.superblock.fd_prev = FD_INVALID;
	sc.superblock.fd_snap_new = FD_INVALID;
	sc.sb_modified = true;
	superblock_write();

	is_sec_valid_fp = is_sec_valid_normal;
	logstor_ba2sa_fp = logstor_ba2sa_normal;
	//unlock metadata
#endif
}

uint32_t
_logstor_read(unsigned ba, void *data)
{
	uint32_t sa;	// sector address

	KASSERT(ba < sc.superblock.block_cnt_max, "");

	sa = logstor_ba2sa_fp(ba);
#if defined(WYC)
	logstor_ba2sa_normal();
	logstor_ba2sa_during_commit();
#endif
	if (sa == SECTOR_NULL)
		bzero(data, SECTOR_SIZE);
	else {
		KASSERT(sa >= SECTORS_PER_SEG, "");
		my_read(sa, data);
	}
	return sa;
}

// The common part of is_sec_valid
static bool
is_sec_valid_comm(uint32_t sa, uint32_t ba_rev, uint8_t fd[], int fd_cnt)
{
	uint32_t sa_rev; // the sector address for ba_rev

	KASSERT(ba_rev < BLOCK_MAX, "");
	for (int i = 0; i < fd_cnt; ++i) {
		uint8_t _fd = fd[i];
		sa_rev = file_read_4byte(_fd, ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

// Is a sector with a reverse ba valid?
// This function is called normally
static bool
is_sec_valid_normal(uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc.superblock.fd_cur,
	    sc.superblock.fd_snap,
	};

	return is_sec_valid_comm(sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
// This function is called during commit
static bool
is_sec_valid_during_commit(uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc.superblock.fd_cur,
	    sc.superblock.fd_prev,
	    sc.superblock.fd_snap,
	};

	return is_sec_valid_comm(sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
static bool
is_sec_valid(uint32_t sa, uint32_t ba_rev)
{
#if defined(MY_DEBUG)
	union meta_addr ma_rev __unused;
	ma_rev.uint32 = ba_rev;
#endif
	if (ba_rev < BLOCK_MAX) {
		return is_sec_valid_fp(sa, ba_rev);
#if defined(WYC)
		is_sec_valid_normal();
		is_sec_valid_during_commit();
#endif
	} else if (IS_META_ADDR(ba_rev)) {
		uint32_t sa_rev = ma2sa((union meta_addr)ba_rev);
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
_logstor_write(uint32_t ba, void *data)
{
	static bool is_called = false;
	struct _seg_sum *seg_sum = &sc.seg_sum;
#if defined(MY_DEBUG)
	union meta_addr ma __unused;
	union meta_addr ma_rev __unused;

	ma.uint32 = ba;
#endif

	KASSERT(ba < sc.superblock.block_cnt_max || IS_META_ADDR(ba), "");
	KASSERT(sc.seg_alloc_sa >= SECTORS_PER_SEG, "");
	KASSERT(!is_called, "recursive call is not allowed");
	is_called = true;

	// record the starting segment
	// if the search for free sector rolls over to the starting segment
	// it means that there is no free sector in this disk
	sc.seg_alloc_start = sc.superblock.seg_alloc;
again:
	for (int i = seg_sum->ss_alloc; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t sa = sc.seg_alloc_sa + i;
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map
#if defined(MY_DEBUG)
		ma_rev.uint32 = ba_rev;
#endif
		if (is_sec_valid(sa, ba_rev))
			continue;

		my_write(sa, data);
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		sc.ss_modified = true;
		seg_sum->ss_alloc = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_alloc == SEG_SUM_OFFSET)
			_seg_alloc();

		if (IS_META_ADDR(ba))
			++sc.other_write_count;
		else {
			++sc.data_write_count;
			// record the forward mapping for the %ba
			// the forward mapping must be recorded after
			// the segment summary block write
			file_write_4byte(sc.superblock.fd_cur, ba, sa);
		}
		is_called = false;
		return sa;
	}
	_seg_alloc();
	goto again;
}

static uint32_t
logstor_ba2sa_comm(uint32_t ba, uint8_t fd[], int fd_cnt)
{
	uint32_t sa;

	KASSERT(ba < BLOCK_MAX, "");
	for (int i = 0; i < fd_cnt; ++i) {
		sa = file_read_4byte(fd[i], ba);
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
logstor_ba2sa_normal(uint32_t ba)
{
	uint8_t fd[] = {
	    sc.superblock.fd_cur,
	    sc.superblock.fd_snap,
	};

	return logstor_ba2sa_comm(ba, fd, NUM_OF_ELEMS(fd));
}

/*
Description:
    Block address to sector address translation in commit state
*/
static uint32_t __unused
logstor_ba2sa_during_commit(uint32_t ba)
{
	uint8_t fd[] = {
	    sc.superblock.fd_cur,
	    sc.superblock.fd_prev,
	    sc.superblock.fd_snap,
	};

	return logstor_ba2sa_comm(ba, fd, NUM_OF_ELEMS(fd));
}

uint32_t
logstor_get_block_cnt(void)
{
	return sc.superblock.block_cnt_max;
}

unsigned
logstor_get_data_write_count(void)
{
	return sc.data_write_count;
}

unsigned
logstor_get_other_write_count(void)
{
	return sc.other_write_count;
}

unsigned
logstor_get_fbuf_hit(void)
{
	return sc.fbuf_hit;
}

unsigned
logstor_get_fbuf_miss(void)
{
	return sc.fbuf_miss;
}

/*
  write out the segment summary
*/
static void
seg_sum_write(void)
{
	uint32_t sa;

	if (!sc.ss_modified)
		return;
	// segment summary is at the end of a segment
	KASSERT(sc.seg_alloc_sa >= SECTORS_PER_SEG, "");
	sa = sc.seg_alloc_sa + SEG_SUM_OFFSET;
	my_write(sa, (void *)&sc.seg_sum);
	sc.ss_modified = false;
	sc.other_write_count++; // the write for the segment summary
}

/*
Description:
    Write the initialized supeblock to the downstream disk

Return:
    The max number of blocks for this disk
*/
static uint32_t
disk_init(int fd)
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
	KASSERT(max_block < BLOCK_MAX, ""); // 1G
	sb->block_cnt_max = max_block;
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u block_cnt_max %u\n",
	    __func__, sector_cnt, sb->block_cnt_max);
#endif
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
	memcpy(ram_disk, sb, SECTOR_SIZE);

	// clear the rest of the supeblock's segment
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SECTORS_PER_SEG; i++) {
		memcpy(ram_disk + i * SECTOR_SIZE, buf, SECTOR_SIZE);
	}
	struct _seg_sum ss;
	for (int i = 0; i < SECTORS_PER_SEG - 1; ++i)
		ss.ss_rm[i] = BLOCK_INVALID;
	sc.superblock.seg_cnt = seg_cnt; // to silence the assert fail in my_write
	// initialize all segment summary blocks
	for (int i = SEG_DATA_START; i < seg_cnt; ++i)
	{	uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		my_write(sa, &ss);
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
superblock_read(void)
{
	int	i;
	uint16_t sb_gen;
	struct _superblock *sb;
	char buf[2][SECTOR_SIZE];

	_Static_assert(sizeof(sb_gen) == sizeof(sc.superblock.sb_gen), "sb_gen");

	// get the superblock
	sb = (struct _superblock *)buf[0];
	memcpy(sb, ram_disk, SECTOR_SIZE);
	if (sb->sig != SIG_LOGSTOR ||
	    sb->seg_alloc >= sb->seg_cnt)
		return EINVAL;

	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SECTORS_PER_SEG; i++) {
		sb = (struct _superblock *)buf[i%2];
		memcpy(sb, ram_disk + i * SECTOR_SIZE, SECTOR_SIZE);
		if (sb->sig != SIG_LOGSTOR)
			break;
		if (sb->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	sc.sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2];
	if (sb->seg_alloc >= sb->seg_cnt)
		return EINVAL;

	for (i=0; i<FD_COUNT; ++i)
		if (sb->fd_root[i] == SECTOR_CACHE)
			sb->fd_root[i] = SECTOR_NULL;
	memcpy(&sc.superblock, sb, sizeof(sc.superblock));

	return 0;
}

static void
superblock_write(void)
{
	size_t sb_size = sizeof(sc.superblock);
	char buf[SECTOR_SIZE];

	//if (!sc.sb_modified)
	//	return;

	for (int i = 0; i < 4; ++i) {
		KASSERT(sc.superblock.fd_root[i] != SECTOR_CACHE, "");
	}
	sc.superblock.sb_gen++;
	if (++sc.sb_sa == SECTORS_PER_SEG)
		sc.sb_sa = 0;
	memcpy(buf, &sc.superblock, sb_size);
	memset(buf + sb_size, 0, SECTOR_SIZE - sb_size);
	my_write(sc.sb_sa, buf);
	sc.sb_modified = false;
	sc.other_write_count++;
}

static void
my_read(uint32_t sa, void *buf)
{
//MY_BREAK(sa == );
	KASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG, "");
	memcpy(buf, ram_disk + (off_t)sa * SECTOR_SIZE, SECTOR_SIZE);
}

static void
my_write(uint32_t sa, const void *buf)
{
//MY_BREAK(sa == );
	KASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG, "");
	memcpy(ram_disk + (off_t)sa * SECTOR_SIZE , buf, SECTOR_SIZE);
}

/*
Description:
  Allocate a segment for writing

Output:
  Store the segment address into @seg_sum->sega
  Initialize @seg_sum->sum.alloc_p to 0
*/
static void
_seg_alloc(void)
{
	// write the previous segment summary to disk if it has been modified
	seg_sum_write();

	KASSERT(sc.superblock.seg_alloc < sc.superblock.seg_cnt, "");
	if (++sc.superblock.seg_alloc == sc.superblock.seg_cnt)
		sc.superblock.seg_alloc = SEG_DATA_START;
	if (sc.superblock.seg_alloc == sc.seg_alloc_start)
		// has accessed all the segment summary blocks
		MY_PANIC();
	sc.seg_alloc_sa = sega2sa(sc.superblock.seg_alloc);
	my_read(sc.seg_alloc_sa + SEG_SUM_OFFSET, &sc.seg_sum);
	sc.seg_sum.ss_alloc = 0;
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
file_read_4byte(uint8_t fd, uint32_t ba)
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
	if (sc.superblock.fd_root[fd] == SECTOR_NULL ||
	    sc.superblock.fd_root[fd] == SECTOR_DEL)
		return SECTOR_NULL;

	fbuf = file_access_4byte(fd, ba, &off_4byte);
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
file_write_4byte(uint8_t fd, uint32_t ba, uint32_t sa)
{
	struct _fbuf *fbuf;
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data

	KASSERT(fd < FD_COUNT, "");
	KASSERT(ba < BLOCK_MAX, "");
	KASSERT(sc.superblock.fd_root[fd] != SECTOR_DEL, "");

	fbuf = file_access_4byte(fd, ba, &off_4byte);
	KASSERT(fbuf != NULL, "");
	fbuf->data[off_4byte] = sa;
	if (!fbuf->fc.modified) {
		// move to QUEUE_LEAF_DIRTY
		KASSERT(fbuf->queue_which == QUEUE_LEAF_CLEAN, "");
		fbuf->fc.modified = true;
		if (fbuf == sc.fbuf_alloc)
			sc.fbuf_alloc = fbuf->fc.queue_next;
		fbuf_queue_remove(fbuf);
		fbuf_queue_insert_tail(QUEUE_LEAF_DIRTY, fbuf);
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
file_access_4byte(uint8_t fd, uint32_t ba, uint32_t *off_4byte)
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
	fbuf = fbuf_access(ma);
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
ma2sa(union meta_addr ma)
{
	uint32_t sa;

	switch (ma.depth)
	{
	case 0:
		sa = sc.superblock.fd_root[ma.fd];
		break;
	case 1:
	case 2:
		if (sc.superblock.fd_root[ma.fd] == SECTOR_NULL ||
		    sc.superblock.fd_root[ma.fd] == SECTOR_DEL)
			sa = SECTOR_NULL;
		else {
			struct _fbuf *parent;	// parent buffer
			union meta_addr pma;	// parent's metadata address
			unsigned pindex;	// index in the parent indirect block

			pma = ma2pma(ma, &pindex);
			parent = fbuf_access(pma);
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
fbuf_mod_init(void)
{
	int fbuf_count;
	int i;

	//fbuf_count = sc.superblock.block_cnt_max / (SECTOR_SIZE / 4);
	fbuf_count = FBUF_MIN;
	if (fbuf_count < FBUF_MIN)
		fbuf_count = FBUF_MIN;
	if (fbuf_count > FBUF_MAX)
		fbuf_count = FBUF_MAX;
	sc.fbuf_count = fbuf_count;
	sc.fbufs = malloc(fbuf_count * sizeof(*sc.fbufs));
	KASSERT(sc.fbufs != NULL, "");

	for (i = 0; i < FBUF_BUCKET_CNT; ++i) {
		fbuf_bucket_init(i);
	}
	for (i = 0; i < QUEUE_CNT; ++i) {
		fbuf_queue_init(i);
	}
	// insert fbuf to both QUEUE_LEAF_CLEAN and hash queue
	for (i = 0; i < fbuf_count; ++i) {
		struct _fbuf *fbuf = &sc.fbufs[i];
#if defined(MY_DEBUG)
		fbuf->index = i;
#endif
		fbuf->fc.is_sentinel = false;
		fbuf->fc.accessed = false;
		fbuf->fc.modified = false;
		fbuf_queue_insert_tail(QUEUE_LEAF_CLEAN, fbuf);
		// insert fbuf to the last fbuf bucket
		// this bucket is not used in hash search
		// init parent, child_cnt and ma before inserting into FBUF_BUCKET_LAST
		fbuf->parent = NULL;
		fbuf->child_cnt = 0;
		fbuf->ma.uint32 = META_INVALID;
		fbuf_bucket_insert_head(FBUF_BUCKET_LAST, fbuf);
	}
	sc.fbuf_alloc = &sc.fbufs[0];;
	sc.fbuf_hit = sc.fbuf_miss = 0;
}

static void
fbuf_mod_fini(void)
{
	fbuf_cache_flush();
	free(sc.fbufs);
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
fbuf_clean_queue_check(void)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;

	if (sc.fbuf_queue_len[QUEUE_LEAF_CLEAN] > FBUF_CLEAN_THRESHOLD)
		return;

	fbuf_cache_flush();
	// move all parent nodes with child_cnt 0 to clean queue and last bucket
	for (int i = QUEUE_IND1; i >= QUEUE_IND0; --i) {
		queue_sentinel = &sc.fbuf_queue[i];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			KASSERT(fbuf->queue_which == i, "");
			struct _fbuf *fbuf_next = fbuf->fc.queue_next;
			if (fbuf->child_cnt == 0) {
				fbuf_queue_remove(fbuf);
				fbuf->fc.accessed = false; // so that it can be replaced faster
				fbuf_queue_insert_tail(QUEUE_LEAF_CLEAN, fbuf);
				if (fbuf->parent) {
					KASSERT(i == QUEUE_IND1, "");
					struct _fbuf *parent = fbuf->parent;
					--parent->child_cnt;
					KASSERT(parent->child_cnt <= SECTOR_SIZE/4, "");
					fbuf->parent = NULL;
				}
				// move it to the last bucket so that it cannot be searched
				// fbufs on the last bucket will have the metadata address META_INVALID
				fbuf_bucket_remove(fbuf);
				KASSERT(fbuf->parent == NULL, "");
				KASSERT(fbuf->child_cnt == 0, "");
				fbuf->ma.uint32 = META_INVALID;
				fbuf_bucket_insert_head(FBUF_BUCKET_LAST, fbuf);
			}
			fbuf = fbuf_next;
		}
	}
}

// write back all the dirty fbufs to disk
static void
fbuf_cache_flush(void)
{
	int	i;
	struct _fbuf *fbuf;
	struct _fbuf *clean_next, *dirty_next, *dirty_prev;
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf_sentinel *dirty_sentinel;
	struct _fbuf_sentinel *clean_sentinel;

	// write back all the dirty leaf nodes to disk
	queue_sentinel = &sc.fbuf_queue[QUEUE_LEAF_DIRTY];
	fbuf = queue_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)queue_sentinel) {
		KASSERT(fbuf->queue_which == QUEUE_LEAF_DIRTY, "");
		KASSERT(IS_META_ADDR(fbuf->ma.uint32), "");
		KASSERT(fbuf->fc.modified, "");
		// for dirty leaf nodes it's always dirty
		fbuf_write(fbuf);
		fbuf = fbuf->fc.queue_next;
	}

	// write back all the modified internal nodes to disk
	for (i = QUEUE_IND1; i >= 0; --i) {
		queue_sentinel = &sc.fbuf_queue[i];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			KASSERT(fbuf->queue_which == i, "");
			KASSERT(IS_META_ADDR(fbuf->ma.uint32), "");
			// for non-leaf nodes the fbuf might not be modified
			if (__predict_true(fbuf->fc.modified))
				fbuf_write(fbuf);
			fbuf = fbuf->fc.queue_next;
		}
	}
	seg_sum_write();
	superblock_write();

	dirty_sentinel = &sc.fbuf_queue[QUEUE_LEAF_DIRTY];
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
	clean_sentinel = &sc.fbuf_queue[QUEUE_LEAF_CLEAN];
	clean_next = clean_sentinel->fc.queue_next;
	clean_sentinel->fc.queue_next = dirty_next;
	dirty_next->fc.queue_prev = (struct _fbuf *)clean_sentinel;
	dirty_prev->fc.queue_next = clean_next;
	clean_next->fc.queue_prev = dirty_prev;
	sc.fbuf_queue_len[QUEUE_LEAF_CLEAN] += sc.fbuf_queue_len[QUEUE_LEAF_DIRTY];
	sc.fbuf_queue_len[QUEUE_LEAF_DIRTY] = 0;
	queue_init(dirty_sentinel);
	// don't need to change clean queue's head
}

// flush the cache and invalid fbufs with file descriptors fd1 or fd2
static void
fbuf_cache_flush_and_invalidate_fd(int fd1, int fd2)
{
	struct _fbuf *fbuf;

	fbuf_cache_flush();
	for (int i = 0; i < sc.fbuf_count; ++i)
	{
		fbuf = &sc.fbufs[i];
		if (fbuf->ma.uint32 == META_INVALID) {
			// the fbufs with metadata address META_INVALID are
			// linked in bucket FBUF_BUCKET_LAST
			KASSERT(fbuf->bucket_which == FBUF_BUCKET_LAST, "fbuf on the wrong bucket");
			continue;
		}
		// move fbufs with fd equals to fd1 or fd2 to the last bucket
		if (fbuf->ma.fd == fd1 || fbuf->ma.fd == fd2) {
			KASSERT(fbuf->bucket_which != FBUF_BUCKET_LAST, "must not on the last bucket");
			fbuf_bucket_remove(fbuf);
			// init parent, child_cnt and ma before inserting to bucket FBUF_BUCKET_LAST
			fbuf->parent = NULL;
			fbuf->child_cnt = 0;
			fbuf->ma.uint32 = META_INVALID;
			fbuf_bucket_insert_head(FBUF_BUCKET_LAST, fbuf);
			fbuf->fc.accessed = false; // so it will be recycled sooner
			if (fbuf->queue_which != QUEUE_LEAF_CLEAN) {
				// it is an internal node, move it to QUEUE_LEAF_CLEAN
				KASSERT(fbuf->queue_which != QUEUE_LEAF_DIRTY, "cannot be on the dirty queue since the cache has been flushed");
				fbuf_queue_remove(fbuf);
				fbuf_queue_insert_tail(QUEUE_LEAF_CLEAN, fbuf);
			}
		}
	}
}

static void
fbuf_queue_init(int which)
{
	struct _fbuf *fbuf;

	KASSERT(which < QUEUE_CNT, "which must be within the queue count");
	sc.fbuf_queue_len[which] = 0;
	fbuf = (struct _fbuf *)&sc.fbuf_queue[which];
	fbuf->fc.queue_next = fbuf;
	fbuf->fc.queue_prev = fbuf;
	fbuf->fc.is_sentinel = true;
	fbuf->fc.accessed = true;
	fbuf->fc.modified = false;
}

static void
fbuf_queue_insert_tail(int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *queue_head;
	struct _fbuf *prev;

	KASSERT(which < QUEUE_CNT, "which must be within the queue count");
	KASSERT(which != QUEUE_LEAF_CLEAN || !fbuf->fc.modified, "if on clean queue, it must be unmodified");
	fbuf->queue_which = which;
	queue_head = &sc.fbuf_queue[which];
	prev = queue_head->fc.queue_prev;
	KASSERT(prev->fc.is_sentinel || prev->queue_which == which, "prev must be on the same queue as fbuf");
	queue_head->fc.queue_prev = fbuf;
	fbuf->fc.queue_next = (struct _fbuf *)queue_head;
	fbuf->fc.queue_prev = prev;
	prev->fc.queue_next = fbuf;
	++sc.fbuf_queue_len[which];
}

static void
fbuf_queue_remove(struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;
	int which = fbuf->queue_which;

	KASSERT(fbuf != (struct _fbuf *)&sc.fbuf_queue[which], "fbuf cannot be the sentinel node");
	prev = fbuf->fc.queue_prev;
	next = fbuf->fc.queue_next;
	KASSERT(prev->fc.is_sentinel || prev->queue_which == which, "prev must be on the same queue as fbuf");
	KASSERT(next->fc.is_sentinel || next->queue_which == which, "next must be on the same queue as fbuf");
	prev->fc.queue_next = next;
	next->fc.queue_prev = prev;
	--sc.fbuf_queue_len[which];
}

// insert to the head of the hashed bucket
static void
fbuf_hash_insert_head(struct _fbuf *fbuf)
{
	unsigned hash;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = fbuf->ma.uint32 % FBUF_BUCKET_LAST;
	fbuf_bucket_insert_head(hash, fbuf);
}

static void
fbuf_bucket_init(int which)
{
	struct _fbuf_sentinel *bucket_head;

#if defined(MY_DEBUG)
	KASSERT(which < FBUF_BUCKET_CNT, "which must be within the bucket range");
	sc.fbuf_bucket_len[which] = 0;
#endif
	bucket_head = &sc.fbuf_bucket[which];
	bucket_head->fc.queue_next = (struct _fbuf *)bucket_head;
	bucket_head->fc.queue_prev = (struct _fbuf *)bucket_head;
	bucket_head->fc.is_sentinel = true;
}

static void
fbuf_bucket_insert_head(int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *bucket_head;
	struct _fbuf *next;

#if defined(MY_DEBUG)
	KASSERT(which < FBUF_BUCKET_CNT, "which must be within the bucket range");
	fbuf->bucket_which = which;
	++sc.fbuf_bucket_len[which];
#endif
	bucket_head = &sc.fbuf_bucket[which];
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
fbuf_bucket_remove(struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;
#if defined(MY_DEBUG)
	struct _fbuf_sentinel *bucket_head;
	int which = fbuf->bucket_which;

	KASSERT(which < FBUF_BUCKET_CNT, "which must be within the bucket range");
	--sc.fbuf_bucket_len[which];
	bucket_head = &sc.fbuf_bucket[which];
	KASSERT(fbuf != (struct _fbuf *)bucket_head, "fbuf cannot be the sentinel node");
#endif

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
fbuf_search(union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf	*fbuf;
	struct _fbuf_sentinel	*bucket_sentinel;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = ma.uint32 % FBUF_BUCKET_LAST;
	bucket_sentinel = &sc.fbuf_bucket[hash];
	fbuf = bucket_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)bucket_sentinel) {
		if (fbuf->ma.uint32 == ma.uint32) { // cache hit
			++sc.fbuf_hit;
			return fbuf;
		}
		fbuf = fbuf->bucket_next;
	}
	++sc.fbuf_miss;
	return NULL;	// cache miss
}

/*
Description:
  using the second chance replace policy to choose a fbuf in QUEUE_LEAF_CLEAN
*/
struct _fbuf *
fbuf_alloc(union meta_addr ma, int depth)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf, *parent;

	queue_sentinel = &sc.fbuf_queue[QUEUE_LEAF_CLEAN];
	fbuf = sc.fbuf_alloc;
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
		KASSERT(fbuf != (struct _fbuf *)queue_sentinel, "fbuf cannot be the sentinel node");
		goto again;
	}

	KASSERT(!fbuf->fc.modified, "the fbuf on QUEUE_LEAF_CLEAN must be unmodified");
	KASSERT(fbuf->child_cnt == 0, "the children count for fbufs on leaf level must be 0");
	sc.fbuf_alloc = fbuf->fc.queue_next;
	if (depth != META_LEAF_DEPTH) {
		// for fbuf allocated for internal nodes insert it immediately
		// to its internal queue
		fbuf_queue_remove(fbuf);
		fbuf_queue_insert_tail(depth, fbuf);
	}
	fbuf_bucket_remove(fbuf);
	fbuf->ma = ma;
	fbuf_hash_insert_head(fbuf);
	parent = fbuf->parent;
	if (parent) {
		// parent with child_cnt == 0 will stay in its queue
		// it will only be moved to QUEUE_LEAF_CLEAN in fbuf_clean_queue_check()
		--parent->child_cnt;
		KASSERT(parent->child_cnt <= SECTOR_SIZE/4, "check for wrap around");
		KASSERT(parent->queue_which == parent->ma.depth, "must be on the correct queue");
	}
	return fbuf;
}

#if defined(MY_DEBUG)
static struct _fbuf *depth[3];
#endif
/*
Description:
    Read or write the file buffer with metadata address @ma
*/
static struct _fbuf *
fbuf_access(union meta_addr ma)
{
	uint32_t sa;	// sector address where the metadata is stored
	unsigned index;
	union meta_addr	ima;	// the intermediate metadata address
	struct _fbuf *parent;	// parent buffer
	struct _fbuf *fbuf;

	KASSERT(IS_META_ADDR(ma.uint32), "must be a metadata address");
	KASSERT(ma.depth <= META_LEAF_DEPTH, "");

	// get the root sector address of the file %ma.fd
	sa = sc.superblock.fd_root[ma.fd];
	KASSERT(sa != SECTOR_DEL, "the root sector cannot be SECTOR_DEL");

	fbuf = fbuf_search(ma);
	if (fbuf != NULL) // cache hit
		goto end;

	// cache miss
	parent = NULL;	// parent for root is NULL
	ima = (union meta_addr){.meta = 0xFF};	// set .meta to 0xFF and all others to 0
	ima.fd = ma.fd;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		ima.depth = i;
		fbuf = fbuf_search(ima);
#if defined(MY_DEBUG)
		depth[i] = fbuf;
#endif
		if (fbuf == NULL) {
			fbuf = fbuf_alloc(ima, i);	// allocate a fbuf from clean queue
			fbuf->parent = parent;
			if (parent) {
				// parent with child_cnt == 0 will stay in its queue
				// it will only be moved to QUEUE_LEAF_CLEAN in fbuf_clean_queue_check()
				++parent->child_cnt;
				KASSERT(parent->child_cnt <= SECTOR_SIZE/4, "the maximum number of children is SECTOR_SIZE/4");
			} else {
				KASSERT(i == 0, "if no parent, it must be depth 0");
			}
			if (sa == SECTOR_NULL) {
				bzero(fbuf->data, sizeof(fbuf->data));
				if (i == 0)
					sc.superblock.fd_root[ma.fd] = SECTOR_CACHE;
			} else {
				KASSERT(sa >= SECTORS_PER_SEG, "sector address must not be within the first segment");
				my_read(sa, fbuf->data);
			}
#if defined(MY_DEBUG)
			fbuf->sa = sa;
			if (parent)
				parent->child[index] = fbuf;
#endif
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
fbuf_write(struct _fbuf *fbuf)
{
	struct _fbuf *parent;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address

	KASSERT(fbuf->fc.modified, "fbuf must have been modified");
	sa = _logstor_write(fbuf->ma.uint32, fbuf->data);
#if defined(MY_DEBUG)
	fbuf->sa = sa;
#endif
	fbuf->fc.modified = false;

	// update the sector address of this fbuf in its parent's fbuf
	parent = fbuf->parent;
	if (parent) {
		KASSERT(fbuf->ma.depth != 0, "depth cannot be 0 if it has parent");
		KASSERT(parent->ma.depth == fbuf->ma.depth - 1, "parent depth must qeual to child depth minus 1");
		pindex = ma_index_get(fbuf->ma, fbuf->ma.depth - 1);
		parent->data[pindex] = sa;
		parent->fc.modified = true;
	} else {
		KASSERT(fbuf->ma.depth == 0, "depth must be 0 if it doesn't have parent");
		// store the root sector address to the corresponding file table in super block
		sc.superblock.fd_root[fbuf->ma.fd] = sa;
		sc.sb_modified = true;
	}
}

DECLARE_GEOM_CLASS(g_logstor_class, g_logstor);
MODULE_VERSION(geom_logstor, 0);
