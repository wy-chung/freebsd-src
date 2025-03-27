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

DECLARE_GEOM_CLASS(g_logstor_class, g_logstor);
MODULE_VERSION(geom_logstor, 0);
