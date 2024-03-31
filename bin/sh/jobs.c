/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Kenneth Almquist.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 */

#ifndef lint
#if 0
static char sccsid[] = "@(#)jobs.c	8.5 (Berkeley) 5/4/95";
#endif
#endif /* not lint */
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "shell.h"
#if JOBS
#include <termios.h>
#undef CEOF			/* syntax.h redefines this */
#endif
#include "redir.h"
#include "exec.h"
#include "show.h"
#include "main.h"
#include "parser.h"
#include "nodes.h"
#include "jobs.h"
#include "options.h"
#include "trap.h"
#include "syntax.h"
#include "input.h"
#include "output.h"
#include "memalloc.h"
#include "error.h"
#include "mystring.h"
#include "var.h"
#include "builtins.h"
#include "eval.h"

/*
 * A job structure contains information about a job.  A job is either a
 * single process or a set of processes contained in a pipeline.  In the
 * latter case, pidlist will be non-NULL, and will point to a -1 terminated
 * array of pids.
 */

struct procstat {
	pid_t pid;		/* process id */
	int status;		/* status flags (defined above) */
	char *cmd;		/* text of command being run */
};

/* states */
enum job_state {
	JOBRUNNING,
	JOBSTOPPED,	/* all procs are stopped */
	JOBDONE,	/* all procs are completed */
};

struct job {
	struct procstat ps0;	/* status of process */
	struct procstat *ps;	/* status or processes when more than one */
	short nprocs;		/* number of processes */
	pid_t pgrp;		/* process group of this job */
	char state;		// see enum job_state
	bool used;		/* true if this entry is in used */
	bool changed;		/* true if status has changed */
	bool foreground;	/* true if running in the foreground */
	bool remembered;	/* true if $! referenced */
	char pipefail;		/* pass any non-zero status */
#if JOBS
	bool jobctl;		/* job running under job control */
	struct job *next;	/* job used after this one */
#endif
};

static struct job *jobtab;	/* array of jobs */
static int njobs;		/* size of array */
static pid_t backgndpid = -1;	/* pid of last background process */
static struct job *bgjob = NULL; /* last background process */
#if JOBS
static struct job *jobmru;	/* most recently used job list */
static pid_t initialpgrp;	/* pgrp of shell on invocation */
#endif
static int ttyfd = -1;

/* mode flags for dowait */
#define DOWAIT_BLOCK	0x1 /* wait until a child exits */
#define DOWAIT_SIG	0x2 /* if DOWAIT_BLOCK, abort on signal */
#define DOWAIT_SIG_TRAP	0x4 /* if DOWAIT_SIG, abort on trapped signal only */

#if JOBS
static void restartjob(struct job *);
#endif
static void freejob(struct job *);
static int waitcmdloop(struct job *);
static struct job *getjob_nonotfound(const char *);
static struct job *getjob(const char *);
pid_t killjob(const char *, int);
static pid_t dowait(int, struct job *);
static void checkzombies(void);
static void cmdtxt(union node *);
static void cmdputs(const char *);
#if JOBS
static void setcurjob(struct job *);
static void deljob(struct job *);
static struct job *getcurjob(struct job *);
#endif
static int getjobstatus(const struct job *);
static void printjobcmd(struct job *);
static void showjob(struct job *, int);

/*
 * Turn job control on and off.
 */

static _Thread_local bool jobctl;

#if JOBS
static void
jobctl_notty(void)
{
	if (ttyfd >= 0) {
		close(ttyfd);
		ttyfd = -1;
	}
	if (!iflag) {
		setsignal(SIGTSTP);
		setsignal(SIGTTOU);
		setsignal(SIGTTIN);
		jobctl = true;
		return;
	}
	out2fmt_flush("sh: can't access tty; job control turned off\n");
	mflag = 0;
}

void
setjobctl(bool on)
{
	int i;

	if (on == jobctl || !rootshell)
		return;
	if (on) {
		if (ttyfd != -1)
			close(ttyfd);
		if ((ttyfd = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) < 0) {
			i = 0;
			while (i <= 2 && !isatty(i))
				i++;
			if (i > 2 ||
			    (ttyfd = fcntl(i, F_DUPFD_CLOEXEC, 10)) < 0) {
				jobctl_notty();
				return;
			}
		}
		if (ttyfd < 10) {
			/*
			 * Keep our TTY file descriptor out of the way of
			 * the user's redirections.
			 */
			if ((i = fcntl(ttyfd, F_DUPFD_CLOEXEC, 10)) < 0) {
				jobctl_notty();
				return;
			}
			close(ttyfd);
			ttyfd = i;
		}
		do { /* while we are in the background */
			initialpgrp = tcgetpgrp(ttyfd);
			if (initialpgrp < 0) {
				jobctl_notty();
				return;
			}
			if (initialpgrp != getpgrp()) {
				if (!iflag) {
					initialpgrp = -1;
					jobctl_notty();
					return;
				}
				kill(0, SIGTTIN);
				continue;
			}
		} while (0);
		setsignal(SIGTSTP);
		setsignal(SIGTTOU);
		setsignal(SIGTTIN);
		setpgid(0, rootpid);
		tcsetpgrp(ttyfd, rootpid);
	} else { /* turning job control off */
		setpgid(0, initialpgrp);
		if (ttyfd >= 0) {
			tcsetpgrp(ttyfd, initialpgrp);
			close(ttyfd);
			ttyfd = -1;
		}
		setsignal(SIGTSTP);
		setsignal(SIGTTOU);
		setsignal(SIGTTIN);
	}
	jobctl = on;
}
#endif

#if JOBS
int
fgcmd(int argc __unused, char **argv __unused)
{
	struct job *jp;
	pid_t pgrp;
	int status;

	nextopt("");
	jp = getjob(*argptr);
	if (!jp->jobctl)
		error("job not created under job control");
	printjobcmd(jp);
	flushout(&output);
	pgrp = jp->ps[0].pid;
	if (ttyfd >= 0)
		tcsetpgrp(ttyfd, pgrp);
	restartjob(jp);
	jp->foreground = true;
	INTOFF;
	status = waitforjob(jp, (bool *)NULL);
	INTON;
	return status;
}

int
bgcmd(int argc __unused, char **argv __unused) // refer to int (*const builtinfunc[])(int, char **)
{
	struct job *jp;

	nextopt("");
	do {
		jp = getjob(*argptr);
		if (!jp->jobctl)
			error("job not created under job control");
		if (jp->state == JOBDONE)
			continue;
		restartjob(jp);
		jp->foreground = false;
		out1fmt("[%td] ", jp - jobtab + 1);
		printjobcmd(jp);
	} while (*argptr != NULL && *++argptr != NULL);
	return 0;
}

static void
restartjob(struct job *jp)
{

	if (jp->state == JOBDONE)
		return;
	setcurjob(jp);
	INTOFF;
	kill(-jp->ps[0].pid, SIGCONT);
	for (int i = 0; i < jp->nprocs; ++i ) {
		if (WIFSTOPPED(jp->ps[i].status)) {
			jp->ps[i].status = -1;
			jp->state = JOBRUNNING;
		}
	}
	INTON;
}
#endif

int
jobscmd(int argc __unused, char *argv[] __unused) // refer to int (*const builtinfunc[])(int, char **)
{
	char *id;
	int ch, mode;

	mode = SHOWJOBS_DEFAULT;
	while ((ch = nextopt("lps")) != '\0') {
		switch (ch) {
		case 'l':
			mode = SHOWJOBS_VERBOSE;
			break;
		case 'p':
			mode = SHOWJOBS_PGIDS;
			break;
		case 's':
			mode = SHOWJOBS_PIDS;
			break;
		}
	}

	if (*argptr == NULL)
		showjobs(false, mode);
	else
		while ((id = *argptr++) != NULL)
			showjob(getjob(id), mode);

	return (0);
}

static int getjobstatus(const struct job *jp)
{

	if (!jp->pipefail)
		return (jp->ps[jp->nprocs - 1].status);
	for (int i = jp->nprocs - 1; i >= 0; i--) {
		int status = jp->ps[i].status;
		if (status != 0)
			return (status);
	}
	return (0);
}

static void
printjobcmd(struct job *jp)
{

	for (int i = 0; i < jp->nprocs; ++i) {
		out1str(jp->ps[i].cmd);
		if (i != jp->nprocs - 1)
			out1str(" | ");
	}
	out1c('\n');
}

static void
showjob(struct job *jp, int mode)
{
	const char *statestr, *coredump;
	int curr, jobno, prev, nprocs, status;

	nprocs = (mode == SHOWJOBS_PGIDS) ? 1 : jp->nprocs;
	jobno = jp - jobtab + 1;
	curr = prev = 0;
#if JOBS
	struct job *j;
	if ((j = getcurjob(NULL)) != NULL) {
		curr = j - jobtab + 1;
		if ((j = getcurjob(j)) != NULL)
			prev = j - jobtab + 1;
	}
#endif
	coredump = "";
	status = getjobstatus(jp);
	if (jp->state == JOBRUNNING) {
		statestr = "Running";
#if JOBS
	} else if (jp->state == JOBSTOPPED) {
		int sig;
		struct procstat *ps = &jp->ps[jp->nprocs - 1];

		while (!WIFSTOPPED(ps->status) && ps > jp->ps)
			ps--;
		if (WIFSTOPPED(ps->status))
			sig = WSTOPSIG(ps->status);
		else
			sig = -1;
		statestr = strsignal(sig);
		if (statestr == NULL)
			statestr = "Suspended";
#endif
	} else if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0)
			statestr = "Done";
		else {
			char statebuf[16];
			fmtstr(statebuf, sizeof(statebuf), "Done(%d)",
			    WEXITSTATUS(status));
			statestr = statebuf;
		}
	} else {
		int sig = WTERMSIG(status);
		statestr = strsignal(sig);
		if (statestr == NULL)
			statestr = "Unknown signal";
		if (WCOREDUMP(status))
			coredump = " (core dumped)";
	}

	for (int i = 0; i< nprocs; ++i ) { /* for each process */
		int col;
		char c;
		char s[63];

		if (mode == SHOWJOBS_PIDS || mode == SHOWJOBS_PGIDS) {
			out1fmt("%d\n", (int)jp->ps[i].pid);
			continue;
		}
		if (mode != SHOWJOBS_VERBOSE && i != 0)
			continue;
		if (jobno == curr && i == 0)
			c = '+';
		else if (jobno == prev && i == 0)
			c = '-';
		else
			c = ' ';
		if (i == 0)
			fmtstr(s, sizeof(s), "[%d] %c ", jobno, c); //wyctodo
		else
			fmtstr(s, sizeof(s), "    %c ", c); //wyctodo
		out1str(s);
		col = strlen(s);
		if (mode == SHOWJOBS_VERBOSE) {
			fmtstr(s, sizeof(s), "%d ", (int)jp->ps[i].pid); //wyctodo
			out1str(s);
			col += strlen(s);
		}
		if (i == 0) {
			out1str(statestr);
			out1str(coredump);
			col += strlen(statestr) + strlen(coredump);
		}
		do {
			out1c(' ');
			col++;
		} while (col < 30);
		if (mode == SHOWJOBS_VERBOSE) {
			out1str(jp->ps[i].cmd);
			out1c('\n');
		} else
			printjobcmd(jp);
	}
}

/*
 * Print a list of jobs.  If "change" is nonzero, only print jobs whose
 * statuses have changed since the last call to showjobs.
 *
 * If the shell is interrupted in the process of creating a job, the
 * result may be a job structure containing zero processes.  Such structures
 * will be freed here.
 */
void
showjobs(bool change, int mode)
{

	TRACE(("showjobs(%d) called\n", change));
	checkzombies();
	for (int i = 0; i < njobs ; ++i) {
		if (! jobtab[i].used)
			continue;
		if (jobtab[i].nprocs == 0) {
			freejob(&jobtab[i]);
			continue;
		}
		if (change && !jobtab[i].changed)
			continue;
		showjob(&jobtab[i], mode);
		if (mode == SHOWJOBS_DEFAULT || mode == SHOWJOBS_VERBOSE) {
			jobtab[i].changed = false;
			/* Hack: discard jobs for which $! has not been
			 * referenced in interactive mode when they terminate.
			 */
			if (jobtab[i].state == JOBDONE && !jobtab[i].remembered &&
					(iflag || &jobtab[i] != bgjob)) {
				freejob(&jobtab[i]);
			}
		}
	}
}

/*
 * Mark a job structure as unused.
 */
static void
freejob(struct job *jp)
{

	INTOFF;
	if (bgjob == jp)
		bgjob = NULL;
	for (int i = 0; i < jp->nprocs; ++i) {
		if (jp->ps[i].cmd != nullstr)
			ckfree(jp->ps[i].cmd);
	}
	if (jp->ps != &jp->ps0)
		ckfree(jp->ps);
	jp->used = false;
#if JOBS
	deljob(jp);
#endif
	INTON;
}

int
waitcmd(int argc __unused, char **argv __unused) // refer to int (*const builtinfunc[])(int, char **)
{
	struct job *job;
	int retval;

	nextopt("");
	if (*argptr == NULL)
		return (waitcmdloop(NULL));

	do {
		job = getjob_nonotfound(*argptr);
		if (job == NULL)
			retval = 127;
		else
			retval = waitcmdloop(job);
		argptr++;
	} while (*argptr != NULL);

	return (retval);
}

static int
waitcmdloop(struct job *job)
{
	int status, retval, sig;
	struct job *jp;

	/*
	 * Loop until a process is terminated or stopped, or a SIGINT is
	 * received.
	 */
	do {
		if (job != NULL) {
			if (job->state == JOBDONE) {
				status = getjobstatus(job);
				if (WIFEXITED(status))
					retval = WEXITSTATUS(status);
				else
					retval = WTERMSIG(status) + 128;
				if (! iflag || ! job->changed)
					freejob(job);
				else {
					job->remembered = false;
					if (job == bgjob)
						bgjob = NULL;
				}
				return retval;
			}
		} else {
			if (njobs == 0)
				return 0;
			for (jp = jobtab ; jp < jobtab + njobs; jp++)
				if (jp->used && jp->state == JOBDONE) {
					if (! iflag || ! jp->changed)
						freejob(jp);
					else {
						jp->remembered = false;
						if (jp == bgjob)
							bgjob = NULL;
					}
				}
			for (jp = jobtab ; ; jp++) {
				if (jp >= jobtab + njobs) {	/* no running procs */
					return 0;
				}
				if (jp->used && jp->state == JOBRUNNING)
					break;
			}
		}
	} while (dowait(DOWAIT_BLOCK | DOWAIT_SIG, (struct job *)NULL) != -1);

	sig = pendingsig_waitcmd;
	pendingsig_waitcmd = 0;
	return sig + 128;
}

int
jobidcmd(int argc __unused, char **argv __unused) // refer to int (*const builtinfunc[])(int, char **)
{
	struct job *jp;
	int i;

	nextopt("");
	jp = getjob(*argptr);
	for (i = 0 ; i < jp->nprocs ; ) {
		out1fmt("%d", (int)jp->ps[i].pid);
		out1c(++i < jp->nprocs? ' ' : '\n');
	}
	return 0;
}

/*
 * Convert a job name to a job structure.
 */
static struct job *
getjob_nonotfound(const char *name)
{
	int jobno;
	struct job *found, *jp;
	size_t namelen;

	if (name == NULL) {
#if JOBS
		name = "%+";
#else
		error("No current job");
#endif
	}
	if (name[0] == '%') {
		if (is_digit(name[1])) {
			jobno = number(name + 1);
			if (jobno > 0 && jobno <= njobs
			 && jobtab[jobno - 1].used)
				return &jobtab[jobno - 1];
#if JOBS
		} else if ((name[1] == '%' || name[1] == '+') &&
		    name[2] == '\0') {
			if ((jp = getcurjob(NULL)) == NULL)
				error("No current job");
			return (jp);
		} else if (name[1] == '-' && name[2] == '\0') {
			if ((jp = getcurjob(NULL)) == NULL ||
			    (jp = getcurjob(jp)) == NULL)
				error("No previous job");
			return (jp);
#endif
		} else if (name[1] == '?') {
			found = NULL;
			for (int i = 0; i < njobs; ++i) {
				jp = &jobtab[i];
				if (jp->used && jp->nprocs > 0
				 && strstr(jp->ps[0].cmd, name + 2) != NULL) {
					if (found)
						error("%s: ambiguous", name);
					found = jp;
				}
			}
			if (found != NULL)
				return (found);
		} else {
			namelen = strlen(name);
			found = NULL;
			for (int i = 0; i < njobs; ++i ) {
				jp = &jobtab[i];
				if (jp->used && jp->nprocs > 0
				 && strncmp(jp->ps[0].cmd, name + 1,
				 namelen - 1) == 0) {
					if (found)
						error("%s: ambiguous", name);
					found = jp;
				}
			}
			if (found)
				return found;
		}
	} else if (is_number(name)) {
		pid_t pid = (pid_t)number(name);
		for (int i = 0; i < njobs; ++i ) {
			jp = &jobtab[i];
			if (jp->used && jp->nprocs > 0
			 && jp->ps[jp->nprocs - 1].pid == pid)
				return jp;
		}
	}
	return NULL;
}

static struct job *
getjob(const char *name)
{
	struct job *jp;

	jp = getjob_nonotfound(name);
	if (jp == NULL)
		error("No such job: %s", name);
	return (jp);
}

int
killjob(const char *name, int sig)
{
	struct job *jp;
	int i, ret;

	jp = getjob(name);
	if (jp->state == JOBDONE)
		return 0;
	if (jp->jobctl)
		return kill(-jp->ps[0].pid, sig);
	ret = -1;
	errno = ESRCH;
	for (i = 0; i < jp->nprocs; i++)
		if (jp->ps[i].status == -1 || WIFSTOPPED(jp->ps[i].status)) {
			if (kill(jp->ps[i].pid, sig) == 0)
				ret = 0;
		} else
			ret = 0;
	return ret;
}

/*
 * Return a new job structure,
 */
struct job *
makejob(int nprocs)
{
	int i;
	struct job *jp;

	for (i = 0; i < njobs; ++i) {
		jp = &jobtab[i];
		if (!jp->used)
			break;
	}
	if (i == njobs) { // didn't find an unused entry
		INTOFF;
		if (njobs == 0) {
			jobtab = ckmalloc(4 * sizeof jobtab[0]);
#if JOBS
			jobmru = NULL;
#endif
		} else {
			jp = ckmalloc((njobs + 4) * sizeof jobtab[0]);
			memcpy(jp, jobtab, njobs * sizeof jp[0]);
#if JOBS
			/* Relocate `next' pointers and list head */
			if (jobmru != NULL)
				jobmru = &jp[jobmru - jobtab];
			for (i = 0; i < njobs; i++)
				if (jp[i].next != NULL)
					jp[i].next = &jp[jp[i].next -
					    jobtab];
#endif
			if (bgjob != NULL)
				bgjob = &jp[bgjob - jobtab];
			/* Relocate `ps' pointers */
			for (i = 0; i < njobs; i++)
				if (jp[i].ps == &jobtab[i].ps0)
					jp[i].ps = &jp[i].ps0;
			ckfree(jobtab);
			jobtab = jp;
		}
		jp = jobtab + njobs;
		for (i = 4 ; --i >= 0 ; jobtab[njobs++].used = false)
			;
		INTON;
	}
	INTOFF;
	jp->nprocs = 0;
	jp->state = JOBRUNNING;
	jp->used = true;
	jp->changed = false;
	jp->foreground = false;
	jp->remembered = false;
	jp->pipefail = pipefailflag;
#if JOBS
	jp->jobctl = jobctl;
	jp->next = NULL;
#endif
	if (nprocs > 1) {
		jp->ps = ckmalloc(nprocs * sizeof (struct procstat));
	} else {
		jp->ps = &jp->ps0;
	}
	INTON;
	TRACE(("%s(%d) returns %%%td\n", __func__, nprocs, jp - jobtab + 1));
	return jp;
}

#if JOBS
static void
setcurjob(struct job *cj)
{
	struct job *jp, *prev;

	for (prev = NULL, jp = jobmru; jp != NULL; prev = jp, jp = jp->next) {
		if (jp == cj) {
			if (prev != NULL)
				prev->next = jp->next;
			else
				jobmru = jp->next;
			jp->next = jobmru;
			jobmru = cj;
			return;
		}
	}
	cj->next = jobmru;
	jobmru = cj;
}

static void
deljob(struct job *j)
{
	struct job *jp, *prev;

	for (prev = NULL, jp = jobmru; jp != NULL; prev = jp, jp = jp->next) {
		if (jp == j) {
			if (prev != NULL)
				prev->next = jp->next;
			else
				jobmru = jp->next;
			return;
		}
	}
}

/*
 * Return the most recently used job that isn't `nj', and preferably one
 * that is stopped.
 */
static struct job *
getcurjob(struct job *nj)
{
	struct job *jp;

	/* Try to find a stopped one.. */
	for (jp = jobmru; jp != NULL; jp = jp->next)
		if (jp->used && jp != nj && jp->state == JOBSTOPPED)
			return (jp);
	/* Otherwise the most recently used job that isn't `nj' */
	for (jp = jobmru; jp != NULL; jp = jp->next)
		if (jp->used && jp != nj)
			return (jp);

	return (NULL);
}
#endif

static void
forkshell_child(struct job *jp, enum fork_mode mode)
{
	bool wasroot;

	TRACE(("Child shell %d\n", (int)getpid()));
	wasroot = rootshell;
	rootshell = false;
	handler = &main_handler;
	closescript();
	INTON;
	forcelocal = 0;
	clear_traps(); //wyc may not be needed
#if JOBS
	jobctl = false;		/* do job control only in root shell */
	if (wasroot && mode != FORK_NOJOB && mflag) {
		pid_t pgrp;

		if (jp == NULL || jp->nprocs == 0)
			pgrp = getpid();
		else
			pgrp = jp->ps[0].pid;
		if (setpgid(0, pgrp) == 0 && mode == FORK_FG && ttyfd >= 0) {
			/*
			 * Each process in a pipeline must have the tty
			 * pgrp set before running its code.
			 * Only for pipelines of three or more processes
			 * could this be reduced to two calls.
			 */
			if (tcsetpgrp(ttyfd, pgrp) < 0)
				error("tcsetpgrp failed, errno=%d", errno);
		}
		setsignal(SIGTSTP);
		setsignal(SIGTTOU);
	} else if (mode == FORK_BG) {
		ignoresig(SIGINT);
		ignoresig(SIGQUIT);
		if ((jp == NULL || jp->nprocs == 0) &&
		    ! fd0_redirected_p ()) {
			close(0);
			if (open(_PATH_DEVNULL, O_RDONLY) != 0)
				error("cannot open %s: %s", _PATH_DEVNULL, strerror(errno));
		}
	}
#else // !JOBS
	if (mode == FORK_BG) {
		ignoresig(SIGINT);
		ignoresig(SIGQUIT);
		if ((jp == NULL || jp->nprocs == 0) && !fd0_redirected_p()) {
			close(0);
			if (open(_PATH_DEVNULL, O_RDONLY) != 0)
				error("cannot open %s: %s", _PATH_DEVNULL, strerror(errno));
		}
	}
#endif
	INTOFF;
	struct job *p = jobtab;
	for (int i = njobs; --i >= 0 ; p++)
		if (p->used)
			freejob(p);
	INTON;
	if (wasroot && iflag) {
		setsignal(SIGINT);
		setsignal(SIGQUIT);
		setsignal(SIGTERM);
	}
}

/*
 * Fork of a subshell.  If we are doing job control, give the subshell its
 * own process group.  Jp is a job structure that the job is to be added to.
 * N is the command that will be evaluated by the child.  Both jp and n may
 * be NULL.  The mode parameter can be one of the following:
 *	FORK_FG - Fork off a foreground process.
 *	FORK_BG - Fork off a background process.
 *	FORK_NOJOB - Like FORK_FG, but don't give the process its own
 *		     process group even if job control is on.
 *
 * When job control is turned off, background processes have their standard
 * input redirected to /dev/null (except for the second and later processes
 * in a pipeline).
 */
static volatile bool ischild;

pid_t
forkshell(struct job *jp, union node *n, enum fork_mode mode)
{
	pid_t pid;

	TRACE(("forkshell(%%%td, %p, %d) called\n", jp - jobtab, (void *)n, mode));
	INTOFF;
	if (mode == FORK_BG && (jp == NULL || jp->nprocs == 0))
		checkzombies();
	flushall();
	if (ischild) {
		//print_trace(__func__);
		//exit(1);
	}
	pid = fork();
	if (pid == 0) { // child
		//print_trace("child fork");
		ischild = true;
		forkshell_child(jp, mode);
	} else if (pid == -1) {
		TRACE(("Fork failed, errno=%d\n", errno));
		INTON;
		//print_trace();
		error("%s: Cannot fork: %s", __func__, strerror(errno));
		// will call a long jump
		/*NOTREACHED*/
	} else {
		if (rootshell && mode != FORK_NOJOB && mflag) {
			pid_t pgrp;

			if (jp == NULL || jp->nprocs == 0)
				pgrp = pid;
			else
				pgrp = jp->ps[0].pid;
			setpgid(pid, pgrp);
		}
		if (mode == FORK_BG) {
			if (bgjob != NULL && bgjob->state == JOBDONE &&
			    !bgjob->remembered && !iflag)
				freejob(bgjob);
			backgndpid = pid;		/* set $! */
			bgjob = jp;
		}
		if (jp) {
			struct procstat *ps = &jp->ps[jp->nprocs++];
			ps->pid = pid;
			ps->status = -1;
			ps->cmd = nullstr;
			if (iflag && rootshell && n)
				ps->cmd = commandtext(n);
			jp->foreground = mode == FORK_FG;
#if JOBS
			setcurjob(jp);
#endif
		}
		INTON;
		TRACE(("In parent shell:  child = %d\n", (int)pid));
	}
	return pid;
}

static void
vforkexecshell_child(char **argv, char **envp, const char *path, int idx, int pip[2])
{
	struct jmploc jmploc;

	TRACE(("Child shell %d\n", (int)getpid()));
	if (setjmp(jmploc.loc)) // return from longjmp
		_exit(exitstatus);
	if (pip != NULL) {
		close(pip[0]);
		if (pip[1] != 1) {
			dup2(pip[1], 1);
			close(pip[1]);
		}
	}
	handler = &jmploc;
	shellexec(argv, envp, path, idx);
	// will call execve or _exit at #1001
	/*NOTREACHED*/
}

void
vforkexecshell(struct job *jp, char **argv, char **envp, const char *path, int idx, int pip[2])
{
	pid_t pid;
	struct jmploc *savehandler;
	int inton;

	TRACE(("vforkexecshell(%%%td, %s, %p) called\n", jp - jobtab, argv[0],
	    (void *)pip));
	inton = is_int_on();
	INTOFF;
	flushall();
	savehandler = handler;
	if (ischild) {
		//print_trace(__func__);
		//exit(1);
	}
	pid = vfork();
	if (pid == 0) { // child
		fprintf(stderr, "child: vfork called\n");
		ischild = true;
		vforkexecshell_child(argv, envp, path, idx, pip);
		// will call execve or _exit
		/*NOTREACHED*/
	}
	ischild = false;
	if (pid == -1) {
		TRACE(("Vfork failed, errno=%d\n", errno));
		INTON;
		//print_trace();
		error("%s: Cannot fork: %s", __func__, strerror(errno));
		// will call a longjmp
		/*NOTREACHED*/
	} else { // parent
		handler = savehandler;
		if (jp) {
			struct procstat *ps = &jp->ps[jp->nprocs++];
			ps->pid = pid;
			ps->status = -1;
			ps->cmd = nullstr;
			jp->foreground = true;
#if JOBS
			setcurjob(jp);
#endif
		}
		SETINTON(inton);
		TRACE(("In parent shell:  child = %d\n", (int)pid));
	}
}

/*
 * Wait for job to finish.
 *
 * Under job control we have the problem that while a child process is
 * running interrupts generated by the user are sent to the child but not
 * to the shell.  This means that an infinite loop started by an inter-
 * active user may be hard to kill.  With job control turned off, an
 * interactive user may place an interactive program inside a loop.  If
 * the interactive program catches interrupts, the user doesn't want
 * these interrupts to also abort the loop.  The approach we take here
 * is to have the shell ignore interrupt signals while waiting for a
 * foreground process to terminate, and then send itself an interrupt
 * signal if the child process was terminated by an interrupt signal.
 * Unfortunately, some programs want to do a bit of cleanup and then
 * exit on interrupt; unless these processes terminate themselves by
 * sending a signal to themselves (instead of calling exit) they will
 * confuse this approach.
 */
int
waitforjob(struct job *jp, bool *signaled)
{
#if JOBS
	bool propagate_int = jp->jobctl && jp->foreground;
#endif
	int status;
	int st;

	INTOFF;
	TRACE(("waitforjob(%%%td) called\n", jp - jobtab + 1));
	while (jp->state == JOBRUNNING)
		if (dowait(DOWAIT_BLOCK | (Tflag ? DOWAIT_SIG | DOWAIT_SIG_TRAP : 0), jp) == -1)
			dotrap();
#if JOBS
	if (jp->jobctl) {
		if (ttyfd >= 0 && tcsetpgrp(ttyfd, rootpid) < 0)
			error("tcsetpgrp failed, errno=%d\n", errno);
	}
	if (jp->state == JOBSTOPPED)
		setcurjob(jp);
#endif
	status = getjobstatus(jp);
	if (signaled != NULL)
		*signaled = WIFSIGNALED(status);
	/* convert to 8 bits */
	if (WIFEXITED(status))
		st = WEXITSTATUS(status);
#if JOBS
	else if (WIFSTOPPED(status))
		st = WSTOPSIG(status) + 128;
#endif
	else
		st = WTERMSIG(status) + 128;
	if (! JOBS || jp->state == JOBDONE)
		freejob(jp);
	if (int_pending()) {
		if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGINT)
			CLEAR_PENDING_INT;
	}
#if JOBS
	else if (rootshell && propagate_int &&
			WIFSIGNALED(status) && WTERMSIG(status) == SIGINT)
		kill(getpid(), SIGINT);
#endif
	INTON;
	return st;
}

static void
dummy_handler(int sig __unused)
{
}

/*
 * Wait for a process to terminate.
 */
static pid_t
dowait(int mode, struct job *job)
{
	struct sigaction sa, osa;
	sigset_t mask, omask;
	pid_t pid;
	int status;
	struct procstat *sp;
	struct job *jp;
	struct job *thisjob;
	const char *sigstr;
	int done;
	int stopped;
	int sig;
	int coredump;
	int wflags;
	int restore_sigchld;

	TRACE(("dowait(%d, %p) called\n", mode, job));
	restore_sigchld = 0;
	if ((mode & DOWAIT_SIG) != 0) {
		sigfillset(&mask);
		sigprocmask(SIG_BLOCK, &mask, &omask);
		INTOFF;
		if (!issigchldtrapped()) {
			restore_sigchld = 1;
			sa.sa_handler = dummy_handler;
			sa.sa_flags = 0;
			sigemptyset(&sa.sa_mask);
			sigaction(SIGCHLD, &sa, &osa);
		}
	}
	do {
#if JOBS
		if (iflag)
			wflags = WUNTRACED | WCONTINUED;
		else
#endif
			wflags = 0;
		if ((mode & (DOWAIT_BLOCK | DOWAIT_SIG)) != DOWAIT_BLOCK)
			wflags |= WNOHANG;
		pid = wait3(&status, wflags, (struct rusage *)NULL);
		TRACE(("wait returns %d, status=%d\n", (int)pid, status));
		if (pid == 0 && (mode & DOWAIT_SIG) != 0) {
			pid = -1;
			if (((mode & DOWAIT_SIG_TRAP) != 0 ?
			    pendingsig : pendingsig_waitcmd) != 0) {
				errno = EINTR;
				break;
			}
			sigsuspend(&omask);
			if (int_pending())
				break;
		}
	} while (pid == -1 && errno == EINTR);
	if (pid == -1 && errno == ECHILD && job != NULL)
		job->state = JOBDONE;
	if ((mode & DOWAIT_SIG) != 0) {
		if (restore_sigchld)
			sigaction(SIGCHLD, &osa, NULL);
		sigprocmask(SIG_SETMASK, &omask, NULL);
		INTON;
	}
	if (pid <= 0)
		return pid;
	INTOFF;
	thisjob = NULL;
	for (jp = jobtab ; jp < jobtab + njobs ; jp++) {
		if (jp->used && jp->nprocs > 0) {
			done = 1;
			stopped = 1;
			for (sp = jp->ps ; sp < jp->ps + jp->nprocs ; sp++) {
				if (sp->pid == -1)
					continue;
				if (sp->pid == pid && (sp->status == -1 ||
				    WIFSTOPPED(sp->status))) {
					TRACE(("Changing status of proc %d from 0x%x to 0x%x\n",
						   (int)pid, sp->status,
						   status));
					if (WIFCONTINUED(status)) {
						sp->status = -1;
						jp->state = JOBRUNNING;
					} else
						sp->status = status;
					thisjob = jp;
				}
				if (sp->status == -1)
					stopped = 0;
				else if (WIFSTOPPED(sp->status))
					done = 0;
			}
			if (stopped) {		/* stopped or done */
				int state = done? JOBDONE : JOBSTOPPED;
				if (jp->state != state) {
					TRACE(("Job %td: changing state from %d to %d\n", jp - jobtab + 1, jp->state, state));
					jp->state = state;
					if (jp != job) {
						if (done && !jp->remembered &&
						    !iflag && jp != bgjob)
							freejob(jp);
#if JOBS
						else if (done)
							deljob(jp);
#endif
					}
				}
			}
		}
	}
	INTON;
	if (!thisjob || thisjob->state == JOBRUNNING)
		;
	else if ((!rootshell || !iflag || thisjob == job) &&
	    thisjob->foreground && thisjob->state != JOBSTOPPED) {
		sig = 0;
		coredump = 0;
		for (sp = thisjob->ps; sp < thisjob->ps + thisjob->nprocs; sp++)
			if (WIFSIGNALED(sp->status)) {
				sig = WTERMSIG(sp->status);
				coredump = WCOREDUMP(sp->status);
			}
		if (sig > 0 && sig != SIGINT && sig != SIGPIPE) {
			sigstr = strsignal(sig);
			if (sigstr != NULL)
				out2str(sigstr);
			else
				out2str("Unknown signal");
			if (coredump)
				out2str(" (core dumped)");
			out2c('\n');
			flushout(out2);
		}
	} else {
		TRACE(("Not printing status, rootshell=%d, job=%p\n", rootshell, job));
		thisjob->changed = true;
	}
	return pid;
}

/*
 * return 1 if there are stopped jobs, otherwise 0
 */
int job_warning = 0;
bool
stoppedjobs(void)
{
	int jobno;
	struct job *jp;

	if (job_warning)
		return (false);
	for (jobno = 1, jp = jobtab; jobno <= njobs; jobno++, jp++) {
		if (!jp->used)
			continue;
		if (jp->state == JOBSTOPPED) {
			out2fmt_flush("You have stopped jobs.\n");
			job_warning = 2;
			return (true);
		}
	}

	return (false);
}

static void
checkzombies(void)
{
	while (njobs > 0 && dowait(0, NULL) > 0)
		;
}

int
backgndpidset(void)
{
	return backgndpid != -1;
}

pid_t
backgndpidval(void)
{
	if (bgjob != NULL && !forcelocal)
		bgjob->remembered = true;
	return backgndpid;
}

/*
 * Return a string identifying a command (to be printed by the
 * jobs command.
 */
static char *cmdnextc;
static int cmdnleft;
#define MAXCMDTEXT	200

char *
commandtext(union node *n)
{
	char *name;

	cmdnextc = name = ckmalloc(MAXCMDTEXT);
	cmdnleft = MAXCMDTEXT - 4;
	cmdtxt(n);
	*cmdnextc = '\0';
	return name;
}

static void
cmdtxtdogroup(union node *n)
{
	cmdputs("; do ");
	cmdtxt(n);
	cmdputs("; done");
}

static void
cmdtxtredir(union node *n, const char *op, int deffd)
{
	char s[2];

	if (n->nfile.fd != deffd) {
		s[0] = n->nfile.fd + '0';
		s[1] = '\0';
		cmdputs(s);
	}
	cmdputs(op);
	if (n->type == NTOFD || n->type == NFROMFD) {
		if (n->ndup.dupfd >= 0)
			s[0] = n->ndup.dupfd + '0';
		else
			s[0] = '-';
		s[1] = '\0';
		cmdputs(s);
	} else {
		cmdtxt(n->nfile.fname);
	}
}

static void
cmdtxt(union node *n)
{
	union node *np;
	struct nodelist *lp;

	if (n == NULL)
		return;
	switch (n->type) {
	case NSEMI:
		cmdtxt(n->nbinary.ch1);
		cmdputs("; ");
		cmdtxt(n->nbinary.ch2);
		break;
	case NAND:
		cmdtxt(n->nbinary.ch1);
		cmdputs(" && ");
		cmdtxt(n->nbinary.ch2);
		break;
	case NOR:
		cmdtxt(n->nbinary.ch1);
		cmdputs(" || ");
		cmdtxt(n->nbinary.ch2);
		break;
	case NPIPE:
		for (lp = n->npipe.cmdlist ; lp ; lp = lp->next) {
			cmdtxt(lp->n);
			if (lp->next)
				cmdputs(" | ");
		}
		break;
	case NSUBSHELL:
		cmdputs("(");
		cmdtxt(n->nredir.n);
		cmdputs(")");
		break;
	case NREDIR:
	case NBACKGND:
		cmdtxt(n->nredir.n);
		break;
	case NIF:
		cmdputs("if ");
		cmdtxt(n->nif.test);
		cmdputs("; then ");
		cmdtxt(n->nif.ifpart);
		cmdputs("...");
		break;
	case NWHILE:
		cmdputs("while ");
		cmdtxt(n->nbinary.ch1);
		cmdtxtdogroup(n->nbinary.ch2);
		break;
	case NUNTIL:
		cmdputs("until ");
		cmdtxt(n->nbinary.ch1);
		cmdtxtdogroup(n->nbinary.ch2);
		break;
	case NFOR:
		cmdputs("for ");
		cmdputs(n->nfor.var);
		cmdputs(" in ...");
		break;
	case NCASE:
		cmdputs("case ");
		cmdputs(n->ncase.expr->narg.text);
		cmdputs(" in ...");
		break;
	case NDEFUN:
		cmdputs(n->narg.text);
		cmdputs("() ...");
		break;
	case NNOT:
		cmdputs("! ");
		cmdtxt(n->nnot.com);
		break;
	case NCMD:
		for (np = n->ncmd.args ; np ; np = np->narg.next) {
			cmdtxt(np);
			if (np->narg.next)
				cmdputs(" ");
		}
		for (np = n->ncmd.redirect ; np ; np = np->nfile.next) {
			cmdputs(" ");
			cmdtxt(np);
		}
		break;
	case NARG:
		cmdputs(n->narg.text);
		break;
	case NTO:
		cmdtxtredir(n, ">", 1);
		break;
	case NAPPEND:
		cmdtxtredir(n, ">>", 1);
		break;
	case NTOFD:
		cmdtxtredir(n, ">&", 1);
		break;
	case NCLOBBER:
		cmdtxtredir(n, ">|", 1);
		break;
	case NFROM:
		cmdtxtredir(n, "<", 0);
		break;
	case NFROMTO:
		cmdtxtredir(n, "<>", 0);
		break;
	case NFROMFD:
		cmdtxtredir(n, "<&", 0);
		break;
	case NHERE:
	case NXHERE:
		cmdputs("<<...");
		break;
	default:
		cmdputs("???");
		break;
	}
}

static void
cmdputs(const char *s)
{
	const char *p;
	char *q;
	char c;
	int subtype = 0;

	if (cmdnleft <= 0)
		return;
	p = s;
	q = cmdnextc;
	while ((c = *p++) != '\0') {
		if (c == CTLESC)
			*q++ = *p++;
		else if (c == CTLVAR) {
			*q++ = '$';
			if (--cmdnleft > 0)
				*q++ = '{';
			subtype = *p++;
			if ((subtype & VSTYPE) == VSLENGTH && --cmdnleft > 0)
				*q++ = '#';
		} else if (c == '=' && subtype != 0) {
			*q = "}-+?=##%%\0X"[(subtype & VSTYPE) - VSNORMAL];
			if (*q)
				q++;
			else
				cmdnleft++;
			if (((subtype & VSTYPE) == VSTRIMLEFTMAX ||
			    (subtype & VSTYPE) == VSTRIMRIGHTMAX) &&
			    --cmdnleft > 0)
				*q = q[-1], q++;
			subtype = 0;
		} else if (c == CTLENDVAR) {
			*q++ = '}';
		} else if (c == CTLBACKQ || c == CTLBACKQ+CTLQUOTE) {
			cmdnleft -= 5;
			if (cmdnleft > 0) {
				*q++ = '$';
				*q++ = '(';
				*q++ = '.';
				*q++ = '.';
				*q++ = '.';
				*q++ = ')';
			}
		} else if (c == CTLARI) {
			cmdnleft -= 2;
			if (cmdnleft > 0) {
				*q++ = '$';
				*q++ = '(';
				*q++ = '(';
			}
			p++;
		} else if (c == CTLENDARI) {
			if (--cmdnleft > 0) {
				*q++ = ')';
				*q++ = ')';
			}
		} else if (c == CTLQUOTEMARK || c == CTLQUOTEEND)
			cmdnleft++; /* ignore */
		else
			*q++ = c;
		if (--cmdnleft <= 0) {
			*q++ = '.';
			*q++ = '.';
			*q++ = '.';
			break;
		}
	}
	cmdnextc = q;
}
