
.include <src.opts.mk>

PACKAGE=	newsyslog

CONFS=	newsyslog.conf
PROG=	newsyslog
MAN=	newsyslog.8 newsyslog.conf.5
SRCS=	newsyslog.c ptimes.c
LIBADD=	sbuf util

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests
SUBDIR+=	newsyslog.conf.d

.include <bsd.prog.mk>
