
MAN=

.include <src.opts.mk>

.PATH: ${SRCTOP}/contrib/ntp/ntpq

BINDIR=	/usr/bin

PROG=	ntpq
SRCS= 	ntpq.c ntpq-opts.c ntpq-subs.c version.c

CFLAGS+= -I${SRCTOP}/contrib/ntp/include \
	-I${SRCTOP}/contrib/ntp/include \
	-I${SRCTOP}/contrib/ntp/libntp/lib/isc/include \
	-I${SRCTOP}/contrib/ntp/libntp/lib/isc/unix/include \
	-I${SRCTOP}/contrib/ntp/libntp/lib/isc/pthreads/include \
	-I${SRCTOP}/contrib/ntp/libntp/lib/isc/${NTP_ATOMIC}/include \
	-I${SRCTOP}/contrib/ntp/sntp/libopts \
	-I${.CURDIR:H}

LIBADD+=	edit ntp opts m md pthread

.if ${MK_OPENSSL} != "no"
LIBADD+=	crypto
.endif

CLEANFILES+= .version version.c

version.c:
	sh -e ${.CURDIR:H}/scripts/mkver ntpq

.include <bsd.prog.mk>
