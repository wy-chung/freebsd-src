
.include <src.opts.mk>
.include "${SRCTOP}/secure/ssh.mk"

CONFS=	ssh_config
CONFSDIR=	/etc/ssh
PROG=	ssh
LINKS=	${BINDIR}/ssh ${BINDIR}/slogin
MAN=	ssh.1 ssh_config.5
MLINKS=	ssh.1 slogin.1
PACKAGE=	ssh

SRCS=	ssh.c readconf.c clientloop.c sshtty.c \
	sshconnect.c sshconnect2.c mux.c

# gss-genr.c really belongs in libssh; see src/secure/lib/libssh/Makefile
SRCS+=	gss-genr.c

LIBADD=	ssh

.if ${MK_GSSAPI} != "no" && ${MK_KERBEROS_SUPPORT} != "no"
LIBADD+=	gssapi
.endif

LIBADD+=	crypto

.include <bsd.prog.mk>

.PATH:	${SSHDIR}
