
.include <src.opts.mk>
.include "${SRCTOP}/secure/ssh.mk"

PROG=	ssh-pkcs11-helper
SRCS=	ssh-pkcs11.c ssh-pkcs11-helper.c
MAN=	ssh-pkcs11-helper.8

LIBADD=	crypto ssh

.include <bsd.prog.mk>

.PATH:	${SSHDIR}
