
.include <src.opts.mk>

SUBDIR= libpkgecc
.if ${MK_OPENSSL} != "no"
SUBDIR+=libcrypto libssl
.if ${MK_OPENSSH} != "no"
SUBDIR+=libssh
.endif
.endif

SUBDIR.${MK_TESTS}+= tests

.include <bsd.subdir.mk>
