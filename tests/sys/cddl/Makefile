
.include <src.opts.mk>

TESTSDIR=	${TESTSBASE}/sys/cddl

TESTS_SUBDIRS+=	${_zfs}

.if ${MK_ZFS_TESTS} != "no"
_zfs=	zfs
.endif

.include <bsd.test.mk>
