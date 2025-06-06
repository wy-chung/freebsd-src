
#
# HOW TO UPDATE THE ZONEINFO DATA
#
# Import the new sources to the vendor branch:
#
# $ cd ~/freebsd/src
# $ git worktree add ../tzdata vendor/tzdata
# $ pushd ../tzdata
# $ tar -xvf ../tzdata-latest.tar.gz
#   (check with "git status" and "git diff" if it all makes sense)
# $ git add -A
# $ git commit -m "Import tzdata 20XXX"
# $ git tag -a -m "Tag import of tzdata 20XXX" vendor/tzdata/tzdata20XXX
# $ git push --follow-tags freebsd vendor/tzdata
# $ popd
#
# Merge-from-vendor
#
# $ git subtree merge -P contrib/tzdata vendor/tzdata
#   (write a meaningful commit message)
# $ git push freebsd HEAD:main
#
# MFC
#
# $ git checkout -b freebsd/stable/12 stable-12
# $ git cherry-pick -x [hash of merge commit to main] -m 1 --edit
#   (write a meaningful commit message)
# $ git push freebsd HEAD:stable/12
#
#
# If there are changes to zone1970.tab, update the baseline file by running
# `make baseline` in usr.sbin/tzsetup to check if tzsetup is able to parse new
# contents (if not, report/fix tzsetup).  Check that update does not
# introduce breaking/unexpected changes to continents/countries/zones,
# and commit the updated baseline file.

.include <src.opts.mk>

PACKAGE=	zoneinfo
CLEANDIRS+=	builddir
CONTRIBDIR=	${SRCTOP}/contrib/tzdata/
.PATH:		${CONTRIBDIR}

.if defined(LEAPSECONDS)
.warning Using backwards compatibility variable for LEAPSECONDS; please use WITH_ZONEINFO_LEAPSECONDS_SUPPORT instead
MK_ZONEINFO_LEAPSECONDS_SUPPORT= yes
.endif

.if ${MK_ZONEINFO_LEAPSECONDS_SUPPORT} != "no"
LEAPFILE=	-L ${CONTRIBDIR}leapseconds
.else
LEAPFILE=
.endif

TZFILES=	africa antarctica asia australasia etcetera europe \
		factory northamerica southamerica
TZFILES+=	backward

TZFILES:=	${TZFILES:S/^/${CONTRIBDIR}/}

TZBUILDDIR=	${.OBJDIR}/builddir
TZBUILDSUBDIRS=	\
		Africa \
		America/Argentina \
		America/Indiana \
		America/Kentucky \
		America/North_Dakota \
		Antarctica \
		Arctic \
		Asia \
		Atlantic \
		Australia \
		Etc \
		Europe \
		Indian \
		Pacific
TZBUILDSUBDIRS+= US Mexico Chile Canada Brazil

.if !defined(_SKIP_BUILD)
all: zonefiles
.endif
META_TARGETS+=	zonefiles install-zoneinfo

#
# Produce “fat” zoneinfo files for backward compatibility.
#
ZICFLAGS?=	-b fat

.if ${MK_DIRDEPS_BUILD} == "yes"
ZIC= ${STAGE_HOST_OBJTOP}/usr/sbin/zic
# we do everything in a single visit
install-zoneinfo: zonefiles
.endif

zonefiles: ${TDATA}
	mkdir -p ${TZBUILDDIR}
	(cd ${TZBUILDDIR}; mkdir -p ${TZBUILDSUBDIRS})
	(umask 022; cd ${.CURDIR}; \
	${ZIC:Uzic} -D -d ${TZBUILDDIR} ${ZICFLAGS} -m ${NOBINMODE} \
	    ${LEAPFILE} ${TZFILES})
	(umask 022; cd ${TZBUILDDIR}; \
	read -r version <${CONTRIBDIR}version && \
	LC_ALL=C awk \
	    -v DATAFORM='main' \
	    -v PACKRATDATA='' \
	    -v PACKRATLIST='' \
	    -f ${CONTRIBDIR}ziguard.awk ${TZFILES} >${TZBUILDDIR}/main.zi; \
	LC_ALL=C awk \
	    -v dataform='main' \
	    -v deps='zishrink.awk' \
	    -v redo='posix_only' \
	    -v version="$$version" \
	    -f ${CONTRIBDIR}zishrink.awk \
	main.zi >tzdata.zi; rm main.zi)
	(cd ${TZBUILDDIR} && find * -type f | LC_ALL=C sort) > ${.TARGET}

beforeinstall: install-zoneinfo
install-zoneinfo:
	mkdir -p ${DESTDIR}/usr/share/zoneinfo
	(cd ${DESTDIR}/usr/share/zoneinfo;  mkdir -p ${TZBUILDSUBDIRS})
	for f in `cat zonefiles`; do \
		${INSTALL} ${TAG_ARGS} \
		    -o ${BINOWN} -g ${BINGRP} -m ${NOBINMODE} \
		    ${TZBUILDDIR}/$${f} ${DESTDIR}/usr/share/zoneinfo/$${f}; \
	done
	${INSTALL} ${TAG_ARGS} -o ${BINOWN} -g ${BINGRP} -m ${NOBINMODE} \
	    ${CONTRIBDIR}/zone.tab ${DESTDIR}/usr/share/zoneinfo/
	${INSTALL} ${TAG_ARGS} -o ${BINOWN} -g ${BINGRP} -m ${NOBINMODE} \
	    ${CONTRIBDIR}/zone1970.tab ${DESTDIR}/usr/share/zoneinfo/

afterinstall:
#
# If the file /var/db/zoneinfo exists, and it is owned by root:wheel,
# and the contents of it exists in /usr/share/zoneinfo, then reinstall
# it.
#
	@if [ -f ${DESTDIR}/var/db/zoneinfo -a -O ${DESTDIR}/var/db/zoneinfo \
	    -a -G ${DESTDIR}/var/db/zoneinfo ]; then \
		zf=$$(cat ${DESTDIR}/var/db/zoneinfo); \
		if [ -f ${DESTDIR}/usr/share/zoneinfo/$${zf} ]; then \
			if [ ! -z "${DESTDIR}" ]; then \
				optC="-C ${DESTDIR}"; \
			fi; \
			echo "Updating /etc/localtime"; \
			tzsetup $${optC} -r; \
		fi; \
	else \
		echo "Run tzsetup(8) manually to update /etc/localtime."; \
	fi

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
