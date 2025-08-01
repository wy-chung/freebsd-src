
DEVIWLWIFIDIR=	${SRCTOP}/sys/contrib/dev/iwlwifi

.PATH: ${DEVIWLWIFIDIR}

WITH_CONFIG_PM=	0
WITH_DEBUGFS=	1
WITH_CONFIG_ACPI=	1

KMOD=	if_iwlwifi

SRCS=	iwl-drv.c
SRCS+=	iwl-dbg-tlv.c iwl-debug.c
SRCS+=	iwl-io.c iwl-nvm-parse.c iwl-nvm-utils.c iwl-phy-db.c iwl-trans.c
SRCS+=	cfg/7000.c cfg/8000.c cfg/9000.c cfg/22000.c
SRCS+=	cfg/ax210.c cfg/bz.c cfg/sc.c
SRCS+=	fw/dbg.c fw/dump.c fw/img.c fw/notif-wait.c
SRCS+=	fw/paging.c fw/pnvm.c fw/regulatory.c fw/rs.c fw/smem.c fw/init.c
#SRCS+=	fw/uefi.c
SRCS+=	mvm/rs.c mvm/binding.c mvm/coex.c mvm/ftm-initiator.c
SRCS+=	mvm/ftm-responder.c mvm/fw.c mvm/mac-ctxt.c
SRCS+=	mvm/mac80211.c mvm/nvm.c mvm/offloading.c mvm/ops.c
SRCS+=	mvm/phy-ctxt.c mvm/power.c mvm/quota.c mvm/rs-fw.c mvm/rfi.c
SRCS+=	mvm/rx.c mvm/rxmq.c mvm/scan.c mvm/sf.c mvm/sta.c mvm/tdls.c
SRCS+=	mvm/time-event.c mvm/tt.c mvm/tx.c mvm/utils.c
SRCS+=	mvm/link.c
SRCS+=	mvm/mld-key.c mvm/mld-mac.c mvm/mld-mac80211.c mvm/mld-sta.c
SRCS+=	mvm/ptp.c mvm/time-sync.c
#SRCS+=	mvm/led.c
SRCS+=	pcie/ctxt-info-gen3.c pcie/ctxt-info.c
SRCS+=	pcie/drv.c pcie/rx.c pcie/trans-gen2.c pcie/trans.c
SRCS+=	pcie/tx-gen2.c pcie/tx.c

.if defined(WITH_DEBUGFS) && ${WITH_DEBUGFS} > 0
SRCS+=	fw/debugfs.c mvm/debugfs.c mvm/debugfs-vif.c
CFLAGS+=	-DCONFIG_IWLWIFI_DEBUGFS
CFLAGS+=	-DCONFIG_MAC80211_DEBUGFS
.endif
.if defined(WITH_CONFIG_PM) && ${WITH_CONFIG_PM} > 0
SRCS+=	mvm/d3.c
CFLAGS+=	-DCONFIG_PM
CFLAGS+=	-DCONFIG_PM_SLEEP
.endif

.if defined(WITH_CONFIG_ACPI) && ${WITH_CONFIG_ACPI} > 0
SRCS+=	fw/acpi.c
CFLAGS+=	-DCONFIG_ACPI
CFLAGS+=	-DLINUXKPI_WANT_LINUX_ACPI
.endif

SRCS+=	iwl-devtrace.c

# Other
SRCS+=	${LINUXKPI_GENSRCS}
SRCS+=	opt_wlan.h opt_inet6.h opt_inet.h opt_acpi.h

CFLAGS+=	-DKBUILD_MODNAME='"iwlwifi"'
CFLAGS+=	-DLINUXKPI_VERSION=61100

CFLAGS+=	-I${DEVIWLWIFIDIR}
CFLAGS+=	${LINUXKPI_INCLUDES}
CFLAGS+=	-DCONFIG_IWLDVM=0
CFLAGS+=	-DCONFIG_IWLMVM=1
# Helpful after fresh imports.
#CFLAGS+=	-ferror-limit=0

#CFLAGS+=	-DCONFIG_INET=1		# Need LKPI TSO implementation.
#CFLAGS+=	-DCONFIG_IPV6=1
CFLAGS+=	-DCONFIG_IWLWIFI_DEBUG=1
#CFLAGS+=	-DCONFIG_IWLWIFI_LEDS=1
#CFLAGS+=	-DCONFIG_IWLWIFI_OPMODE_MODULAR=1
CFLAGS+=	-DCONFIG_IWLWIFI_DEVICE_TRACING=1
#CFLAGS+=	-DCONFIG_LOCKDEP=1
#CFLAGS+=	-DCONFIG_NL80211_TESTMODE=1
#CFLAGS+=	-DCONFIG_THERMAL=1
#CFLAGS+=	-DCONFIG_EFI=1

.include <bsd.kmod.mk>
