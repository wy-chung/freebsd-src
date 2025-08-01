/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013, Joyent, Inc. All rights reserved.
 * Copyright (C) 2016 Lawrence Livermore National Security, LLC.
 * Copyright (c) 2025, Rob Norris <robn@despairlabs.com>
 *
 * For Linux the vast majority of this enforcement is already handled via
 * the standard Linux VFS permission checks.  However certain administrative
 * commands which bypass the standard mechanisms may need to make use of
 * this functionality.
 */

#include <sys/policy.h>
#include <linux/security.h>
#include <linux/vfs_compat.h>

static int
priv_policy_ns(const cred_t *cr, int capability, int err,
    struct user_namespace *ns)
{
	/*
	 * The passed credentials cannot be directly verified because Linux
	 * only provides an interface to check the *current* process
	 * credentials.  In order to handle this we check if the passed in
	 * creds match the current process credentials or the kcred.  If not,
	 * we swap the passed credentials into the current task, perform the
	 * check, and then revert it before returning.
	 */
	const cred_t *old =
	    (cr != CRED() && cr != kcred) ? override_creds(cr) : NULL;

#if defined(CONFIG_USER_NS)
	if (ns ? ns_capable(ns, capability) : capable(capability))
#else
	if (capable(capability))
#endif
		err = 0;

	if (old)
		revert_creds(old);

	return (err);
}

static int
priv_policy(const cred_t *cr, int capability, int err)
{
	return (priv_policy_ns(cr, capability, err, cr->user_ns));
}

static int
priv_policy_user(const cred_t *cr, int capability, int err)
{
	/*
	 * All priv_policy_user checks are preceded by kuid/kgid_has_mapping()
	 * checks. If we cannot do them, we shouldn't be using ns_capable()
	 * since we don't know whether the affected files are valid in our
	 * namespace.
	 */
#if defined(CONFIG_USER_NS)
	return (priv_policy_ns(cr, capability, err, cr->user_ns));
#else
	return (priv_policy_ns(cr, capability, err, NULL));
#endif
}

/*
 * Checks for operations that are either client-only or are used by
 * both clients and servers.
 */
int
secpolicy_nfs(const cred_t *cr)
{
	return (priv_policy(cr, CAP_SYS_ADMIN, EPERM));
}

/*
 * Catch all system configuration.
 */
int
secpolicy_sys_config(const cred_t *cr, boolean_t checkonly)
{
	return (priv_policy(cr, CAP_SYS_ADMIN, EPERM));
}

/*
 * Like secpolicy_vnode_access() but we get the actual wanted mode and the
 * current mode of the file, not the missing bits.
 *
 * Enforced in the Linux VFS.
 */
int
secpolicy_vnode_access2(const cred_t *cr, struct inode *ip, uid_t owner,
    mode_t curmode, mode_t wantmode)
{
	return (0);
}

/*
 * This is a special routine for ZFS; it is used to determine whether
 * any of the privileges in effect allow any form of access to the
 * file.  There's no reason to audit this or any reason to record
 * this.  More work is needed to do the "KPLD" stuff.
 */
int
secpolicy_vnode_any_access(const cred_t *cr, struct inode *ip, uid_t owner)
{
	if (crgetuid(cr) == owner)
		return (0);

	if (zpl_inode_owner_or_capable(zfs_init_idmap, ip))
		return (0);

#if defined(CONFIG_USER_NS)
	if (!kuid_has_mapping(cr->user_ns, SUID_TO_KUID(owner)))
		return (EPERM);
#endif

	if (priv_policy_user(cr, CAP_DAC_OVERRIDE, EPERM) == 0)
		return (0);

	if (priv_policy_user(cr, CAP_DAC_READ_SEARCH, EPERM) == 0)
		return (0);

	return (EPERM);
}

/*
 * Determine if subject can chown owner of a file.
 */
int
secpolicy_vnode_chown(const cred_t *cr, uid_t owner)
{
	if (crgetuid(cr) == owner)
		return (0);

#if defined(CONFIG_USER_NS)
	if (!kuid_has_mapping(cr->user_ns, SUID_TO_KUID(owner)))
		return (EPERM);
#endif

	return (priv_policy_user(cr, CAP_FOWNER, EPERM));
}

/*
 * Determine if subject can change group ownership of a file.
 */
int
secpolicy_vnode_create_gid(const cred_t *cr)
{
	return (priv_policy(cr, CAP_SETGID, EPERM));
}

/*
 * Policy determines whether we can remove an entry from a directory,
 * regardless of permission bits.
 */
int
secpolicy_vnode_remove(const cred_t *cr)
{
	return (priv_policy(cr, CAP_FOWNER, EPERM));
}

/*
 * Determine that subject can modify the mode of a file.  allzone privilege
 * needed when modifying root owned object.
 */
int
secpolicy_vnode_setdac(const cred_t *cr, uid_t owner)
{
	if (crgetuid(cr) == owner)
		return (0);

#if defined(CONFIG_USER_NS)
	if (!kuid_has_mapping(cr->user_ns, SUID_TO_KUID(owner)))
		return (EPERM);
#endif

	return (priv_policy_user(cr, CAP_FOWNER, EPERM));
}

/*
 * Are we allowed to retain the set-uid/set-gid bits when
 * changing ownership or when writing to a file?
 * "issuid" should be true when set-uid; only in that case
 * root ownership is checked (setgid is assumed).
 *
 * Enforced in the Linux VFS.
 */
int
secpolicy_vnode_setid_retain(struct znode *zp __maybe_unused, const cred_t *cr,
    boolean_t issuidroot)
{
	return (priv_policy_user(cr, CAP_FSETID, EPERM));
}

/*
 * Determine that subject can set the file setgid flag.
 */
int
secpolicy_vnode_setids_setgids(const cred_t *cr, gid_t gid, zidmap_t *mnt_ns,
    struct user_namespace *fs_ns)
{
	gid = zfs_gid_to_vfsgid(mnt_ns, fs_ns, gid);
#if defined(CONFIG_USER_NS)
	if (!kgid_has_mapping(cr->user_ns, SGID_TO_KGID(gid)))
		return (EPERM);
#endif
	if (crgetgid(cr) != gid && !groupmember(gid, cr))
		return (priv_policy_user(cr, CAP_FSETID, EPERM));

	return (0);
}

/*
 * Determine if the subject can inject faults in the ZFS fault injection
 * framework.  Requires all privileges.
 */
int
secpolicy_zinject(const cred_t *cr)
{
	return (priv_policy(cr, CAP_SYS_ADMIN, EACCES));
}

/*
 * Determine if the subject has permission to manipulate ZFS datasets
 * (not pools).  Equivalent to the SYS_MOUNT privilege.
 */
int
secpolicy_zfs(const cred_t *cr)
{
	return (priv_policy(cr, CAP_SYS_ADMIN, EACCES));
}

void
secpolicy_setid_clear(vattr_t *vap, cred_t *cr)
{
	if ((vap->va_mode & (S_ISUID | S_ISGID)) != 0 &&
	    secpolicy_vnode_setid_retain(NULL, cr,
	    (vap->va_mode & S_ISUID) != 0 &&
	    (vap->va_mask & AT_UID) != 0 && vap->va_uid == 0) != 0) {
		vap->va_mask |= AT_MODE;
		vap->va_mode &= ~(S_ISUID|S_ISGID);
	}
}

/*
 * Determine that subject can set the file setid flags.
 */
static int
secpolicy_vnode_setid_modify(const cred_t *cr, uid_t owner, zidmap_t *mnt_ns,
    struct user_namespace *fs_ns)
{
	owner = zfs_uid_to_vfsuid(mnt_ns, fs_ns, owner);

	if (crgetuid(cr) == owner)
		return (0);

#if defined(CONFIG_USER_NS)
	if (!kuid_has_mapping(cr->user_ns, SUID_TO_KUID(owner)))
		return (EPERM);
#endif

	return (priv_policy_user(cr, CAP_FSETID, EPERM));
}

/*
 * Determine that subject can make a file a "sticky".
 *
 * Enforced in the Linux VFS.
 */
static int
secpolicy_vnode_stky_modify(const cred_t *cr)
{
	return (0);
}

int
secpolicy_setid_setsticky_clear(struct inode *ip, vattr_t *vap,
    const vattr_t *ovap, cred_t *cr, zidmap_t *mnt_ns,
    struct user_namespace *fs_ns)
{
	int error;

	if ((vap->va_mode & S_ISUID) != 0 &&
	    (error = secpolicy_vnode_setid_modify(cr,
	    ovap->va_uid, mnt_ns, fs_ns)) != 0) {
		return (error);
	}

	/*
	 * Check privilege if attempting to set the
	 * sticky bit on a non-directory.
	 */
	if (!S_ISDIR(ip->i_mode) && (vap->va_mode & S_ISVTX) != 0 &&
	    secpolicy_vnode_stky_modify(cr) != 0) {
		vap->va_mode &= ~S_ISVTX;
	}

	/*
	 * Check for privilege if attempting to set the
	 * group-id bit.
	 */
	if ((vap->va_mode & S_ISGID) != 0 &&
	    secpolicy_vnode_setids_setgids(cr, ovap->va_gid,
	    mnt_ns, fs_ns) != 0) {
		vap->va_mode &= ~S_ISGID;
	}

	return (0);
}

/*
 * Check privileges for setting xvattr attributes
 */
int
secpolicy_xvattr(xvattr_t *xvap, uid_t owner, cred_t *cr, mode_t type)
{
	return (secpolicy_vnode_chown(cr, owner));
}

/*
 * Check privileges for setattr attributes.
 *
 * Enforced in the Linux VFS.
 */
int
secpolicy_vnode_setattr(cred_t *cr, struct inode *ip, struct vattr *vap,
    const struct vattr *ovap, int flags,
    int unlocked_access(void *, int, cred_t *), void *node)
{
	return (0);
}

/*
 * Check privileges for links.
 *
 * Enforced in the Linux VFS.
 */
int
secpolicy_basic_link(const cred_t *cr)
{
	return (0);
}
