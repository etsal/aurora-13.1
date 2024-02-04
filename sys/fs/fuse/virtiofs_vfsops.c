/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sglist.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

#include "fuse.h"
#include "fuse_kernel.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"

#include <dev/virtio/fs/virtio_fs.h>

#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_errno.inc>

vfs_fhtovp_t fuse_vfsop_fhtovp;
static vfs_mount_t virtiofs_vfsop_mount;
static vfs_unmount_t virtiofs_vfsop_unmount;
vfs_root_t fuse_vfsop_root;
vfs_statfs_t fuse_vfsop_statfs;
vfs_vget_t fuse_vfsop_vget;

/* Only mount/unmount is different compared to fuse. */
struct vfsops virtiofs_vfsops = {
	.vfs_fhtovp = fuse_vfsop_fhtovp,
	.vfs_mount = virtiofs_vfsop_mount,
	.vfs_unmount = virtiofs_vfsop_unmount,
	.vfs_root = fuse_vfsop_root,
	.vfs_statfs = fuse_vfsop_statfs,
	.vfs_vget = fuse_vfsop_vget,
};

static void
virtiofs_drop_ticket(void *xtick)
{
	struct fuse_ticket *ftick = xtick;

	fuse_lck_mtx_lock(ftick->tk_aw_mtx);
	KASSERT(!fticket_answered(ftick), ("ticket already answered"));
	fuse_lck_mtx_unlock(ftick->tk_aw_mtx);

	fuse_ticket_drop(ftick);
}

static void
virtiofs_complete_ticket(void *xtick)
{
	struct fuse_ticket *ftick = xtick;
	struct fuse_data *data = ftick->tk_data;
	int err;

	fuse_lck_mtx_lock(data->aw_mtx);
	fuse_aw_remove(ftick);
	fuse_lck_mtx_unlock(data->aw_mtx);

	fuse_lck_mtx_lock(ftick->tk_aw_mtx);

	KASSERT(!fticket_answered(ftick), ("ticket already answered"));

	/* XXX Do the ohead checks here. */

	if (ftick->tk_aw_ohead.error != 0) {
		err = -ftick->tk_aw_ohead.error;
		if (err < 0 || err >= nitems(linux_to_bsd_errtbl))
			panic("Unknown error");

		/* '-', because it will get flipped again below */
		ftick->tk_aw_ohead.error = linux_to_bsd_errtbl[err];
	}

	if (ftick->irq_unique > 0)
		panic("Unhandled interruption");

	KASSERT(ftick->tk_aw_errno == 0, ("ticket error %d", ftick->tk_aw_errno));

	fuse_lck_mtx_unlock(ftick->tk_aw_mtx);

	if (ftick->tk_aw_handler != NULL)
		ftick->tk_aw_handler(ftick, NULL);

	fuse_ticket_drop(ftick);
}

static int
virtiofs_vfsop_mount(struct mount *mp)
{
	struct thread *td = curthread;
	struct vfsoptlist *opts;
	struct fuse_data *data;
	vtfs_instance vtfs;
	char *tag;
	int error;

	opts = mp->mnt_optnew;
	if (opts == NULL)
		return (EINVAL);

	/*
	 * TODO: Add DAX mode parameters.
	 * Can wait until we add DAX mode.
	 */

	/* `fspath' contains the mount point (eg. /mnt/guestfs); REQUIRED */
	if (!vfs_getopts(opts, "fspath", &error))
		return (error);


	if (mp->mnt_flag & MNT_UPDATE) {
		/* XXX Handle remount. */
		panic("Unhandled");
	}

	/* `from' contains the virtio tag; REQUIRED */
	tag = vfs_getopts(opts, "tag", &error);
	if (!tag)
		return (error);

	vtfs = vtfs_find(tag);
	if (vtfs == NULL)
		return (error);

	vtfs_register_cb(vtfs, virtiofs_drop_ticket, virtiofs_complete_ticket);

	data = fdata_alloc(NULL, td->td_ucred);
	data->max_read = maxbcachebuf;
	data->mp = mp;
	data->vtfs = vtfs;
	data->dataflags |= FSESS_VIRTIOFS;

	/* XXX daemoncred check. */

	KASSERT(!fdata_get_dead(data), ("newly created fuse session is dead"));

	vfs_getnewfsid(mp);

	MNT_ILOCK(mp);
	/* 
	 * The FS is remote by default. Disable nullfs caching to avoid
	 * the extra coherence cost, same as FUSE.
	 *
	 * XXX Re-add MNTK_USES_BCACHE when we allow in-guest caching.
	 */
	mp->mnt_data = data;
	mp->mnt_flag &= ~MNT_LOCAL;
	mp->mnt_kern_flag |= MNTK_USES_BCACHE;
	mp->mnt_kern_flag |= MNTK_NULL_NOCACHE;
	MNT_IUNLOCK(mp);
	
	mp->mnt_stat.f_iosize = maxbcachebuf;
	memset(mp->mnt_stat.f_mntfromname, 0, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntfromname, tag, MNAMELEN);
	mp->mnt_iosize_max = maxphys;

	/* Now handshaking with daemon */
	fuse_internal_send_init(data, td);

	return (0);
}

static int
virtiofs_vfsop_unmount(struct mount *mp, int mntflags)
{
	struct fuse_data *data;
	struct fuse_dispatcher fdi;
	struct thread *td = curthread;
	vtfs_instance vtfs;

	int err = 0;
	int flags = 0;

	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
	}
	data = fuse_get_mpdata(mp);
	if (!data) {
		panic("no private data for mount point?");
	}
	vtfs = data->vtfs;

	/* There is 1 extra root vnode reference (mp->mnt_data). */
	FUSE_LOCK();
	if (data->vroot != NULL) {
		struct vnode *vroot = data->vroot;

		data->vroot = NULL;
		FUSE_UNLOCK();
		vrele(vroot);
	} else
		FUSE_UNLOCK();

	err = vflush(mp, 0, flags, td);
	if (err) {
		return err;
	}

	if (fdata_get_dead(data))
		goto alreadydead;

	if (fsess_maybe_impl(mp, FUSE_DESTROY)) {
		fdisp_init(&fdi, 0);
		fdisp_make(&fdi, FUSE_DESTROY, mp, 0, td, NULL);

		(void)fdisp_wait_answ(&fdi);
		fdisp_destroy(&fdi);
	}

	vtfs_drain(vtfs);

	fdata_set_dead(data);

alreadydead:
	FUSE_LOCK();
	data->mp = NULL;
	fdata_trydestroy(data);
	FUSE_UNLOCK();

	MNT_ILOCK(mp);
	mp->mnt_data = NULL;
	MNT_IUNLOCK(mp);

	vtfs_unregister_cb(vtfs);
	/* XXX Unref the FS instance and release the reference. */

	return 0;

}
