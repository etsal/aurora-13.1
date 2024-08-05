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

#define VIRTIOFS_THREADS_TQ (8)

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

/* Push the ticket to the virtiofs device. */
static int
virtiofs_enqueue(struct fuse_ticket *ftick)
{
	struct fuse_out_header *ohead = &ftick->tk_aw_ohead;
	struct fuse_data *data = ftick->tk_data;
	struct fuse_iov *riov, *wiov;
	struct sglist *sg = NULL;
	int readable, writable;
	bool urgent;
	int error;

	urgent = (fticket_opcode(ftick) == FUSE_FORGET);

	riov = &ftick->tk_ms_fiov;
	wiov = &ftick->tk_aw_fiov;

	refcount_acquire(&ftick->tk_refcount);

	/* Preallocate the response buffer. */
	error = fiov_adjust(wiov, fticket_out_size(ftick), M_NOWAIT);
	if (error != 0)
		goto out;

	/* Readable/writable from the host's point of view. */
	readable = sglist_count(riov->base, riov->len);

	/* Account for the out header. */
	writable = sglist_count(ohead, sizeof(*ohead)) + 
		sglist_count(wiov->base, wiov->len);

	sg = sglist_alloc(readable + writable, M_NOWAIT);
	if (sg == NULL) {
		error = ENOMEM;
		goto out;
	}

	error = sglist_append(sg, riov->base, riov->len);
	if (error != 0)
		goto out;

	error = sglist_append(sg, ohead, sizeof(*ohead));
	if (error != 0)
		goto out;

	error = sglist_append(sg, wiov->base, wiov->len);
	if (error != 0)
		goto out;

	error = vtfs_enqueue(data->vtfs, ftick, sg, readable, writable, urgent);

	/*
	 * The enqueue call destroys the scatter-gather array both on success and
	 * on failure, so no need to clean it up.
	 */

	return (error);

out:
	fuse_ticket_drop(ftick);
	if (sg != NULL)
		sglist_free(sg);

	return (error);
}

static void
virtiofs_flush(void *xdata, int __unused pending)
{
	struct fuse_ticket *ftick;
	struct fuse_data *data = xdata;
	int error;

	/* XXX Account for dead sessions. */

	fuse_lck_mtx_lock(data->ms_mtx);

	while (!STAILQ_EMPTY(&data->ms_head)) {
		ftick = STAILQ_FIRST(&data->ms_head);

		STAILQ_REMOVE_HEAD(&data->ms_head, tk_ms_link);
		data->ms_count--;

		KASSERT(ftick != STAILQ_FIRST(&data->ms_head), ("ticket still in the queue"));

#ifdef INVARIANTS
		MPASS(data->ms_count >= 0);
		ftick->tk_ms_link.stqe_next = NULL;
#endif

		FUSE_ASSERT_MS_DONE(ftick);
		fuse_ticket_drop(ftick);

		/*
		 * The enqueue operation is synchronous and may sleep,
		 * so drop the session lock - we have already adjusted
		 * all session fields so we don't need it while flushing
		 * to the virtio device anyway.
		 */
		fuse_lck_mtx_unlock(data->ms_mtx);
		error = virtiofs_enqueue(ftick);
		fuse_lck_mtx_lock(data->ms_mtx);
		if (error != 0)
			break;
	}

	fuse_lck_mtx_unlock(data->ms_mtx);

	if (error != 0)
		printf("Warning: %s failed with %d\n", __func__, error);

	return;
}

static void
virtiofs_cb_drop_ticket(void *xtick)
{
	struct fuse_ticket *ftick = xtick;

	fuse_lck_mtx_lock(ftick->tk_aw_mtx);
	KASSERT(!fticket_answered(ftick), ("ticket already answered"));
	fuse_lck_mtx_unlock(ftick->tk_aw_mtx);

	fuse_ticket_drop(ftick);
}

static void
virtiofs_cb_complete_ticket(void *xtick)
{
	struct fuse_ticket *ftick = xtick;
	struct fuse_data *data = ftick->tk_data;
	int err;

	fuse_lck_mtx_lock(data->aw_mtx);
	fuse_aw_remove(ftick);
	fuse_lck_mtx_unlock(data->aw_mtx);

	fuse_lck_mtx_lock(ftick->tk_aw_mtx);

	/* XXX Do the ohead checks here. */

	/* XXX Merge this with the dev write method that does the same thing. */
	if (ftick->tk_aw_ohead.error != 0) {
		err = -ftick->tk_aw_ohead.error;
		if (err < 0 || err >= nitems(linux_to_bsd_errtbl))
			panic("Unknown error");

		/* '-', because it will get flipped again below */
		ftick->tk_aw_ohead.error = linux_to_bsd_errtbl[err];
	}

	/* XXX Check who this can happen in virtiofs. */
	if (ftick->irq_unique > 0)
		panic("Unhandled interruption");

	KASSERT(ftick->tk_aw_errno == 0, ("ticket error %d", ftick->tk_aw_errno));

	fuse_lck_mtx_unlock(ftick->tk_aw_mtx);

	if (ftick->tk_aw_handler != NULL)
		ftick->tk_aw_handler(ftick, NULL);

	fuse_ticket_drop(ftick);
}

/* 
 * XXX Possibly roll this into fusefs_vfsop_mount, turns out they are very similar.
 * At least refactor virtiofs_vfsop_mount and reuse its logic here.
 */
static int
virtiofs_vfsop_mount(struct mount *mp)
{
	struct thread *td = curthread;
	struct vfsoptlist *opts;
	struct fuse_data *data;
	int daemon_timeout;
	vtfs_instance vtfs;
	uint32_t max_read;
	int linux_errnos;
	uint64_t mntopts;
	char *subtype;
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

	mntopts = 0;
	vfs_flagopt(opts, "push_symlinks_in", &mntopts, FSESS_PUSH_SYMLINKS_IN);
	vfs_flagopt(opts, "default_permissions", &mntopts, FSESS_DEFAULT_PERMISSIONS);
	vfs_flagopt(opts, "intr", &mntopts, FSESS_INTR);

	max_read = maxbcachebuf;
	(void)vfs_scanopt(opts, "max_read=", "%u", &max_read);

	linux_errnos = 0;
	(void)vfs_scanopt(opts, "linux_errnos", "%d", &linux_errnos);

	/* XXX Handle timeout */
	daemon_timeout = FUSE_MIN_DAEMON_TIMEOUT;

	subtype = vfs_getopts(opts, "subtype=", &error);

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

	vtfs_register_cb(vtfs, virtiofs_cb_drop_ticket, virtiofs_cb_complete_ticket);

	/* 
	 * XXX Retrieve the session from the device if it already exists,
	 * and only create a new one if it does not .
	 */
	data = fdata_alloc(NULL, td->td_ucred);

	FUSE_LOCK();
	if (fdata_get_dead(data)) {
		/* XXX Proper error handling. */
		panic("Data is already dead");
	}

	data->vtfs_tq = taskqueue_create("virtiofstq", M_NOWAIT, taskqueue_thread_enqueue, 
			&data->vtfs_tq);
	if (data->vtfs_tq == NULL)
		panic("ENOMEM when initializing taskqueue");

	data->vtfs = vtfs;
	data->vtfs_flush_cb = virtiofs_flush;

	/* XXX Permission checks on whether we are allowed to mount the virtiofs. */

	data->mp = mp;
	data->dataflags |= mntopts | FSESS_VIRTIOFS;
	data->max_read = max_read;
	data->daemon_timeout = daemon_timeout;
	data->linux_errnos = linux_errnos;
	data->mnt_flag = mp->mnt_flag & MNT_UPDATEMASK;
	FUSE_UNLOCK();

	KASSERT(!fdata_get_dead(data), ("newly created fuse session is dead"));

	vfs_getnewfsid(mp);
	MNT_ILOCK(mp);
	mp->mnt_data = data;
	mp->mnt_flag &= ~MNT_LOCAL;
	mp->mnt_kern_flag |= MNTK_USES_BCACHE;
	/* 
	 * The FS is remote by default. Disable nullfs caching to avoid
	 * the extra coherence cost, same as FUSE.
	 */
	mp->mnt_kern_flag |= MNTK_NULL_NOCACHE;
	MNT_IUNLOCK(mp);
	
	mp->mnt_stat.f_iosize = maxbcachebuf;
	if (subtype) {
		strlcat(mp->mnt_stat.f_fstypename, ".", MFSNAMELEN);
		strlcat(mp->mnt_stat.f_fstypename, subtype, MFSNAMELEN);
	}
	memset(mp->mnt_stat.f_mntfromname, 0, MNAMELEN);
	strlcpy(mp->mnt_stat.f_mntfromname, tag, MNAMELEN);
	mp->mnt_iosize_max = maxphys;

	error = taskqueue_start_threads(&data->vtfs_tq, VIRTIOFS_THREADS_TQ, PVFS, "virtiofs_tq"); 
	if (error != 0)
		panic("error when initializing taskqueue threads");

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

	taskqueue_drain_all(data->vtfs_tq);
	taskqueue_free(data->vtfs_tq);

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
