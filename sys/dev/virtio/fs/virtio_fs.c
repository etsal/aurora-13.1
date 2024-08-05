/*
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Device for the VirtIO file system. */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/queue.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/selinfo.h>
#include <sys/sglist.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>
#include <sys/bus.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/fs/virtio_fs.h>

#include "virtio_if.h"
#include "virtio_fs_internal.h"

/* Methods for the vtfs device. */

struct vtfs_softc;

/* Module-wide device list. */

LIST_HEAD(, vtfs_softc) vtfs_contexts = LIST_HEAD_INITIALIZER(vtfs_contexts);
struct mtx vtfs_mod_mtx;
MTX_SYSINIT(vtfs_mod_mtx, &vtfs_mod_mtx, "Virtio FS Global Lock", MTX_DEF);

#define VTFS_LOCK()		mtx_lock(&vtfs_mod_mtx)
#define VTFS_UNLOCK()		mtx_unlock(&vtfs_mod_mtx)

#define FSQ_LOCK(_fsq)		mtx_lock(&(_fsq)->vtfsq_mtx)
#define FSQ_UNLOCK(_fsq)	mtx_unlock(&(_fsq)->vtfsq_mtx)

static int	vtfs_modevent(module_t, int, void *);

static int	vtfs_probe(device_t);
static int	vtfs_attach(device_t);
static int	vtfs_detach(device_t);
static int	vtfs_suspend(device_t);
static int	vtfs_resume(device_t);
static int	vtfs_shutdown(device_t);
static int	vtfs_attach_completed(device_t);
static int	vtfs_config_change(device_t);

static device_method_t vtfs_methods[] = {
	DEVMETHOD(device_probe,		vtfs_probe),
	DEVMETHOD(device_attach,	vtfs_attach),
	DEVMETHOD(device_detach,	vtfs_detach),
	DEVMETHOD(device_suspend,	vtfs_suspend),
	DEVMETHOD(device_resume,	vtfs_resume),
	DEVMETHOD(device_shutdown,	vtfs_shutdown),

	DEVMETHOD(virtio_attach_completed, vtfs_attach_completed),
	DEVMETHOD(virtio_config_change, vtfs_config_change),

	DEVMETHOD_END
};

static driver_t vtfs_driver = {
	"vtfs",
	vtfs_methods,
	sizeof(struct vtfs_softc),
};

VIRTIO_DRIVER_MODULE(vtfs, vtfs_driver, vtfs_modevent, NULL);
MODULE_VERSION(vtfs, 1);
MODULE_DEPEND(vtfs, virtio, 1, 1, 1);

VIRTIO_SIMPLE_PNPINFO(vtfs, VIRTIO_ID_FS, "VirtIO FS Adapter");

/* Module load/unload logic. */

static int
vtfs_modevent(module_t mod, int type, void *unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
	case MOD_UNLOAD:
	case MOD_QUIESCE:
	case MOD_SHUTDOWN:
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static int
vtfs_probe(device_t dev)
{
	return (VIRTIO_SIMPLE_PROBE(dev, vtfs));
}

static int
vtfs_suspend(device_t dev)
{
	VTFS_DEBUG("invoked");
	return (0);	
}

static int
vtfs_resume(device_t dev)
{
	VTFS_DEBUG("invoked");
	return (0);
}

static int
vtfs_shutdown(device_t dev)
{
	VTFS_DEBUG("invoked");
	return (0);	
}

static int
vtfs_attach_completed(device_t dev)
{
	VTFS_DEBUG("vtfs ready");
	return (0);
}

static int
vtfs_config_change(device_t dev)
{
	VTFS_DEBUG("invoked");
	return (0);
}

static int
vtfs_read_config(struct vtfs_softc *sc)
{
	device_t dev;
	size_t taglen;
#ifdef INVARIANTS
	struct vtfs_config fscfg;
#endif

	dev = sc->vtfs_dev;

	KASSERT(sizeof(sc->vtfs_nqs) == sizeof(fscfg.num_request_queues),
		("reading num_request_queues into wrongly typed struct"));

	virtio_read_device_config(dev,
		offsetof(struct vtfs_config, num_request_queues),
		&sc->vtfs_nqs,
		sizeof(&sc->vtfs_nqs));

	if (sc->vtfs_nqs <= 0) {
		VTFS_ERR("read negative queue number from host");
		return (EINVAL);
	}

	/* Account for the priority queue. */
	sc->vtfs_nqs += 1;

	virtio_read_device_config_array(dev,
		offsetof(struct vtfs_config, tag),
		sc->vtfs_tag, 1, TAG_SIZE);

	/* The read tag may not be NUL-terminated. */
	taglen = strnlen(sc->vtfs_tag, TAG_SIZE);
	if (taglen == 0) {
		VTFS_ERR("read empty tag");
		return (EINVAL);
	}

	KASSERT(taglen < sizeof(sc->vtfs_tag), ("overran tag buffer"));
	sc->vtfs_tag[taglen] = '\0';

	VTFS_DEBUG("fs tag: %s, # vqs: %d", sc->vtfs_tag, sc->vtfs_nqs);

	return (0);
}

static void
vtfs_vq_intr(void *xfsq)
{
	struct vtfs_fsq *fsq = xfsq;
	struct virtqueue *vq = fsq->vtfsq_vq;
	void *ftick;

	if (fsq->vtfsq_cb == NULL)
		panic("missing virtiofs fuse callback");

	FSQ_LOCK(fsq);

again:
	/* Go through the tickets one by one, invoke the fuse callback. */
	while  ((ftick = virtqueue_dequeue(vq, NULL)) != NULL)
		fsq->vtfsq_cb(ftick);

	/* If the host pushed another descriptor in the meantime, go again. */
	if (virtqueue_enable_intr(vq) != 0) {
		virtqueue_disable_intr(vq);
		goto again;
	}

	FSQ_UNLOCK(fsq);
}

static int
vtfs_init_fsq(struct vtfs_softc *sc, int id)
{
	struct vtfs_fsq *fsq = &sc->vtfs_fsqs[id];
	int error;

	if (id == 0) {
		snprintf(fsq->vtfsq_name, sizeof(fsq->vtfsq_name), 
			"%s-priority", device_get_nameunit(sc->vtfs_dev));
	} else {
		snprintf(fsq->vtfsq_name, sizeof(fsq->vtfsq_name), 
			"%s-queue%d", device_get_nameunit(sc->vtfs_dev), id);
	}

	mtx_init(&fsq->vtfsq_mtx, fsq->vtfsq_name, NULL, MTX_DEF);

	fsq->vtfsq_tq = taskqueue_create("vtfsqtq", M_WAITOK, 
			taskqueue_thread_enqueue, &fsq->vtfsq_tq);
	if (fsq->vtfsq_tq == NULL)
		return (ENOMEM);

	error = taskqueue_start_threads(&fsq->vtfsq_tq, 4, PVM, "VirtioFS device");
	if (error != 0)
		return (error);

	fsq->vtfsq_sc = sc;
	VTFS_DEBUG("vq %s online", fsq->vtfsq_name);

	return (0);
}

static void
vtfs_fini_fsq(struct vtfs_fsq *fsq)
{

	if (fsq->vtfsq_sg != NULL) {
		sglist_free(fsq->vtfsq_sg);
		fsq->vtfsq_sg = NULL;
	}

	if (fsq->vtfsq_tq != NULL) {
		taskqueue_drain_all(fsq->vtfsq_tq);
		taskqueue_free(fsq->vtfsq_tq);
		fsq->vtfsq_tq = NULL;
	}

	if (mtx_initialized(&fsq->vtfsq_mtx) != 0)
		mtx_destroy(&fsq->vtfsq_mtx);

	VTFS_DEBUG("vq %s destroyed", fsq->vtfsq_name);
}

static int
vtfs_alloc_fsqueues(struct vtfs_softc *sc)
{
	int error;
	int nvqs;
	int i, j;

	nvqs = sc->vtfs_nqs;
	sc->vtfs_fsqs = malloc((sizeof(*sc->vtfs_fsqs)) * nvqs, M_DEVBUF,
		M_NOWAIT | M_ZERO);
	if (sc->vtfs_fsqs == NULL)
		return (ENOMEM);

	for (i = 0; i < nvqs; i++) {
		error = vtfs_init_fsq(sc, i);
		if (error != 0)
			goto fail;
	}

	return (0);

fail:
	VTFS_DEBUG("failed while initializing vq %d", i);

	/* Clean up any initialized fsqs. */
	for (j = 0; j < i; j++)
		vtfs_fini_fsq(&sc->vtfs_fsqs[j]);

	free(sc->vtfs_fsqs, M_DEVBUF);
	sc->vtfs_fsqs = NULL;

	return (error);
}

static void
vtfs_free_fsqueues(struct vtfs_softc *sc)
{
	int i;

	for (i = 0; i < sc->vtfs_nqs; i++)
		vtfs_fini_fsq(&sc->vtfs_fsqs[i]);
	
	free(sc->vtfs_fsqs, M_DEVBUF);
}

static int
vtfs_alloc_virtqueues(struct vtfs_softc *sc)
{
	struct vq_alloc_info *vq_info;
	struct vtfs_fsq *fsq;
	device_t dev;
	int error;
	int nqs;
	int i;

	dev = sc->vtfs_dev;
	nqs = sc->vtfs_nqs;

	/* 
	 * We have num_request_queues regular queues and one high-priority 
	 * queue for FORGET/general priority operations.
	 */
	KASSERT(nqs > 1, ("missing regular queues"));

	vq_info = malloc(sizeof(*vq_info) * nqs, M_TEMP, M_NOWAIT);
	if (vq_info == NULL)
		return (ENOMEM);

	for (i = 0; i < nqs; i++) {
		/* XXX Decide on the maximum number of segments. */
		fsq = &sc->vtfs_fsqs[i];
		VQ_ALLOC_INFO_INIT(&vq_info[i], 8, vtfs_vq_intr, fsq,
			&fsq->vtfsq_vq, "%s", fsq->vtfsq_name);
	}

	error = virtio_alloc_virtqueues(dev, nqs, vq_info);
	free(vq_info, M_TEMP);

	VTFS_DEBUG("virtqueues online");

	return (error);
}

static int
vtfs_enable_intr(device_t dev)
{
	struct vtfs_softc *sc;
	int error;
	int i;

	sc = device_get_softc(dev);

	error = virtio_setup_intr(dev, INTR_TYPE_BIO);
	if (error != 0)
		return (error);

	for (i = 0; i < sc->vtfs_nqs; i++)
		virtqueue_enable_intr(sc->vtfs_fsqs[i].vtfsq_vq);
	

	return (0);
}

static void
vtfs_stop(struct vtfs_softc *sc)
{
	struct virtqueue *vq;
	int i;

	/* The file system should have cleared the virtqueues when umounting .*/
	for (i = 0; i < sc->vtfs_nqs; i++) {
		vq = sc->vtfs_fsqs[i].vtfsq_vq;
		virtqueue_disable_intr(vq);
		KASSERT(virtqueue_empty(vq), ("virtqueue not empty"));
	}

	virtio_stop(sc->vtfs_dev);

}

/* XXX Make sure the module is not being unloaded. */
static void
vtfs_add(struct vtfs_softc *sc)
{
	VTFS_LOCK();
	LIST_INSERT_HEAD(&vtfs_contexts, sc, vtfs_link);
	VTFS_UNLOCK();
}
static void
vtfs_remove(struct vtfs_softc *sc)
{
	VTFS_LOCK();
	LIST_REMOVE(sc, vtfs_link);
	VTFS_UNLOCK();
}

struct vtfs_softc *
vtfs_find(char *tag)
{
	struct vtfs_softc *sc;

	VTFS_LOCK();

	LIST_FOREACH(sc, &vtfs_contexts, vtfs_link) {
		if (strncmp(sc->vtfs_tag, tag, sizeof(sc->vtfs_tag)) != 0)
			continue;

		/* XXX Grab a reference for the sc. */

		VTFS_UNLOCK();

		return (sc);
	}

	VTFS_UNLOCK();

	return (NULL);
}

static int
vtfs_attach(device_t dev)
{
	struct vtfs_softc *sc;
	int error;

	sc = device_get_softc(dev);
	sc->vtfs_dev = dev;

	error = vtfs_read_config(sc);
	if (error != 0)
		goto fail;

	error = vtfs_alloc_fsqueues(sc);
	if (error != 0)
		goto fail;

	error = vtfs_alloc_virtqueues(sc);
	if (error != 0)
		goto fail;

	error = vtfs_enable_intr(dev);
	if (error != 0)
		goto fail;

	vtfs_add(sc);

fail:
	if (error != 0) {
		/* 
		 * XXX Expand when we expand detach.
		 */
		vtfs_stop(sc);
		vtfs_free_fsqueues(sc);
	}

	return (error);	
}


static int
vtfs_detach(device_t dev)
{
	struct vtfs_softc *sc;

	sc = device_get_softc(dev);

	vtfs_remove(sc);

	/* XXX Mark the sc as dead. */

	/* XXX Drain all queues. */

	vtfs_stop(sc);

	vtfs_free_fsqueues(sc);

	/* XXX Drop a reference for the sc. */

	VTFS_DEBUG("device detached");

	return (0);	
}

void
vtfs_register_cb(struct vtfs_softc *sc, vtfs_fuse_cb forget_cb,
	vtfs_fuse_cb regular_cb)
{
	struct vtfs_fsq *fsq;
	int i;

	for (i = 0; i < sc->vtfs_nqs; i++) {
		fsq = &sc->vtfs_fsqs[i];
		FSQ_LOCK(fsq);
		if (i == VTFS_FORGET_FSQ)
			fsq->vtfsq_cb = forget_cb;
		else
			fsq->vtfsq_cb = regular_cb;
		FSQ_UNLOCK(fsq);
	}

}

void
vtfs_unregister_cb(struct vtfs_softc *sc)
{
	struct vtfs_fsq *fsq;
	int i;

	for (i = 0; i < sc->vtfs_nqs; i++) {
		fsq = &sc->vtfs_fsqs[i];

		FSQ_LOCK(fsq);
		fsq->vtfsq_cb = NULL;
		FSQ_UNLOCK(fsq);
	}

}

/* XXX Hacky implementation to get a prototype running. */
/* XXX Track in-flight requests. */
int
vtfs_enqueue(struct vtfs_softc *sc, void *ftick, struct sglist *sg,
	int readable, int writable, bool urgent)
{
	struct virtqueue *vq;
	struct vtfs_fsq *fsq;
	int error;

	/* 
	 * XXX Do we even need multiple request queues if no
	 * host implements them?
	 */
	if (urgent)
		fsq = &sc->vtfs_fsqs[VTFS_FORGET_FSQ];
	else
		fsq = &sc->vtfs_fsqs[VTFS_REGULAR_FSQ];

	FSQ_LOCK(fsq);
	vq = fsq->vtfsq_vq;

	KASSERT(sg->sg_nseg == readable + writable, ("inconsistent segmentation"));

	error = virtqueue_enqueue(vq, ftick, sg, readable, writable);
	if (error == 0)
		virtqueue_notify(vq);

	FSQ_UNLOCK(fsq);
	sglist_free(sg);

	return (error);
}

/* XXX This is a misnomer, we are "draining" the vq not in 
 * the sense of virtqueue_drain but rather by draining its
 * input and output queues and turning off its interrupts
 * to prevent the host from reading host changes.
 */
static void
vtfs_drain_vq(struct vtfs_fsq *fsq)
{
	struct virtqueue *vq = fsq->vtfsq_vq;
	void *ftick;

	if (fsq->vtfsq_cb == NULL)
		panic("missing virtiofs fuse callback");

	vq = fsq->vtfsq_vq;

	while ((ftick = virtqueue_dequeue(vq, NULL)) != NULL) {
		fsq->vtfsq_cb(ftick);
	}

	/* 
	 * XXX Do we need to drain the virtqueues? What about 
	 * unplugging the device?
	 */

	KASSERT(virtqueue_empty(vq), ("virtqueue not empty"));
}

void
vtfs_drain(struct vtfs_softc *sc)
{
	struct vtfs_fsq *fsq;
	int i;

	for (i = 0; i < sc->vtfs_nqs; i++) {
		fsq = &sc->vtfs_fsqs[i];
		FSQ_LOCK(fsq);
		virtqueue_disable_intr(fsq->vtfsq_vq);
		FSQ_UNLOCK(fsq);
	}

	for (i = 0; i < sc->vtfs_nqs; i++) {
		fsq = &sc->vtfs_fsqs[i];
		FSQ_LOCK(fsq);
		vtfs_drain_vq(fsq);
		FSQ_UNLOCK(fsq);
	}

}
