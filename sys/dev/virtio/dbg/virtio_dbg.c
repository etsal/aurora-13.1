/*-
 * Copyright (c) 2024 Emil Tsalapatis
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/kernel.h>
#include <sys/kobj.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rman.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/stat.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_param.h>

#include <machine/bus.h>
#include <machine/pmap.h>
#include <machine/resource.h>
#include <machine/vmparam.h>

#include <dev/virtio/virtio_config.h>
#include <dev/virtio/virtqueue.h>
#include <dev/virtio/dbg/virtio_dbg.h>
#include <dev/virtio/mmio/virtio_mmio.h>

#include "virtio_mmio_if.h"

#define VTDBG_MAGIC ((uint64_t)0x84848484ULL)

/* 
 * XXX Determine these sizes in a well-defined
 * per-device fashion.
 */
#define VTDBG_MAPSZ (1024 * 1024 * 10)
#define VTDBG_RESERVE_DEVSPACE (4096)

/* XXX Remove after development is done. */
#define VTDBG_WARN(format, ...)                                            \
	do {                                                                  \
		printf("(%s:%d) " format, __func__, __LINE__, ##__VA_ARGS__); \
	} while (0)

static device_t vtdbg_parent;
static driver_t *vtdbg_driver;

#define VTDBG_UPDATE_DESC	(0x1)
#define VTDBG_UPDATE_USED	(0x2)
#define VTDBG_UPDATE_AVAIL	(0x4)

/*
 * Information on a debug device instance. Accessed 
 * through the control device's softc.
 */
struct vtdbg_softc {
	struct mtx		vtd_mtx;
	struct knlist		vtd_note;
	uint32_t		vtd_magic;

	vm_object_t		vtd_object;
	vm_ooffset_t		vtd_baseaddr;
	size_t			vtd_bytes;
	size_t			vtd_allocated;

	virtqueue_intr_t	*vtd_intr;
	void			*vtd_intr_arg;
	uint32_t		vtd_flags;

	vm_ooffset_t		vtd_offset;

	device_t		vtd_dev;
};

/*
 * Subclass of vtmmio_softc that also lets the virtio device access
 * vtdbg related information while also being usable from vtmmio_*
 * methods. The vtdbg_softc * is the softc of the control device and 
 * is allocated dynamically when opening an instance of the control device, 
 * while the virtio_dbg_softc here is allocated during device_t creation.
 */
struct virtio_dbg_softc {
	struct vtmmio_softc	vtmdbg_mmio;
	struct vtdbg_softc	*vtmdbg_dbg;
};

/*
 * Store the parent bus and driver pointers for the debug devices,
 * because we need them when creating debug devices on-demand later on.
 * We are hanging off of the nexus, so we are certain it's not going away.
 */
static void
virtio_dbg_identify(driver_t *driver, device_t parent)
{
	vtdbg_parent = parent;
	vtdbg_driver = driver;
}

static struct vtdbg_softc *
vtmmio_get_vtdbg(device_t dev)
{
	struct virtio_dbg_softc *sc;

	sc = device_get_softc(dev);
	MPASS(sc->vtmdbg_dbg->vtd_magic == VTDBG_MAGIC);

	return (sc->vtmdbg_dbg);
}

/*
 * Explicitly turn polling into a no-op.
 */
static int
virtio_dbg_poll(device_t dev)
{

	return (0);
}


/*
 * Make sure the shared virtio device region between kernel and userspace
 * is configured properly.
 */
static int
virtio_dbg_probe(device_t dev)
{
	struct virtio_dbg_softc *sc;
	struct vtmmio_softc *mmiosc;
	uint32_t magic, version;

	sc = device_get_softc(dev);
	mmiosc = &sc->vtmdbg_mmio;

	/* Fake platform to trigger virtio_mmio_note() on writes. */
	sc->vtmdbg_mmio.platform = dev;

	magic = vtmmio_read_config_4(mmiosc, VIRTIO_MMIO_MAGIC_VALUE);
	if (magic != VIRTIO_MMIO_MAGIC_VIRT) {
		device_printf(dev, "Bad magic value %#x\n", magic);
		return (ENXIO);
	}

	version = vtmmio_read_config_4(mmiosc, VIRTIO_MMIO_VERSION);
	if (version != 2) {
		device_printf(dev, "Unsupported version: %#x\n", version);
		return (ENXIO);
	}

	if (vtmmio_read_config_4(mmiosc, VIRTIO_MMIO_DEVICE_ID) == 0)
		return (ENXIO);

	device_set_desc(dev, "VirtIO Emulated MMIO adapter");

	return (0);
}

/*
 * Creates the virtio device corresponding to the transport instance.
 */
static int 
virtio_dbg_attach(device_t dev)
{
	struct virtio_dbg_softc *sc;
	struct vtmmio_softc *mmiosc;
	device_t child;

	sc = device_get_softc(dev);
	mmiosc = &sc->vtmdbg_mmio;

	mmiosc->dev = dev;
	mmiosc->vtmmio_version = vtmmio_read_config_4(mmiosc, VIRTIO_MMIO_VERSION);

	vtmmio_reset(mmiosc);

	/* Tell the host we've noticed this device. */
	vtmmio_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);

	mtx_lock(&Giant);
	if ((child = device_add_child(dev, NULL, -1)) == NULL) {
		device_printf(dev, "Cannot create child device.\n");
		vtmmio_set_status(dev, VIRTIO_CONFIG_STATUS_FAILED);

		DEVICE_DETACH(dev);
		mtx_unlock(&Giant);

		return (ENOMEM);
	}

	mmiosc->vtmmio_child_dev = child;
	vtmmio_probe_and_attach_child(mmiosc);

	mtx_unlock(&Giant);

	return (0);
}

/*
 * Recompute the queue descriptor to be an offset within the shared user/kernel
 * device control region. Our userspace cannot meaningfully translate 
 * kernel physical addresses, so we transform the values in the queue
 * descriptor address registers into offsets. Userspace finds the vq address 
 * by adding the offset to its own virtual address for the region.
 */
static void
virtio_dbg_qdesc_offset(struct vtmmio_softc *sc, uint64_t baseaddr,
		int hireg, int loreg)
{
	struct resource *res = sc->res[0];
	uint32_t hi, lo;
	uint64_t qaddr;

	/* Read in the components of the physical address. */
	hi = bus_read_4(res, hireg);
	lo = bus_read_4(res, loreg);

	/* Recompute into an offset into the vq control region. */
	qaddr = (((uint64_t)hi) << 32 | (uint64_t)lo);
	qaddr -= vtophys(baseaddr);

	/* Update the register values. */
	hi = (qaddr >> 32);
	lo = (qaddr & ((1ULL << 32) - 1));
	
	/* Direct bus write because to avoid triggering note(). */
	bus_write_4(res, hireg, hi);
	bus_write_4(res, loreg, lo);
}

/* Notify userspace of a write, and wait for a response. */
static int
virtio_dbg_note(device_t dev, size_t offset, int val)
{
	struct vtdbg_softc *vtdsc;
	struct virtio_dbg_softc *sc;

	sc = device_get_softc(dev);
	vtdsc = sc->vtmdbg_dbg;
	MPASS(vtdsc->vtd_magic == VTDBG_MAGIC);

	/*
	 * Intercept writes to the QUEUE_{DESC, AVAIL, USED}_{HIGH, LOW} 
	 * registers and instead pass to the user the offset from the beginning 
	 * of the control region. Do not actually notify userspace of the writes,
	 * we will recompute and notify once we set VIRTIO_MMIO_QUEUE_READY.
	 *
	 * Both high and low registers are set together, so just track writes to
	 * the high address bits.
	 */
	switch (offset) {
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
		vtdsc->vtd_flags |= VTDBG_UPDATE_DESC;
		return (1);
	case VIRTIO_MMIO_QUEUE_USED_HIGH:
		vtdsc->vtd_flags |= VTDBG_UPDATE_USED;
		return (1);
	case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
		vtdsc->vtd_flags |= VTDBG_UPDATE_AVAIL;
		return (1);
	}

	/* Only forward the listed register writes to userspace. */
	switch (offset) {
	case VIRTIO_MMIO_HOST_FEATURES_SEL:
	case VIRTIO_MMIO_GUEST_FEATURES:
	case VIRTIO_MMIO_QUEUE_SEL:
	case VIRTIO_MMIO_QUEUE_NUM:
	case VIRTIO_MMIO_QUEUE_NOTIFY:
	case VIRTIO_MMIO_INTERRUPT_ACK:
	case VIRTIO_MMIO_STATUS:
		break;
	case VIRTIO_MMIO_QUEUE_READY:
		/* if changed, transform the offsets. */
		if (vtdsc->vtd_flags & VTDBG_UPDATE_DESC) {
			virtio_dbg_qdesc_offset(&sc->vtmdbg_mmio, vtdsc->vtd_baseaddr,
				VIRTIO_MMIO_QUEUE_DESC_HIGH, VIRTIO_MMIO_QUEUE_DESC_LOW);
			vtdsc->vtd_flags &= ~VTDBG_UPDATE_DESC;
		}

		if (vtdsc->vtd_flags & VTDBG_UPDATE_USED) {
			virtio_dbg_qdesc_offset(&sc->vtmdbg_mmio, vtdsc->vtd_baseaddr,
				VIRTIO_MMIO_QUEUE_USED_HIGH, VIRTIO_MMIO_QUEUE_USED_LOW);
			vtdsc->vtd_flags &= ~VTDBG_UPDATE_USED;
		}

		if (vtdsc->vtd_flags & VTDBG_UPDATE_AVAIL) {
			virtio_dbg_qdesc_offset(&sc->vtmdbg_mmio, vtdsc->vtd_baseaddr,
				VIRTIO_MMIO_QUEUE_AVAIL_HIGH, VIRTIO_MMIO_QUEUE_AVAIL_LOW);
			vtdsc->vtd_flags &= ~VTDBG_UPDATE_AVAIL;
		}
		break;
	default:
		return (1);
	}

	mtx_lock(&vtdsc->vtd_mtx);
	vtdsc->vtd_offset = offset;
	KNOTE_LOCKED(&vtdsc->vtd_note, 0);

	/* 
	 * We cannot sleep here because this code is called holding non-sleepable locks.
	 * This is because this busy wait's corresponding operation for other transports is 
	 * a VM exit, which is instantaneous from the point of view of the guest kernel.
	 * To prevent a "sleeping thread" panic, we busy wait here. There is always the
	 * danger of our VMM process leaving us hanging, but that is always a danger even
	 * with non-emulated virtio transports - it just isn't visible to the guest, since
	 * the VMM is normally on the host.
	 */
	while (vtdsc->vtd_offset != 0) {
		mtx_unlock(&vtdsc->vtd_mtx);
		cpu_spinwait();
		mtx_lock(&vtdsc->vtd_mtx);
	}

	mtx_unlock(&vtdsc->vtd_mtx);

	return (1);
}

/* 
 * Pass interrupt information to the cdev. The cdev will be directly
 * running the device interrupt handling code as an ioctl.
 */
static int
virtio_dbg_setup_intr(device_t dev, device_t mmio_dev, void *handler, void *ih_user)
{
	struct vtdbg_softc *sc;

	sc = vtmmio_get_vtdbg(dev);
	MPASS(sc->vtd_magic == VTDBG_MAGIC);

	mtx_lock(&sc->vtd_mtx);
	sc->vtd_intr = handler;
	sc->vtd_intr_arg = ih_user;
	mtx_unlock(&sc->vtd_mtx);

	return (0);
}

static device_method_t virtio_dbg_methods[] = {
	DEVMETHOD(device_attach,		virtio_dbg_attach),
	DEVMETHOD(device_identify,		virtio_dbg_identify),
	DEVMETHOD(device_probe,			virtio_dbg_probe),

	DEVMETHOD(virtio_mmio_poll,		virtio_dbg_poll),
	DEVMETHOD(virtio_mmio_note,		virtio_dbg_note),
	DEVMETHOD(virtio_mmio_setup_intr,	virtio_dbg_setup_intr),

        DEVMETHOD_END
};

DEFINE_CLASS_1(virtio_dbg, virtio_dbg_driver, virtio_dbg_methods,
    sizeof(struct vtdbg_softc), vtmmio_driver);
/*
 * XXX As noted below, we should be hanging off of the ram pseudodevice
 * so we can reserve part of the real physical memory for our device. This
 * is a significant task so avoid it for now.
 */
DRIVER_MODULE(virtio_dbg, nexus, virtio_dbg_driver, 0, 0);
MODULE_VERSION(virtio_dbg, 1);

static struct cdev *vtdbg_dev;

/*
 * Create and map the device memory into the kernel.
 */ 
static int
vtdbg_map_kernel(struct vtdbg_softc *sc)
{
	vm_object_t obj = sc->vtd_object;
	size_t bytes = IDX_TO_OFF(obj->size);
	vm_offset_t baseaddr, tmp;
	vm_page_t m, end_m;
	int error;

	/* XXX Do not allow mapping twice. */

	vm_object_reference(obj);

	/* 
	 * Populate the object with physically contiguous pages, because
	 * the object is used to back the virtio device control region.
	 */
	VM_OBJECT_WLOCK(obj);
	m = vm_page_alloc_contig(obj, 0, VM_ALLOC_NORMAL | VM_ALLOC_ZERO, obj->size,
			0, (uint64_t) -1, 1, 0, VM_MEMATTR_DEFAULT);
	VM_OBJECT_WUNLOCK(obj);
	if (m == NULL) {
		vm_object_deallocate(obj);
		return (ENOMEM);
	}


	baseaddr = VM_MIN_KERNEL_ADDRESS;
	error = vm_map_find(kernel_map, obj, 0, &baseaddr, bytes, VM_MAX_KERNEL_ADDRESS,
		VMFS_OPTIMAL_SPACE, VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error != KERN_SUCCESS) {
		vm_object_deallocate(obj);
		return (ENOMEM);
	}

	end_m = m + (bytes / PAGE_SIZE);
	tmp = baseaddr;
	for (; m < end_m; m++) {
		vm_page_valid(m);
		pmap_zero_page(m);
		pmap_enter(kernel_pmap, tmp, m, VM_PROT_RW,
		    VM_PROT_RW | PMAP_ENTER_WIRED, 0);
		tmp += PAGE_SIZE;
		vm_page_xunbusy(m);
	}


	sc->vtd_baseaddr = baseaddr;
	sc->vtd_bytes = bytes;

	/* Reserve space for the device control region. */
	sc->vtd_allocated = VTDBG_RESERVE_DEVSPACE;

	return (0);
}

/*
 * Destroy the virtio transport instance when closing the
 * corresponding control device fd.
 */
static void
vtdbg_dtor(void *arg)
{
	struct virtio_dbg_softc *devsc;
	struct vtdbg_softc *sc = (struct vtdbg_softc *)arg;
	vm_offset_t sva, eva;
	device_t dev;

	MPASS(sc->vtd_magic == VTDBG_MAGIC);

	dev = sc->vtd_dev;
	if (dev != NULL) {
		devsc = device_get_softc(dev);

		mtx_lock(&Giant);
		DEVICE_DETACH(dev);
		mtx_unlock(&Giant);

		free(devsc->vtmdbg_mmio.res[0], M_DEVBUF);
		bus_release_resource(dev, SYS_RES_MEMORY, 0,
				devsc->vtmdbg_mmio.res[0]);
		device_delete_child(vtdbg_parent, dev);
	}


	if (sc->vtd_baseaddr != 0) {
		sva = sc->vtd_baseaddr;
		eva = sva + sc->vtd_bytes;
		vm_map_remove(kernel_map, sva, eva);
		pmap_remove(kernel_pmap, sva, eva);
	}

	vm_object_deallocate(sc->vtd_object);

	knlist_delete(&sc->vtd_note, curthread, 0);
	knlist_destroy(&sc->vtd_note);
	mtx_destroy(&sc->vtd_mtx);

	free(sc, M_DEVBUF);
}

static int
vtdbg_open(struct cdev *cdev, int oflags, int devtype, struct thread *td)
{
	size_t sz = round_page(VTDBG_MAPSZ);
	struct vtdbg_softc *sc;
	int error;

	sc = malloc(sizeof(struct vtdbg_softc), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (sc == NULL)
		return (ENOMEM);

	sc->vtd_magic = VTDBG_MAGIC;
	mtx_init(&sc->vtd_mtx, "vtdbg", NULL, MTX_DEF);
	knlist_init_mtx(&sc->vtd_note, &sc->vtd_mtx);
				
	/* Create the common userspace/kernel virtio device region. */
	sc->vtd_object = vm_pager_allocate(OBJT_PHYS, NULL, sz, VM_PROT_ALL,
			0, thread0.td_ucred);
	if (sc->vtd_object == NULL) {
		vtdbg_dtor(sc);
		return (ENOMEM);
	}

	error = vtdbg_map_kernel(sc);
	if (error != 0) {
		vtdbg_dtor(sc);
		return (error);
	}

	error = devfs_set_cdevpriv((void *)sc, vtdbg_dtor);
	if (error != 0)
		vtdbg_dtor(sc);

	return (error);
}

static int
vtdbg_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
		vm_size_t size, vm_object_t *objp, int nprot)
{
	struct vtdbg_softc *sc;
	int error;

	error = devfs_get_cdevpriv((void **)&sc);
	if (error != 0)
		return (error);

	if (*offset + size > sc->vtd_bytes)
		return (EINVAL);

	vm_object_reference(sc->vtd_object);
	*objp = sc->vtd_object;

	return (0);
}

static void *
vtdbg_ringalloc(device_t dev, size_t size)
{
	struct vtdbg_softc *sc = vtmmio_get_vtdbg(dev);
	void *mem;

	MPASS(sc->vtd_magic == VTDBG_MAGIC);

	mtx_lock(&sc->vtd_mtx);
	if (sc->vtd_allocated + size > sc->vtd_bytes) {
		mtx_unlock(&sc->vtd_mtx);
		return (NULL);
	}
	
	mem = (void *)(sc->vtd_baseaddr + sc->vtd_allocated);
	sc->vtd_allocated += size;

	mtx_unlock(&sc->vtd_mtx);

	return (mem);
}

static device_t
vtdbg_create_transport(device_t parent, struct vtdbg_softc *vtdsc)
{
	struct virtio_dbg_softc *sc;
	struct vtmmio_softc *mmiosc;
	struct resource *res;
	device_t transport;

	int uid = 0;

	transport = BUS_ADD_CHILD(parent, 0, virtio_dbg_driver.name, uid);
	device_set_driver(transport, vtdbg_driver);

	sc = device_get_softc(transport);
	mmiosc = &sc->vtmdbg_mmio;

	/* 
	 * XXX Hack. Create the resource out of thin air to
	 * keep the vtmmio_write_* calls working. Ideally we would
	 * be reserving the resource out of the RAM pseudobus,
	 * but it has no associated struct rman * instance,
	 * and multiple arch-specific implementations. Changing
	 * it would require significant effort.
	 */
	res = malloc(sizeof(*res), M_DEVBUF, M_WAITOK);
	res->r_bushandle = vtdsc->vtd_baseaddr;
	res->r_bustag = X86_BUS_SPACE_MEM;
	mmiosc->res[0] = res;

	/* Ring buffer allocation callback. */
	mmiosc->vtmmio_ringalloc_cb = vtdbg_ringalloc;

	return (transport);
}

static int
vtdbg_linkup_transport(struct vtdbg_softc *vtdsc, device_t dev)
{
	struct virtio_dbg_softc *mmiosc;

	mtx_lock(&vtdsc->vtd_mtx);
	if (vtdsc->vtd_dev != NULL) {
		mtx_unlock(&vtdsc->vtd_mtx);
		return (EALREADY);
	}

	mmiosc = device_get_softc(dev);

	/* Have the device and cdev be able to refer to each other. */
	mmiosc->vtmdbg_dbg = vtdsc;
	vtdsc->vtd_dev = dev;

	mtx_unlock(&vtdsc->vtd_mtx);

	return (0);
}

/* 
 * Create virtio device. This function does the initialization both
 * for the emulated transport, and for the virtio device. These are
 * normally (e.g., for MMIO)) created at boot time using vtmmio_probe/vtmmio_attach,
 * and vtmmio_probe_and_attach_child, respectively. We do this initialization
 * here because we are dynamically creating the devices after booting, so 
 * we must manually invoke the device probe and attach methods.
 */
static int
vtdbg_init(void)
{
	struct virtio_dbg_softc *sc;
	struct vtdbg_softc *vtdsc;
	device_t transport;
	int error;

	/* Retrieve the mapping address/size. */
	error = devfs_get_cdevpriv((void **)&vtdsc);
	if (error != 0)
		return (error);

	MPASS(vtdsc->vtd_magic == VTDBG_MAGIC);

	transport = vtdbg_create_transport(vtdbg_parent, vtdsc);

	error = vtdbg_linkup_transport(vtdsc, transport);
	if (error != 0)
		goto err;

	error = DEVICE_PROBE(transport);
	if (error != 0)
		goto err;

	return (DEVICE_ATTACH(transport));

err:
	/* XXX Test this path. */

	sc = device_get_softc(transport);

	bus_release_resource(transport, SYS_RES_MEMORY, 0,
			sc->vtmdbg_mmio.res[0]);
	free(sc->vtmdbg_mmio.res[0], M_DEVBUF);

	mtx_lock(&Giant);
	device_delete_child(vtdbg_parent, transport);
	mtx_unlock(&Giant);

	vtdsc->vtd_dev = NULL;

	return (error);
}

/* 
 * Instead of triggering an interrupt to handle the virtqueue operation, userspace does it
 * itself using an ioctl().
 *
 * XXX Use a dedicated kernel thread instead, handling driver interrupts like
 * this is causing performance degradation.
 */
static void
vtdbg_kick(struct vtdbg_softc *sc)
{
	sc->vtd_intr(sc->vtd_intr_arg);
}

/*
 * The mmio virtio code uses note() to let the host know there has been a write.
 * The note() call suspends the thread until the userspace device has been properly
 * emulated, at which point a userspace thread will allow it to resume.
 *
 * There can only be one unacknowledged interrupt outstanding at a time, so a single
 * vtd_offset in the softc is enough.
 */
static void
vtdbg_ack(struct vtdbg_softc *sc)
{
	mtx_lock(&sc->vtd_mtx);
	sc->vtd_offset = 0;
	wakeup(sc);
	mtx_unlock(&sc->vtd_mtx);
}

/*
 * Get virtio data in and out of the kernel, required by userspace to interact with
 * the data pointed to by the virtqueue descriptors.
 */
static int
vtdbg_io(struct vtdbg_softc *sc, struct vtdbg_io_args *args)
{
	struct vtdbg_transfer *tf;
	caddr_t driver, device;
	int error = 0;
	size_t len;
	int i;

	tf = malloc(args->cnt * sizeof(*tf), M_DEVBUF, M_NOWAIT);
	if (tf == NULL)
		return (ENOMEM);

	error = copyin(args->transfers, tf, args->cnt * (sizeof(*tf)));
	if (error != 0) {
		free(tf, M_DEVBUF);
		return (error);
	}

	for (i = 0; i < args->cnt; i++) {
		driver = (caddr_t)PHYS_TO_DMAP((vm_paddr_t)tf[i].vtdt_driver);
		/* Translate from physical to kernel virtual. */
		device = tf[i].vtdt_device;
		len = tf[i].vtdt_len;

		if (args->touser)
			error = copyout(driver, device, len);
		else
			error = copyin(device, driver, len);

		if (error != 0)
			break;
	}

	free(tf, M_DEVBUF);

	return (error);
}


static int
vtdbg_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
	struct vtdbg_softc *sc;
	int ret = 0;

	ret = devfs_get_cdevpriv((void **)&sc);
	if (ret != 0)
		return (ret);

	MPASS(sc->vtd_magic == VTDBG_MAGIC);
	switch (cmd) {
	case VIRTIO_DBG_INIT:
		ret = vtdbg_init();
		break;
	case VIRTIO_DBG_KICK:
		vtdbg_kick(sc);
		break;
	case VIRTIO_DBG_ACK:
		vtdbg_ack(sc);
		break;
	case VIRTIO_DBG_TRANSFER:
		ret = vtdbg_io(sc, (struct vtdbg_io_args *)data);
		break;
	}

	return (ret);
}

static int
vtdbg_filt_attach(struct knote *kn)
{
	kn->kn_flags |= EV_CLEAR;
	return (0);
}

static void
vtdbg_filt_detach(struct knote *kn)
{
	struct vtdbg_softc *sc;
	sc = (struct vtdbg_softc *)kn->kn_hook;
	MPASS(sc->vtd_magic == VTDBG_MAGIC);

	knlist_remove(&sc->vtd_note, kn, 0);
	kn->kn_hook = NULL;
}

static int
vtdbg_filt_read(struct knote *kn, long hint)
{
	struct vtdbg_softc *sc;


	sc = (struct vtdbg_softc *)kn->kn_hook;
	MPASS(sc->vtd_magic == VTDBG_MAGIC);
	mtx_assert(&sc->vtd_mtx, MA_OWNED);

	if (sc->vtd_offset == 0)
		return (0);

	kn->kn_data = sc->vtd_offset;

	return (1);
}

struct filterops vtdbg_filtops = {
	.f_isfd = 1,
	.f_attach = vtdbg_filt_attach,
	.f_detach = vtdbg_filt_detach,
	.f_event = vtdbg_filt_read,
};

static int
vtdbg_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct vtdbg_softc *sc;
	int error;

	error = devfs_get_cdevpriv((void **)&sc);
	if (error != 0)
		return (error);
	MPASS(sc->vtd_magic == VTDBG_MAGIC);

	if (kn->kn_filter != EVFILT_READ) {
		kn->kn_data = EINVAL;
		return (EINVAL);
	}

	kn->kn_fop = &vtdbg_filtops;
	kn->kn_hook = sc;
	knlist_add(&sc->vtd_note, kn, 0);

	return (0);

}

static struct cdevsw vtdbg_cdevsw = {
	.d_open = vtdbg_open,
	.d_mmap_single = vtdbg_mmap_single,
	.d_ioctl = vtdbg_ioctl,
	.d_kqfilter = vtdbg_kqfilter,
	.d_name = "vtdbg",
	.d_version = D_VERSION,
};

static int
vtdbg_dev_create(void)
{
	vtdbg_dev = make_dev(&vtdbg_cdevsw, 0, UID_ROOT, GID_OPERATOR,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, "vtdbg");
	if (vtdbg_dev == NULL)
		return (ENOMEM);

	return (0);
}

static void
vtdbg_dev_destroy(void)
{
	MPASS(vtdbg_dev != NULL);
	destroy_dev(vtdbg_dev);
}

static int
vtdbg_loader(struct module *m, int what, void *arg)
{
	int err = 0;

	switch (what) {
	case MOD_LOAD:
		err = vtdbg_dev_create();
		break;
	case MOD_UNLOAD:
		vtdbg_dev_destroy();
		break;
	default:
		return (EINVAL);
	}

	return (err);
}

static moduledata_t vtdbg_moddata = {
	"vtdbg",
	vtdbg_loader,
	NULL,
};

DECLARE_MODULE(vtdbg, vtdbg_moddata, SI_SUB_VFS, SI_ORDER_MIDDLE);
