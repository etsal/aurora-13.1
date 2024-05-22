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
#include <dev/virtio/mmio/virtio_mmio.h>

#include "virtio_mmio_bounce_ioctl.h"
#include "virtio_mmio_if.h"

#define VTBOUNCE_MAGIC ((uint64_t)0x84848484ULL)

/* XXX Make this a sysctl. */
#define VTBOUNCE_MAPSZ (1024 * 1024 * 10)

/* XXX Remove after development is done. */
#define VTBOUNCE_WARN(format, ...)                                            \
	do {                                                                  \
		printf("(%s:%d) " format, __func__, __LINE__, ##__VA_ARGS__); \
	} while (0)

static device_t vtbounce_parent;
static driver_t *vtbounce_driver;
int global_tracking;

/*
 * Information on a bounce character device instance.
 */
struct vtbounce_softc {
	struct mtx		vtb_mtx;
	struct knlist		vtb_note;
	uint32_t		vtb_magic;

	vm_object_t		vtb_object;
	vm_ooffset_t		vtb_baseaddr;
	size_t			vtb_bytes;
	size_t			vtb_allocated;

	virtqueue_intr_t	*vtb_intr;
	void			*vtb_intr_arg;

	vm_ooffset_t		vtb_offset;

	device_t		vtb_dev;
};

/*
 * Subclass of vtmmio_softc that also lets the virtio device access
 * the character device's bounce buffer - related information.
 */
struct vtmmio_bounce_softc {
	struct vtmmio_softc	vtmb_mmio;
	struct vtbounce_softc	*vtmb_bounce;
};

static void
vtmmio_bounce_identify(driver_t *driver, device_t parent)
{
	vtbounce_parent = parent;
	vtbounce_driver = driver;
}

static struct vtbounce_softc *
vtmmio_get_vtb(device_t dev)
{
	struct vtmmio_bounce_softc *sc;

	sc = device_get_softc(dev);
	MPASS(sc->vtmb_bounce->vtb_magic == VTBOUNCE_MAGIC);

	return (sc->vtmb_bounce);
}

static int
vtmmio_bounce_poll(device_t dev)
{

	return (0);
}


static int
vtmmio_bounce_probe(device_t dev)
{
	struct vtmmio_bounce_softc *sc;
	struct vtmmio_softc *mmiosc;
	uint32_t magic, version;

	sc = device_get_softc(dev);
	mmiosc = &sc->vtmb_mmio;

	/* Fake platform to trigger virtio_mmio_note() on writes. */
	sc->vtmb_mmio.platform = dev;

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

static int 
vtmmio_bounce_attach(device_t dev)
{
	struct vtmmio_bounce_softc *sc;
	struct vtmmio_softc *mmiosc;
	device_t child;

	sc = device_get_softc(dev);
	mmiosc = &sc->vtmb_mmio;

	mmiosc->dev = dev;
	mmiosc->vtmmio_version = vtmmio_read_config_4(mmiosc, VIRTIO_MMIO_VERSION);

	vtmmio_reset(mmiosc);

	/* Tell the host we've noticed this device. */
	vtmmio_set_status(dev, VIRTIO_CONFIG_STATUS_ACK);

	/* 
	 * XXX Use the giant lock only when using device_* API, otherwise
	 * a bug on bhyve causes a lockup.
	 */
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
 * Recompute the queue descriptor to be an offset within the shared
 * bhyve/kernel vq region. Our userspace cannot meaningfully translate 
 * kernel physical addresses, so we transform the values in the queue
 * descriptor address registers into offsets. Userspace can add the offset
 * to its own virtual address for the common region to find the vq.
 */
static void
vtmmio_bounce_qdesc_offset(struct vtmmio_softc *sc, uint64_t baseaddr,
		int hireg, int loreg)
{
	uint32_t hi, lo;
	uint64_t qaddr;

	/* Read in the components of the physical address. */
	hi = bus_read_4(sc->res[0], hireg);
	lo = bus_read_4(sc->res[0], loreg);

	/* Recompute into an offset into the vq control region. */
	qaddr = (((uint64_t)hi) << 32 | (uint64_t)lo);
	qaddr -= vtophys(baseaddr);

	/* Update the register values. */
	hi = (qaddr >> 32);
	lo = (qaddr & ((1ULL << 32) - 1));
	
	bus_write_4(sc->res[0], hireg, hi);
	bus_write_4(sc->res[0], loreg, lo);
}

/* XXX Embed into the softc state. */
bool qdesc_recompute, qavail_recompute, qused_recompute;

/* Notify userspace of a write, and wait for a response. */
static int
vtmmio_bounce_note(device_t dev, size_t offset, int val)
{
	struct vtbounce_softc *vtbsc;
	struct vtmmio_bounce_softc *sc;

	sc = device_get_softc(dev);
	vtbsc = sc->vtmb_bounce;
	MPASS(vtbsc->vtb_magic == VTBOUNCE_MAGIC);

	/*
	 * Intercept writes to the QUEUE_{DESC, AVAIL, USED}_{HIGH, LOW} 
	 * registers and instead pass to the user the offset from the beginning 
	 * of the control region. Do not actually notify userspace of the writes,
	 * it will be notified once we set VIRTIO_MMIO_QUEUE_READY.
	 */
	switch (offset) {
	case VIRTIO_MMIO_QUEUE_DESC_HIGH:
		qdesc_recompute = 1;
		return (1);
	case VIRTIO_MMIO_QUEUE_USED_HIGH:
		qused_recompute = 1;
		return (1);
	case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
		qavail_recompute = 1;
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
		if (qdesc_recompute) {
			vtmmio_bounce_qdesc_offset(&sc->vtmb_mmio, vtbsc->vtb_baseaddr,
				VIRTIO_MMIO_QUEUE_DESC_HIGH, VIRTIO_MMIO_QUEUE_DESC_LOW);
			qdesc_recompute = 0;
		}

		if (qused_recompute) {
			vtmmio_bounce_qdesc_offset(&sc->vtmb_mmio, vtbsc->vtb_baseaddr,
				VIRTIO_MMIO_QUEUE_USED_HIGH, VIRTIO_MMIO_QUEUE_USED_LOW);
			qused_recompute = 0;
		}

		if (qavail_recompute) {
			vtmmio_bounce_qdesc_offset(&sc->vtmb_mmio, vtbsc->vtb_baseaddr,
				VIRTIO_MMIO_QUEUE_AVAIL_HIGH, VIRTIO_MMIO_QUEUE_AVAIL_LOW);
			qavail_recompute = 0;
		}
		break;
	default:
		return (1);
	}

	mtx_lock(&vtbsc->vtb_mtx);
	vtbsc->vtb_offset = offset;
	KNOTE_LOCKED(&vtbsc->vtb_note, 0);

	msleep(vtbsc, &vtbsc->vtb_mtx, PRIBIO, "vtmmionote", 0);

	mtx_unlock(&vtbsc->vtb_mtx);

	return (1);
}

/* 
 * Pass interrupt information to the cdev. The cdev will be directly
 * running the device interrupt handling code as an ioctl.
 */
static int
vtmmio_bounce_setup_intr(device_t dev, device_t mmio_dev, void *handler, void *ih_user)
{
	struct vtbounce_softc *sc;

	sc = vtmmio_get_vtb(dev);
	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);

	mtx_lock(&sc->vtb_mtx);
	sc->vtb_intr = handler;
	sc->vtb_intr_arg = ih_user;
	mtx_unlock(&sc->vtb_mtx);

	return (0);
}

static device_method_t vtmmio_bounce_methods[] = {
        /* Device interface. */
	DEVMETHOD(bus_add_child,		bus_generic_add_child),
	DEVMETHOD(bus_alloc_resource,		bus_generic_alloc_resource),
	DEVMETHOD(bus_release_resource,		bus_generic_release_resource),
	DEVMETHOD(bus_print_child,		bus_generic_print_child),

	DEVMETHOD(device_attach,		vtmmio_bounce_attach),
	DEVMETHOD(device_identify,		vtmmio_bounce_identify),
	DEVMETHOD(device_probe,			vtmmio_bounce_probe),

	DEVMETHOD(virtio_mmio_poll,		vtmmio_bounce_poll),
	DEVMETHOD(virtio_mmio_note,		vtmmio_bounce_note),
	DEVMETHOD(virtio_mmio_setup_intr,	vtmmio_bounce_setup_intr),

        DEVMETHOD_END
};

DEFINE_CLASS_1(vtmmio_bounce, vtmmio_bounce_driver, vtmmio_bounce_methods,
    sizeof(struct vtbounce_softc), vtmmio_driver);
DRIVER_MODULE(vtmmio_bounce, ram, vtmmio_bounce_driver, 0, 0);
MODULE_DEPEND(vtmmio_bounce, ram, 1, 1, 1);
MODULE_VERSION(vtmmio_bounce, 1);

static struct cdev *bouncedev;

/*
 * Create and map the device memory into the kernel.
 */ 
static int
virtio_bounce_map_kernel(struct vtbounce_softc *sc)
{
	vm_object_t obj = sc->vtb_object;
	size_t bytes = IDX_TO_OFF(obj->size);
	vm_offset_t baseaddr, tmp;
	vm_page_t m, end_m;
	int error;

	/*
	 * XXX Do not allow mapping twice.
	 */

	vm_object_reference(obj);

	/* 
	 * Populate the object with physically contiguous pages, because
	 * the object is used to back the virtqueue descriptor regions.
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
	printf("PHYSICAL ADDRESS %lx\n", m->phys_addr);
	tmp = baseaddr;
	for (; m < end_m; m++) {
		vm_page_valid(m);
		pmap_enter(kernel_pmap, tmp, m, VM_PROT_RW,
		    VM_PROT_RW | PMAP_ENTER_WIRED, 0);
		tmp += PAGE_SIZE;
		vm_page_xunbusy(m);
	}


	sc->vtb_baseaddr = baseaddr;
	sc->vtb_bytes = bytes;

	return (0);
}

static void
virtio_bounce_dtor(void *arg)
{
	struct vtmmio_bounce_softc *devsc;
	struct vtbounce_softc *sc = (struct vtbounce_softc *)arg;
	device_t dev;

	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);

	dev = sc->vtb_dev;
	if (dev != NULL) {
		devsc = device_get_softc(dev);

		mtx_lock(&Giant);
		DEVICE_DETACH(dev);
		mtx_unlock(&Giant);

		free(devsc->vtmb_mmio.res[0], M_DEVBUF);
		/*
		bus_release_resource(dev, SYS_RES_MEMORY, 0,
				devsc->vtmb_mmio.res[0]);
				*/
		device_delete_child(vtbounce_parent, dev);
	}


	if (sc->vtb_baseaddr != 0) {
		/* XXX Remove from the pmap */
		vm_map_remove(kernel_map, sc->vtb_baseaddr,
			sc->vtb_baseaddr + sc->vtb_bytes);
	}

	vm_object_deallocate(sc->vtb_object);

	knlist_delete(&sc->vtb_note, curthread, 0);
	knlist_destroy(&sc->vtb_note);
	mtx_destroy(&sc->vtb_mtx);

	free(sc, M_DEVBUF);
}

static int
virtio_bounce_open(struct cdev *cdev, int oflags, int devtype, struct thread *td)
{
	size_t sz = round_page(VTBOUNCE_MAPSZ);
	struct vtbounce_softc *sc;
	int error;

	sc = malloc(sizeof(struct vtbounce_softc), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (sc == NULL)
		return (ENOMEM);

	sc->vtb_magic = VTBOUNCE_MAGIC;
	mtx_init(&sc->vtb_mtx, "vtbounce", NULL, MTX_DEF);
	knlist_init_mtx(&sc->vtb_note, &sc->vtb_mtx);
				
	/* vm_page_alloc_contig_domain */
	sc->vtb_object = vm_pager_allocate(OBJT_PHYS, NULL, sz, VM_PROT_ALL,
			0, thread0.td_ucred);
	if (sc->vtb_object == NULL) {
		virtio_bounce_dtor(sc);
		return (ENOMEM);
	}

	error = virtio_bounce_map_kernel(sc);
	if (error != 0) {
		virtio_bounce_dtor(sc);
		return (error);
	}

	error = devfs_set_cdevpriv((void *)sc, virtio_bounce_dtor);
	if (error != 0)
		virtio_bounce_dtor(sc);

	return (error);
}

static int
virtio_bounce_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
		vm_size_t size, vm_object_t *objp, int nprot)
{
	struct vtbounce_softc *sc;
	int error;

	error = devfs_get_cdevpriv((void **)&sc);
	if (error != 0)
		return (error);

	if (*offset + size > sc->vtb_bytes)
		return (EINVAL);

	vm_object_reference(sc->vtb_object);
	*objp = sc->vtb_object;

	return (0);
}

static void *
virtio_bounce_ringalloc(device_t dev, size_t size)
{
	struct vtbounce_softc *sc = vtmmio_get_vtb(dev);
	void *mem;

	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);

	mtx_lock(&sc->vtb_mtx);
	if (sc->vtb_allocated + size > sc->vtb_bytes) {
		mtx_unlock(&sc->vtb_mtx);
		return (NULL);
	}
	
	mem = (void *)(sc->vtb_baseaddr + sc->vtb_allocated);
	/* XXX Zero at allocation time. */
	bzero(mem, size);
	sc->vtb_allocated += size;

	mtx_unlock(&sc->vtb_mtx);

	return (mem);
}

static device_t
virtio_bounce_create_transport(device_t parent, struct vtbounce_softc *vtbsc)
{
	struct vtmmio_bounce_softc *sc;
	struct vtmmio_softc *mmiosc;
	struct resource *res;
	device_t transport;

	int uid = 0;

	/* 
	 * Create an instance of the emulated mmio transport. The RAM pseudobus
	 * does not have any bus method pointers, so directly call the generic
	 * functions.
	 * XXX Move this to the RAM pseudobus.
	 * XXX The RAM pseudobus is not fleshed out enough for this.
	 */
	transport = BUS_ADD_CHILD(parent, 0, vtmmio_bounce_driver.name, uid);

	device_set_driver(transport, vtbounce_driver);

	sc = device_get_softc(transport);
	mmiosc = &sc->vtmb_mmio;

	/* 
	 * XXX Hack. Create the resource out of thin air to
	 * keep the bus_write_* calls working. Ideally we would
	 * be reserving the resource out of the RAM pseudobus,
	 * but it has no implementation for resource management
	 * and multiple arch-specific implementations. Changing
	 * it would require significant effort.
	 */
	res = malloc(sizeof(*res), M_DEVBUF, M_WAITOK);
	res->r_bushandle = vtbsc->vtb_baseaddr;
	res->r_bustag = X86_BUS_SPACE_MEM;
	mmiosc->res[0] = res;

	/* Ring buffer allocation callback. */
	mmiosc->vtmmio_ringalloc_cb = virtio_bounce_ringalloc;

	return (transport);
}

static int
virtio_bounce_linkup_transport(struct vtbounce_softc *vtbsc, device_t dev)
{
	struct vtmmio_bounce_softc *mmiosc;

	mtx_lock(&vtbsc->vtb_mtx);
	if (vtbsc->vtb_dev != NULL) {
		mtx_unlock(&vtbsc->vtb_mtx);
		return (EALREADY);
	}

	mmiosc = device_get_softc(dev);

	/* Have the device and cdev be able to refer to each other. */
	mmiosc->vtmb_bounce = vtbsc;
	vtbsc->vtb_dev = dev;

	mtx_unlock(&vtbsc->vtb_mtx);

	return (0);
}

/* 
 * Create virtio device. This function does the initialization both
 * for the emulated transport, and for the virtio device. These are
 * normally initialized at boot time using vtmmio_probe/vtmmio_attach,
 * and vtmmio_probe_and_attach_child, respectively. We do this initialization
 * here becauseewe are dynamically creating the devices after booting, so 
 * we must manually invoke the Newbus methods.
 */
static int
virtio_bounce_init(void)
{
	struct vtmmio_bounce_softc *mmiosc;
	struct vtbounce_softc *vtbsc;
	device_t transport;
	int error;

	/* Retrieve the mapping address/size. */
	error = devfs_get_cdevpriv((void **)&vtbsc);
	if (error != 0)
		return (error);

	MPASS(vtbsc->vtb_magic == VTBOUNCE_MAGIC);

	/* Create the child and assign its resources. */
	transport = virtio_bounce_create_transport(vtbounce_parent, vtbsc);

	error = virtio_bounce_linkup_transport(vtbsc, transport);
	if (error != 0)
		goto err;

	error = DEVICE_PROBE(transport);
	if (error != 0)
		goto err;

	return (DEVICE_ATTACH(transport));

err:

	mmiosc = device_get_softc(transport);

	/*
	bus_release_resource(transport, SYS_RES_MEMORY, 0,
			mmiosc->vtmb_mmio.res[0]);
			*/
	free(mmiosc->vtmb_mmio.res[0], M_DEVBUF);
	mtx_lock(&Giant);
	device_delete_child(vtbounce_parent, transport);
	mtx_unlock(&Giant);
	vtbsc->vtb_dev = NULL;

	return (error);
}

/* 
 * Instead of triggering an interrupt to handle 
 * the virtqueue operation, we do it ourselves.
 */
static void
virtio_bounce_kick(struct vtbounce_softc *sc)
{
	sc->vtb_intr(sc->vtb_intr_arg);
}

/*
 * The mmio virtio code uses note() to let the host know there has been a write.
 * The note() call suspends the thread until the userspace device has been properly
 * emulated, at which point a userspace thread will allow it to resume.
 */
static void
virtio_bounce_ack(struct vtbounce_softc *sc)
{
	mtx_lock(&sc->vtb_mtx);
	sc->vtb_offset = 0;
	wakeup(sc);
	mtx_unlock(&sc->vtb_mtx);
}

static int
virtio_bounce_io(struct vtbounce_softc *sc, struct virtio_bounce_io_args *args)
{
	struct virtio_bounce_transfer *tf;
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
		driver = (caddr_t)PHYS_TO_DMAP((vm_paddr_t)tf[i].vtbt_driver);
		/* Translate from physical to kernel virtual. */
		device = tf[i].vtbt_device;
		len = tf[i].vtbt_len;

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
virtio_bounce_ioctl(struct cdev *cdev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
	struct vtbounce_softc *sc;
	int ret = 0;

	ret = devfs_get_cdevpriv((void **)&sc);
	if (ret != 0)
		return (ret);

	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);
	switch (cmd) {
	case VIRTIO_BOUNCE_INIT:
		ret = virtio_bounce_init();
		break;
	case VIRTIO_BOUNCE_KICK:
		virtio_bounce_kick(sc);
		break;
	case VIRTIO_BOUNCE_ACK:
		virtio_bounce_ack(sc);
		break;
	case VIRTIO_BOUNCE_TRANSFER:
		ret = virtio_bounce_io(sc, (struct virtio_bounce_io_args *)data);
		break;
	}

	return (ret);
}

static int
virtio_bounce_filt_attach(struct knote *kn)
{
	kn->kn_flags |= EV_CLEAR;
	return (0);
}

static void
virtio_bounce_filt_detach(struct knote *kn)
{
	struct vtbounce_softc *sc;
	sc = (struct vtbounce_softc *)kn->kn_hook;
	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);

	knlist_remove(&sc->vtb_note, kn, 0);
	kn->kn_hook = NULL;
}

static int
virtio_bounce_filt_read(struct knote *kn, long hint)
{
	struct vtbounce_softc *sc;


	/* 
	 * XXX What happens if we have multiple
	 * threads triggering events? Looks like 
	 * we need a queue to be consumed by userspace.
	 */

	sc = (struct vtbounce_softc *)kn->kn_hook;
	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);
	mtx_assert(&sc->vtb_mtx, MA_OWNED);

	if (sc->vtb_offset == 0)
		return (0);

	kn->kn_data = sc->vtb_offset;

	return (1);
}

struct filterops virtio_bounce_filtops = {
	.f_isfd = 1,
	.f_attach = virtio_bounce_filt_attach,
	.f_detach = virtio_bounce_filt_detach,
	.f_event = virtio_bounce_filt_read,
};

static int
virtio_bounce_kqfilter(struct cdev *dev, struct knote *kn)
{
	struct vtbounce_softc *sc;
	int error;

	error = devfs_get_cdevpriv((void **)&sc);
	if (error != 0)
		return (error);
	MPASS(sc->vtb_magic == VTBOUNCE_MAGIC);

	if (kn->kn_filter != EVFILT_READ) {
		kn->kn_data = EINVAL;
		return (EINVAL);
	}

	kn->kn_fop = &virtio_bounce_filtops;
	kn->kn_hook = sc;
	knlist_add(&sc->vtb_note, kn, 0);

	return (0);

}

static struct cdevsw virtio_bounce_cdevsw = {
	.d_open = virtio_bounce_open,
	.d_mmap_single = virtio_bounce_mmap_single,
	.d_ioctl = virtio_bounce_ioctl,
	.d_kqfilter = virtio_bounce_kqfilter,
	.d_name = "virtio_bounce",
	.d_version = D_VERSION,
};

static int
virtio_bounce_dev_create(void)
{
	bouncedev = make_dev(&virtio_bounce_cdevsw, 0, UID_ROOT, GID_OPERATOR,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP, "virtio_bounce");
	if (bouncedev == NULL)
		return (ENOMEM);

	return (0);
}

static void
virtio_bounce_dev_destroy(void)
{
	MPASS(bouncedev != NULL);
	destroy_dev(bouncedev);
}

static int
virtio_bounce_loader(struct module *m, int what, void *arg)
{
	int err = 0;

	switch (what) {
	case MOD_LOAD:
		err = virtio_bounce_dev_create();
		break;
	case MOD_UNLOAD:
		virtio_bounce_dev_destroy();
		break;
	default:
		return (EINVAL);
	}

	return (err);
}

static moduledata_t virtio_bounce_moddata = {
	"virtio_bounce",
	virtio_bounce_loader,
	NULL,
};

DECLARE_MODULE(virtio_bounce, virtio_bounce_moddata, SI_SUB_VFS, SI_ORDER_MIDDLE);
