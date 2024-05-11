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
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/rman.h>
#include <sys/stat.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <vm/vm_extern.h>

#include <dev/virtio/mmio/virtio_mmio.h>

#define VTBOUNCE_PLATFORM (0x0badcafe)

struct vtbounce_softc {
	struct vtmmio_softc sc;
	struct kthread *td;
	struct waitchannel *wc;
};
/**/

#define VTMMIO_SOFTC(sc) (sc.sc)

static int
vtmmio_bounce_probe(device_t dev)
{
	printf("virtio bounce can only be explicitly added\n"):
	return (EINVAL);
}

/*
 * We create a fake platform to trigger virtio_mmio_note() calls.
 */
static int
vtmmio_bounce_attach(device_t dev)
{
	struct vtmmio_softc *sc;

	sc = device_get_softc(dev);
	sc->platform = VTBOUNCE_PLATFORM;

	return (vtmmio_attach(dev));
}

/* XXX Use this to notify userspace after we write, and possibly wait for it. */
static int
vtmmio_bounce_note(device_t dev, size_t offset, int val)
{
	/* XXX Grab the softc, extract the fd. */
	/* XXX Write on the control block. */
	/* XXX Deliver a kqueue event to it. */
	/* XXX Wait on a per-softc for the user to write back. */
	return (1);
}

static int
vtmmio_bounce_setup_intr(device_t dev, device_t mmio_dev, void *handler, void *ih_user)
{
	/* XXX Pass the handler function to the kernel thread. */
	return (0);
}

static device_method_t vtmmio_bounce_methods[] = {
        /* Device interface. */
	DEVMETHOD(device_probe,			vtmmio_bounce_probe),
	DEVMETHOD(device_attach,		vtmmio_bounce_attach),

	DEVMETHOD(virtio_mmio_setup_intr,	vtmmio_bounce_setup_intr),
	DEVMETHOD(virtio_mmio_note,		vtmmio_bounce_note),

        DEVMETHOD_END
};

DEFINE_CLASS_1(virtio_mmio, vtmmio_bounce_driver, vtmmio_bounce_methods,
    sizeof(struct vtbounce_softc), vtmmio_driver);
DRIVER_MODULE(vtmmio_bounce, nexus, vtmmio_bounce_driver, 0, 0);

struct cdev *bouncedev;

/*
 * The mapping/wiring logic is taken from kern/link_elf_obj.c
 */ 
static int
virtio_bounce_map_kernel(vm_object_t obj, vm_offset_t *baseaddrp)
{
	size_t sz = IDX_TO_OFF(obj->size);
	vm_offset_t baseaddr;
	int error;

#ifdef __amd64__
	baseaddr = KERNBASE;
#else
	baseaddr = VM_MIN_KERNEL_ADDRESS;
#endif

	error = vm_map_find(kernel_map, obj, 0, &baseaddr, round_page(sz),
			0, VMFS_OPTIMAL_SPACE, VM_PROT_ALL, VM_PROT_ALL, 0);
	if (error != KERN_SUCCESS) {
		vm_object_deallocate(obj);
		return (ENOMEM);
	}

	/* Wire the pages */
	error = vm_map_wire(kernel_map, baseaddr, baseaddr + sz,
	    VM_MAP_WIRE_SYSTEM|VM_MAP_WIRE_NOHOLES);
	if (error != KERN_SUCCESS) {
		vm_map_remove(baseaddr, baseaddr + sz);
		return (ENOMEM);
	}

	*baseaddrp = baseaddr;

	return (0);
}

/* XXX Make this a sysctl. */
#define MAPPING_SIZE (1024 * 1024 * 10)

void
virtio_bounce_dtor(void *arg)
{
	vm_offset_t baseaddr = (vm_offset_t) arg;
	vm_map_entry_t entry;

	vm_map_lookup_entry(kernel_map, baseaddr, &entry);
	MPASS(entry->start == baseaddr);

	vm_map_delete(entry->start, entry->end);
}

static int
virtio_bounce_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	size_t sz = round_page(MAPPING_SIZE);
	vm_offset_t baseaddr;
	vm_object_t obj;
	int error;

	obj = vm_pager_allocate(OBJT_PHYS, NULL, sz, VM_PROT_ALL,
			0, thread0.td_ucred);
	if (obj == NULL)
		return (ENOMEM);

	error = virtio_bounce_map_kernel(obj, &baseaddr);
	if (error != 0) {
		vm_object_deallocate(obj);
		return (error);
	}

	error = devfs_set_cdevpriv((void *)baseaddr, virtio_bounce_dtor);
	if (error != 0)
		virtio_bounce_dtor((void *) kernmapping);

	return (error);
}

static int
virtio_bounce_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t size,
		struct vm_object_t **objp, int nprot)
{
	vm_map_entry_t entry;
	vm_offset_t baseaddr;
	size_t maxsize;
	vm_object_t obj;
	int error;

	error = devfs_get_cdevpriv(&baseaddr);
	if (error != 0)
		return (error);

	vm_map_lookup_entry(kernel_map, baseaddr, &entry);
	MPASS(entry->start == baseaddr);

	obj = entry->vm_object.object;
	maxsize = IDX_TO_OFF(obj->size);

	if (*offset + size > maxsize)
		return (EINVAL);

	vm_object_reference(obj);
	*objp = obj;
	return (0);
}

static int
virtio_bounce_initialize(void)
{
	unsigned long baseaddr;
	vm_map_entry_t entry;
	vm_offset_t baseaddr;
	device_t child;
	vm_object_t obj;
	size_t sz;
	int error;

	/* XXX Prevent initializing the same device twice. */

	/* Retrieve the mapping address/size. */
	error = devfs_get_cdevpriv(&baseaddr);
	if (error != 0)
		return (error);

	vm_map_lookup_entry(kernel_map, baseaddr, &entry);
	MPASS(entry->start == baseaddr);

	obj = entry->vm_object.object;
	sz = round_page(obj->size);

	/* Create the child and assign its resources. */
	child = BUS_ADD_CHILD(vtmmio_bounce_driver, 0, vtmmio_bounce_driver->name, -1);
	bus_set_resource(child, SYS_RES_MEMORY, 0, baseaddr, sz);
	device_set_driver(child, vtmmio_bounce_driver);

	return (0);
}

/* 
 * Instead of triggering an interrupt to handle 
 * the virtqueue operation, we do it ourselves.
 */
static void
virtio_bounce_kick(void)
{
	/* XXX Access the interrupt handling function and argument and run it. */
	panic("unimplemented");
}

/*
 * The mmio virtio code uses note() to let the host know there has been a write.
 * The note() call suspends the thread until the userspace device has been properly
 * emulated, at which point a userspace thread will allow it to resume.
 */
static void
virtio_bounce_resume(void)
{
	/* XXX Find the waitchannel for the device. */
	/* XXX Notify the waitchannel to allow any executing thread to resume. */
	panic("unimplemented");
}

static int
virtio_bounce_ioctl(struct cdev *dev, u_long cmd, caddr_data, int fflag, struct thread *td)
{
	switch (cmd) {
	case VIRTIO_BOUNCE_INIT:
		virtio_bounce_initialize();
		break;
	case VIRTIO_BOUNCE_STOP:
		/* Stop and detach the device. */
		panic("Unimplemented");
		break;
	case VIRTIO_BOUNCE_KICK:
		virtio_bounce_kick();
		break;
	case VIRTIO_BOUNCE_RESUME:
		virtio_bounce_resume();
		break;
	}

	return (0);
}

static void
fuse_device_filt_detach(struct knote *kn)
{
	/* XXX Remove the control block of the softc as private data. */
	return (0);
}

static int
virtio_bounce_filt_read(struct knote *kn, long hint)
{

	/* 
	 * XXX Only return success if there has been a write
	 * from the driver. If so, retrieve the address it
	 * happened in and add it to kn_data.
	 */
	

	/* XXX Return the address of the write to the user. */
	kn->kn_data = 0;

	return (1);
}

struct filterops fuse_device_rfiltops = {
	.f_isfd = 1,
	.f_detach = virtio_bounce_filt_detach,
	.f_event = virtio_bounce_filt_read,
};

static int
virtio_bounce_filter(struct cdev *dev, struct knote *kn)
{
	if (kn->kn_filter != EVFILT_READ) {
		kn->kn_data = EINVAL;
		return (EINVAL);
	}

	kn->kn_fop = &virtio_bounce_rfiltops;
	/* 
	 * XXX Pass a data structure that allows the filter to
	 * eventually retrieve the address that was written.
	 */
	kn->kn_hook = NULL;

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
virtio_bounce_init(void)
{
	bouncedev = make_dev(&virtio_bounce_cdevsw, 0, UID_ROOT, GID_OPERATOR,
	    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH, "virtio_bounce");
	if (bouncedev == NULL)
		return (ENOMEM);

	return (0);
}

static void
virtio_bounce_destroy(void)
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
		err = virtio_bounce_init();
		break;
	case MOD_UNLOAD:
		virtio_bounce_destroy();
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
