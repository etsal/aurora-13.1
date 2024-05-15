#include <sys/mman.h>

#include <endian.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/event.h>

#include <dev/virtio/virtio.h>
#include <dev/virtio/mmio/virtio_mmio.h>
#include <dev/virtio/mmio/virtio_mmio_bounce_ioctl.h>

#include "mmio_emul.h"

#define BOUNCEDEV ("/dev/virtio_bounce")

/* XXX We currently hardcode how large the region is. */
#define MMIO_REGION_SIZE (1024 * 1024 * 10)

static void
handle_state_change(struct mmio_devinst *mi, uint32_t status)
{
	switch (mi->mi_state) {
	case MIDEV_INVALID:
		if (status & VIRTIO_CONFIG_STATUS_ACK)
			mi->mi_state = MIDEV_ACKNOWLEDGED;
		break;

	case MIDEV_ACKNOWLEDGED:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER)
			mi->mi_state = MIDEV_DRIVER_FOUND;
		break;

	case MIDEV_DRIVER_FOUND:
		if (status & VIRTIO_CONFIG_S_FEATURES_OK)
			mi->mi_state = MIDEV_FEATURES_OK;
		break;

	case MIDEV_FEATURES_OK:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			mi->mi_state = MIDEV_LIVE;

		break;

	case MIDEV_LIVE:
		break;

	case MIDEV_FAILED:
		mi->mi_state = MIDEV_FAILED;
		break;

	default:
		errx(EXIT_FAILURE, "Invalid state %d", mi->mi_state);
		exit(1);
	}
}

static void
handle_status(struct mmio_devinst *mi, uint32_t status)
{
	if (status & VIRTIO_CONFIG_STATUS_FAILED) {
		mi->mi_state = MIDEV_FAILED;
		return;
	}

	if (status & VIRTIO_CONFIG_STATUS_RESET) {
		/* XXX Call a device reset. */
		//vi_reset_dev();
		mi->mi_state = MIDEV_INVALID;
		return;
	}

	handle_state_change(mi, status);
}

/* XXX Set up init_mmio_vtblk() */
/* XXX Use vi_mmio_write as a main loop instead. */
static void
handle_mmio(struct mmio_devinst *mi, uint64_t offset)
{
	uint32_t status;
	/* XXX Handle configuration space changes */

	switch (offset) {
	case VIRTIO_MMIO_STATUS:
		status = 0;
		handle_status(mi, status);
		break;

	default:
		errx(EXIT_FAILURE, "Invalid offset %lx\n", offset);

	}
}

static void
bounce_handler(int kq, struct mmio_devinst *mi)
{
	struct kevent kev;
	int ret;

	for (;;) {
		ret = kevent(kq, NULL, 0, &kev, 1, NULL);
		if (ret == -1) {
			perror("kevent");
			exit(1);
		}

		if (ret == 0)
			continue;

		if (kev.flags & EV_ERROR)
			errx(EXIT_FAILURE, "kevent: %s",  strerror(kev.data));

		handle_mmio(mi, kev.data);

		/* Let in-progress operations continue.  */
		ioctl(mi->mi_fd, VIRTIO_BOUNCE_ACK);
	}

	pthread_exit(NULL);
}

/* XXX Pass arguments for specifying a device. */
int main(void)
{
	struct kevent kev;
	char *mmio;
	int kq, fd;
	int error;
	int ret;

	/* XXX Specify type of device from command line*/
	/* XXX Get the name, look into the list of all available device.
	 * If we do not find it, return. Otherwise, return the device struct. 
	 */

	fd = open(BOUNCEDEV, O_RDWR);
	if (fd == -1) {
		perror("open");
		exit(1);
	}

	mmio = mmap(NULL, MMIO_REGION_SIZE, PROT_READ | PROT_WRITE,
			MAP_FILE | MAP_SHARED, fd, 0);
	if (mmio == MAP_FAILED) {
		perror("mmap");
		pthread_exit(NULL);
	}

	kq = kqueue();
	if (kq == -1) {
		perror("kqueue");
		exit(1);
	}

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ret = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (ret == -1) {
		perror("kevent");
		exit(1);
	}

	/* XXX TEMP */
	struct mmio_devinst mi;
	//mi.mi_d = &mmio_de_vblk;
	strncpy(mi.mi_name, "vtbd-emu", sizeof("vtlblk-emu"));
	mi.mi_mmio = mmio;
	mi.mi_size = MMIO_REGION_SIZE;
	mi.mi_fd = fd;

	error = ioctl(fd, VIRTIO_BOUNCE_INIT);
	if (error < 0) {
		perror("ioctl");
		exit(1);
	}


	bounce_handler(kq, &mi);

}
