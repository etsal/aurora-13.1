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

/* XXX Fix this up when we integrate with the kernel build system. */
#include </usr/src/sys/dev/virtio/mmio/virtio.h>
#include </usr/src/sys/dev/virtio/mmio/virtio_mmio.h>
#include </usr/src/sys/dev/virtio/mmio/virtio_mmio_bounce_ioctl.h>

#define BOUNCEDEV ("/dev/virtio_bounce")

/* XXX We currently hardcode how large the region is. */
#define MMIO_REGION_SIZE (1024 * 1024 * 10)

void
handle_state_change(uint32_t status)
{
	switch (state) {
	case MIDEV_INVALID:
		if (status & VIRTIO_CONFIG_STATUS_ACK)
			state = MIDEV_ACKNOWLEDGED;
		break;

	case MIDEV_ACKNOWLEDGED:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER)
			state = MIDEV_DRIVER_FOUND;
		break;

	case MIDEV_DRIVER_FOUND:
		if (status & VIRTIO_CONFIG_S_FEATURES_OK)
			state = MIDEV_FEATURES_OK;
		break;

	case MIDEV_FEATURES_OK:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			state = MIDEV_LIVE;

		break;

	case MIDEV_LIVE:
		break;

	case MIDEV_FAILED:
		state = MIDEV_FAILED;
		break;

	default:
		errx("Invalid state %d", state);
		exit(1);
	}
}

void
handle_status(struct mmio_devemu *mi, uint32_t status)
{
	if (status & VIRTIO_CONFIG_STATUS_FAILED) {
		state = MIDEV_DRIVER_FAILED;
		return;
	}

	if (status & VIRTIO_CONFIG_STATUS_RESET) {
		/* XXX Call this properly. */
		vi_reset_dev();
		state = MIDEV_DRIVER_INVALID;
		return;
	}

	handle_state_change();
}

void
handle_mmio(struct mmio_devemu *mi, uint64_t offset)
{
	/* XXX Handle configuration space changes */

	switch (offset) {
	case VIRTIO_MMIO_STATUS:
		status = read_config(mi->mi_mmio, VIRTIO_MMIO_STATUS);
		handle_status(mi, status);
		break;

	default:
		errx("Invalid offset %lx\n", offset);

	}
}

void
bounce_handler(int kq, struct mmio_devemu *mi)
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

int main(int argc, char *argv[]) 
{
	struct kevent kev;
	pthread_t init;
	char *mmio;
	int kq, fd;
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
	struct mmio_devemu mi;
	dev.mi_d = &mmio_de_vblk;
	strncpy(dev.mi_name, "vtbd-emu", sizeof("vtlblk-emu"));
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
