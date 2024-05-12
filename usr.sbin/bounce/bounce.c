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
#include </usr/src/sys/dev/virtio/mmio/virtio_mmio_bounce_ioctl.h>

#define BOUNCEDEV ("/dev/virtio_bounce")

/*
 * XXX Find a way to share this between both kernel and userspace.
 */
#define	VIRTIO_MMIO_MAGIC_VALUE		0x000
#define	VIRTIO_MMIO_VERSION		0x004
#define	VIRTIO_MMIO_DEVICE_ID		0x008
#define	VIRTIO_MMIO_VENDOR_ID		0x00c
#define	VIRTIO_MMIO_HOST_FEATURES	0x010
#define	VIRTIO_MMIO_HOST_FEATURES_SEL	0x014
#define	VIRTIO_MMIO_GUEST_FEATURES	0x020
#define	VIRTIO_MMIO_GUEST_FEATURES_SEL	0x024
#define	VIRTIO_MMIO_GUEST_PAGE_SIZE	0x028	/* version 1 only */
#define	VIRTIO_MMIO_QUEUE_SEL		0x030
#define	VIRTIO_MMIO_QUEUE_NUM_MAX	0x034
#define	VIRTIO_MMIO_QUEUE_NUM		0x038
#define	VIRTIO_MMIO_QUEUE_ALIGN		0x03c	/* version 1 only */
#define	VIRTIO_MMIO_QUEUE_PFN		0x040	/* version 1 only */
#define	VIRTIO_MMIO_QUEUE_READY		0x044	/* requires version 2 */
#define	VIRTIO_MMIO_QUEUE_NOTIFY	0x050
#define	VIRTIO_MMIO_INTERRUPT_STATUS	0x060
#define	VIRTIO_MMIO_INTERRUPT_ACK	0x064
#define	VIRTIO_MMIO_STATUS		0x070
#define	VIRTIO_MMIO_QUEUE_DESC_LOW	0x080	/* requires version 2 */
#define	VIRTIO_MMIO_QUEUE_DESC_HIGH	0x084	/* requires version 2 */
#define	VIRTIO_MMIO_QUEUE_AVAIL_LOW	0x090	/* requires version 2 */
#define	VIRTIO_MMIO_QUEUE_AVAIL_HIGH	0x094	/* requires version 2 */
#define	VIRTIO_MMIO_QUEUE_USED_LOW	0x0a0	/* requires version 2 */
#define	VIRTIO_MMIO_QUEUE_USED_HIGH	0x0a4	/* requires version 2 */
#define	VIRTIO_MMIO_CONFIG_GENERATION	0x0fc	/* requires version 2 */
#define	VIRTIO_MMIO_CONFIG		0x100
#define	VIRTIO_MMIO_MAGIC_VIRT		0x74726976
#define	VIRTIO_MMIO_INT_VRING		(1 << 0)
#define	VIRTIO_MMIO_INT_CONFIG		(1 << 1)
#define	VIRTIO_MMIO_VRING_ALIGN		4096

/* XXX We cannot currently decide how large the region is. */
#define MMIO_REGION_SIZE (1024 * 1024 * 10)

char *mmio;
int fd;

static inline uint32_t 
read_config(char *mmio, size_t offset)
{
	return le32toh(*(uint32_t *)(mmio + offset));
}

static inline void
write_config(char *mmio, size_t offset, uint32_t value)
{
	*(uint32_t *)(mmio + offset) = htole32(value);
}

/*
 * Turn the memory region into a virtio mmio device.
 */
void *
bounce_init(void *arg)
{
	int error;

	write_config(mmio, VIRTIO_MMIO_MAGIC_VALUE, VIRTIO_MMIO_MAGIC_VIRT);
	write_config(mmio, VIRTIO_MMIO_VERSION, 0x2);
	/* Do a block device right now. */
	write_config(mmio, VIRTIO_MMIO_DEVICE_ID, 0x2);
	/* XXX Determine what features we support. */
	write_config(mmio, VIRTIO_MMIO_HOST_FEATURES, 0);
	write_config(mmio, VIRTIO_MMIO_QUEUE_NUM_MAX, 1);
	write_config(mmio, VIRTIO_MMIO_QUEUE_NUM, 1);

	exit(0);
	/* XXX Determine what else we need to set. */

	error = ioctl(fd, VIRTIO_BOUNCE_INIT);
	if (error < 0)
		perror("ioctl");
	
	pthread_exit(NULL);
}

void
handle_mmio_virtio(size_t offset)
{
	/* 
	 * XXX Check which control register got triggered. 
	 * Depending on the register, follow the virtio protocol.
	 *
	 * XXX At this point we should be getting very inspired
	 * by bhyve's PCIe drivers.
	 *
	 * TODOs: Port a virtio interface on top of this. The transport-
	 * level events we handle here correspond to virtqueue operations.
	 *
	 * TODOs: Similarly, port the bhyve drivers on top of the virtio
	 * transport. At this point it should be easy because they are 
	 * transport-agnostic.
	 */
	for(;;) {
		sleep(1);
	}
}

void
bounce_handler(int kq)
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

		handle_mmio_virtio(kev.data);

		/* Let in-progress operations continue.  */
		ioctl(fd, VIRTIO_BOUNCE_ACK);
	}

	pthread_exit(NULL);
}

int main() 
{
	struct kevent kev;
	pthread_t init;
	int ret;
	int kq;

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

	exit(1);

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ret = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (ret == -1) {
		perror("kevent");
		exit(1);
	}

	pthread_create(&init, NULL, bounce_init, 0);

	bounce_handler(kq);

	close(fd);
}
