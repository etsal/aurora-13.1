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

/**********************************************/
/*          BLOCK DEVICE EMULATION            */
/**********************************************/

#define	VTBLK_BSIZE	512
#define	VTBLK_RINGSZ	128

_Static_assert(VTBLK_RINGSZ <= BLOCKIF_RING_MAX, "Each ring entry must be able to queue a request");

#define	VTBLK_S_OK	0
#define	VTBLK_S_IOERR	1
#define	VTBLK_S_UNSUPP	2

#define	VTBLK_BLK_ID_BYTES	20 + 1

/* Capability bits */
#define	VTBLK_F_BARRIER		(1 << 0)	/* Does host support barriers? */
#define	VTBLK_F_SIZE_MAX	(1 << 1)	/* Indicates maximum segment size */
#define	VTBLK_F_SEG_MAX		(1 << 2)	/* Indicates maximum # of segments */
#define	VTBLK_F_GEOMETRY	(1 << 4)	/* Legacy geometry available  */
#define	VTBLK_F_RO		(1 << 5)	/* Disk is read-only */
#define	VTBLK_F_BLK_SIZE	(1 << 6)	/* Block size of disk is available*/
#define	VTBLK_F_SCSI		(1 << 7)	/* Supports scsi command passthru */
#define	VTBLK_F_FLUSH		(1 << 9)	/* Writeback mode enabled after reset */
#define	VTBLK_F_WCE		(1 << 9)	/* Legacy alias for FLUSH */
#define	VTBLK_F_TOPOLOGY	(1 << 10)	/* Topology information is available */
#define	VTBLK_F_CONFIG_WCE	(1 << 11)	/* Writeback mode available in config */
#define	VTBLK_F_MQ		(1 << 12)	/* Multi-Queue */
#define	VTBLK_F_DISCARD		(1 << 13)	/* Trim blocks */
#define	VTBLK_F_WRITE_ZEROES	(1 << 14)	/* Write zeros */

/*
 * Host capabilities
 */
#define	VTBLK_S_HOSTCAPS      \
  ( VTBLK_F_SEG_MAX  |						    \
    VTBLK_F_BLK_SIZE |						    \
    VTBLK_F_FLUSH    |						    \
    VTBLK_F_TOPOLOGY |						    \
    VIRTIO_RING_F_INDIRECT_DESC )	/* indirect descriptors */

/*
 * The current blockif_delete() interface only allows a single delete
 * request at a time.
 */
#define	VTBLK_MAX_DISCARD_SEG	1

/*
 * An arbitrary limit to prevent excessive latency due to large
 * delete requests.
 */
#define	VTBLK_MAX_DISCARD_SECT	((16 << 20) / VTBLK_BSIZE)	/* 16 MiB */

/*
 * Config space "registers"
 */
struct vtblk_config {
	uint64_t	vbc_capacity;
	uint32_t	vbc_size_max;
	uint32_t	vbc_seg_max;
	struct {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} vbc_geometry;
	uint32_t	vbc_blk_size;
	struct {
		uint8_t physical_block_exp;
		uint8_t alignment_offset;
		uint16_t min_io_size;
		uint32_t opt_io_size;
	} vbc_topology;
	uint8_t		vbc_writeback;
	uint8_t		unused0[1];
	uint16_t	num_queues;
	uint32_t	max_discard_sectors;
	uint32_t	max_discard_seg;
	uint32_t	discard_sector_alignment;
	uint32_t	max_write_zeroes_sectors;
	uint32_t	max_write_zeroes_seg;
	uint8_t		write_zeroes_may_unmap;
	uint8_t		unused1[3];
} __packed;

/*
 * Fixed-size block header
 */
struct virtio_blk_hdr {
#define	VBH_OP_READ		0
#define	VBH_OP_WRITE		1
#define	VBH_OP_SCSI_CMD		2
#define	VBH_OP_SCSI_CMD_OUT	3
#define	VBH_OP_FLUSH		4
#define	VBH_OP_FLUSH_OUT	5
#define	VBH_OP_IDENT		8
#define	VBH_OP_DISCARD		11
#define	VBH_OP_WRITE_ZEROES	13

#define	VBH_FLAG_BARRIER	0x80000000	/* OR'ed into vbh_type */
	uint32_t	vbh_type;
	uint32_t	vbh_ioprio;
	uint64_t	vbh_sector;
} __packed;


/*
 * Emulated device routines. Hardcode a block device for now.
 */
void
emul_set_device_type()
{
	write_config(mmio, VIRTIO_MMIO_DEVICE_ID, 0x2);
}

void
emul_set_feature_bits()
{
	write_config(mmio, VIRTIO_MMIO_HOST_FEATURES, VTBLK_S_HOSTCAPS);
}

/**********************************************/
/*                EMULATION END 	      */
/**********************************************/

/*
 * Steps: Emulation initialization
 * Question: How much of the device emulation layer depends on PCIe emulation?
 * Right now we need to modify pci_vtblk_init for sure. Parts of it are useful,
 * but parts of it depend on PCIe.
 *
 */

#define BOUNCEDEV ("/dev/virtio_bounce")

/* XXX We cannot currently decide how large the region is. */
#define MMIO_REGION_SIZE (1024 * 1024 * 10)

enum device_state {
	DEV_INVALID,
	DEV_ACKNOWLEDGED,
	DEV_DRIVER_FOUND,
	DEV_FEATURES_OK,
	DEV_LIVE,
	DEV_FAILED,
	DEV_DEVICE_STATES,
};

char *mmio;
int fd;
enum device_state state = DEV_INVALID;

/*
 * Turn the memory region into a virtio mmio device.
 */
void *
bounce_init(void *arg)
{
	int error;

	/* 
	 * XXX Make this code per-device. 
	 */
	write_config(mmio, VIRTIO_MMIO_MAGIC_VALUE, VIRTIO_MMIO_MAGIC_VIRT);
	write_config(mmio, VIRTIO_MMIO_VERSION, 0x2);

	/*
	 * Make sure this is corrrect.
	 */
	write_config(mmio, VIRTIO_MMIO_QUEUE_NUM_MAX, 1);
	write_config(mmio, VIRTIO_MMIO_QUEUE_NUM, 1);

	error = ioctl(fd, VIRTIO_BOUNCE_INIT);
	if (error < 0) {
		perror("ioctl");
		exit(1);
	}
}

void
state_invalid(uint64_t offset)
{
	int32_t status; 

	switch (offset) {
	case VIRTIO_MMIO_STATUS:
		status = read_config(mmio, VIRTIO_MMIO_STATUS);
		if (status & VIRTIO_CONFIG_STATUS_ACK)
			state = DEV_ACKNOWLEDGED;
		if (status & VIRTIO_CONFIG_STATUS_FAILED)
			state = DEV_DRIVER_FAILED;

		break;

	default:
		errx("Invalid offset %lx\n", offset);
	}

	/* If the kernel found a driver, set up feature bits. */
	if (state == DEV_ACKNOWLEDGED)

}

void
handle_status(uint32_t status)
{
	if (status & VIRTIO_CONFIG_STATUS_FAILED) {
		state = DEV_DRIVER_FAILED;
		return;
	}

	/* XXX Handle resets. */

	switch (state) {
	case DEV_INVALID:
		if (status & VIRTIO_CONFIG_STATUS_ACK) {
			state = DEV_ACKNOWLEDGED;
			emul_set_device_type();
		}
		break;

	case DEV_ACKNOWLEDGED:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER) {
			state = DEV_DRIVER_FOUND;
			emul_set_feature_bits();
		}

		break;

	case DEV_DRIVER_FOUND:
		if (status & VIRTIO_CONFIG_S_FEATURES_OK)
			state = FEATURES_OK;

		break;

	case DEV_FEATURES_OK:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			state = DEV_LIVE;

		break;

	case DEV_LIVE:
		break;

	case DEV_FAILED:
		state_failed(offset);
		break;

	default:
		errx("Invalid state %d", state);
		exit(1);
	}
}


void
handle_mmio(uint64_t offset)
{
	/* 
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


	switch (offset) {
	case VIRTIO_MMIO_STATUS:
		status = read_config(mmio, VIRTIO_MMIO_STATUS);
		handle_status(status);
		break;

	default:
		errx("Invalid offset %lx\n", offset);

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

		handle_mmio(kev.data);

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

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
	ret = kevent(kq, &kev, 1, NULL, 0, NULL);
	if (ret == -1) {
		perror("kevent");
		exit(1);
	}

	pthread_create(&init, NULL, bounce_init, 0);

	bounce_handler(kq);

}
