#ifndef _VIRTIO_MMIO_BOUNCE_IOCTL_
#define _VIRTIO_MMIO_BOUNCE_IOCTL_

#include <sys/cdefs.h>
#include <sys/ioccom.h>

#define VIRTIO_BOUNCE_INIT	_IO('v', 1)
#define VIRTIO_BOUNCE_FINI	_IO('v', 2)
#define VIRTIO_BOUNCE_KICK	_IO('v', 3)
#define VIRTIO_BOUNCE_ACK	_IO('v', 4)
#define VIRTIO_BOUNCE_TRANSFER	_IORW('v', 5)

struct virtio_bounce_transfer {
	caddr_t		vtbt_device;
	caddr_t		vtbt_driver;
	size_t		len;
};

struct virtio_bounce_io_args {
	struct virtio_bounce_transfer *transfers;
	size_t	cnt;	
	bool	touser;
};

#endif /* _VIRTIO_MMIO_BOUNCE_IOCTL_ */
