#ifndef _VIRTIO_DBG_
#define _VIRTIO_DBG_

#include <sys/cdefs.h>
#include <sys/ioccom.h>

struct virtio_bounce_transfer {
	caddr_t		vtbt_device;
	caddr_t		vtbt_driver;
	size_t		vtbt_len;
};

struct virtio_bounce_io_args {
	struct virtio_bounce_transfer *transfers;
	size_t	cnt;	
	bool	touser;
};

#define VIRTIO_DBG_INIT	_IO('v', 1)
#define VIRTIO_DBG_KICK	_IO('v', 2)
#define VIRTIO_DBG_ACK	_IO('v', 3)
#define VIRTIO_DBG_TRANSFER	_IOWR('v', 4, struct virtio_bounce_io_args)


#endif /* _VIRTIO_DBG_ */
