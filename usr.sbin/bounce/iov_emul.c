#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include </usr/src/sys/dev/virtio/mmio/virtio_mmio_bounce_ioctl.h>

#include "iov_emul.h"
#include "mmio_emul.h"
#include "virtio.h"

struct iov_emul *
iove_alloc(void)
{
	struct iov_emul *iove;

	iove = calloc(IOVE_INIT, sizeof(*iove));
	iove->iove_maxcnt = IOVE_INIT;

	return (iove);
}

void
iove_free(struct iov_emul *iove)
{
	int i;

	for (i = 0; i < iove->iove_ind; i++)
		free(iove->iove_iov[i].iov_base);

	free(iove);
}


int
iove_add(struct iov_emul *iove, size_t len, struct iovec *iovp)
{
	struct iovec *iov = iove->iove_iov;
	char *base;

	if (iove->iove_ind == iove->iove_maxcnt){
		iov = reallocarray(iov, 2 * iove->iove_maxcnt,
				sizeof(*iov));
		if (iov == NULL)
			return (ENOMEM);
		iove->iove_iov = iov;
		iove->iove_maxcnt *= 2;
	}

	base = malloc(len);
	if (base == NULL)
		return (ENOMEM);

	iov[iove->iove_ind].iov_base = base;
	iov[iove->iove_ind].iov_len = len;

	*iovp = iov[iove->iove_ind];

	iove->iove_ind += 1;

	return (0);
}


/*
 * Import a read IO vector from the kernel.
 */
int
iove_import(struct virtio_softc *vs, struct iov_emul *iove)
{
	int fd = vs->vs_mi->mi_fd;
	struct virtio_bounce_io_args args = {
		.iov = iove->iove_iov,
		.cnt = iove->iove_ind,
		.touser = true,
	};

	return (ioctl(fd, VIRTIO_BOUNCE_IO, &args));
}

/*
 * Export a write IO vector to the kernel.
 */
int
iove_export(struct virtio_softc *vs, struct iov_emul *iove)
{
	int fd = vs->vs_mi->mi_fd;
	struct virtio_bounce_io_args args = {
		.iov = iove->iove_iov,
		.cnt = iove->iove_ind,
		.touser = true,
	};

	return (ioctl(fd, VIRTIO_BOUNCE_IO, &args));
}

