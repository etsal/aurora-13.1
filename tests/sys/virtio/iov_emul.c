#include <sys/param.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include <dev/virtio/dbg/virtio_dbg.h>

#include "debug.h"
#include "iov_emul.h"
#include "mmio_emul.h"
#include "virtio.h"

struct iov_emul *
iove_alloc(void)
{
	struct iov_emul *iove;

	iove = calloc(1, sizeof(*iove));

	iove->iove_tf = calloc(IOVE_INIT, sizeof(*iove->iove_tf));
	if (iove->iove_tf == NULL) {
		free(iove);
		return (NULL);
	}

	iove->iove_maxcnt = IOVE_INIT;

	return (iove);
}

void
iove_free(struct iov_emul *iove)
{
	size_t i;

	for (i = 0; i < iove->iove_ind; i++)
		free(iove->iove_tf[i].vtdt_device);

	free(iove);
}


int
iove_add(struct iov_emul *iove, uint64_t phys, size_t len, struct iovec *iov)
{
	struct vtdbg_transfer *tf = iove->iove_tf;
	size_t ind = iove->iove_ind;
	char *base;

	if (ind == iove->iove_maxcnt){
		tf = reallocarray(tf, 2 * iove->iove_maxcnt,
				sizeof(*tf));
		if (tf == NULL)
			return (ENOMEM);
		iove->iove_tf = tf;
		iove->iove_maxcnt *= 2;
	}

	base = malloc(len);
	if (base == NULL)
		return (ENOMEM);

	iove->iove_tf[ind].vtdt_device = base;
	iove->iove_tf[ind].vtdt_driver = (caddr_t) phys;
	iove->iove_tf[ind].vtdt_len = len;
	iove->iove_ind += 1;

	iov->iov_base = base;
	iov->iov_len = len;

	return (0);
}


/*
 * Import a read IO vector from the kernel.
 */
int
iove_import(int fd, struct iov_emul *iove)
{
	struct vtdbg_io_args args = {
		.transfers = iove->iove_tf,
		.cnt = iove->iove_ind,
		.touser = true,
	};

	return (ioctl(fd, VIRTIO_DBG_TRANSFER, &args));
}

/*
 * Export a write IO vector to the kernel.
 */
int
iove_export(int fd, struct iov_emul *iove)
{
	struct vtdbg_io_args args = {
		.transfers = iove->iove_tf,
		.cnt = iove->iove_ind,
		.touser = false,
	};

	return (ioctl(fd, VIRTIO_DBG_TRANSFER, &args));
}

