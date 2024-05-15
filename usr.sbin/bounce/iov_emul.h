#ifndef _IOV_EMUL_E
#define _IOV_EMUL_E

struct virtio_softc;

struct iov_emul {
	struct virtio_bounce_transfer *iove_tf;
	size_t 		iove_maxcnt;
	size_t 		iove_ind;
};

#define IOVE_INIT (16)

struct iov_emul *iove_alloc(void);
void iove_free(struct iov_emul *iove);
int iove_add(struct iov_emul *iove, uint64_t phys, size_t len, struct iovec *iov);
int iove_import(struct virtio_softc *vs, struct iov_emul *iove);
int iove_export(struct virtio_softc *vs, struct iov_emul *iove);

#endif /* _IOV_EMUL_E */
