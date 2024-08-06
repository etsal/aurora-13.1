#ifndef _VIRTIO_FS_INTERNAL_
#define _VIRTIO_FS_INTERNAL_

/* Protocol-specified file system tag size. */
#define TAG_SIZE (36)
#define FSQ_NAME_SIZE (16)

#define VTFS_DEBUG(fmt, ...)		\
	do {			\
		printf("(%s:%d) " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); \
	} while (0)		

#define VTFS_ERR(fmt, ...)		\
	do {			\
		printf("[ERROR] (%s:%d) " fmt "\n", __func__, __LINE__, ##__VA_ARGS__); \
	} while (0)		

/* Struct for the file system instance. Provided by the host. */
struct vtfs_config {
	/* UTF-8 File system tag. */
	uint8_t tag[TAG_SIZE];
	/* Number of request queues. */
	uint32_t num_request_queues;
	/* Minimum # bytes for each buffer in the notification queue. */
	uint32_t notify_buf_size;
} __packed;

/* A queue structure belonging to a virtio fs device. */
struct vtfs_fsq {
	struct mtx		vtfsq_mtx;
	struct cv		vtfsq_cv;
	struct virtqueue	*vtfsq_vq;
	struct taskqueue	*vtfsq_tq;
	struct sglist 		*vtfsq_sg;
	char			vtfsq_name[FSQ_NAME_SIZE];
	struct vtfs_softc	*vtfsq_sc;
	vtfs_fuse_cb		vtfsq_cb;
};

/* A single virtio fs device instance. */
struct vtfs_softc {
	device_t	vtfs_dev;
	struct mtx	vtfs_mtx;
	struct vtfs_fsq	*vtfs_fsqs;
	bool		vtfs_inuse;	/* protected by the vtfs modulelock */
	/* Host-provided config state. */
	uint8_t 	vtfs_tag[TAG_SIZE + 1];
	uint32_t 	vtfs_nqs;
	LIST_ENTRY(vtfs_softc) vtfs_link;
};

#define VTFS_FORGET_FSQ (0)
#define VTFS_REGULAR_FSQ (1)

#define VTFS_MAXSEGS (16)
#define VTFS_TQTHREAD (4)

#endif /* _VIRTIO_FS_INTERNAL_ */
