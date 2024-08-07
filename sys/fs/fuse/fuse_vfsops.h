#ifndef _FUSE_VFSOPS_H_
#define _FUSE_VFSOPS_H_

vfs_fhtovp_t fuse_vfsop_fhtovp;
vfs_mount_t fuse_vfsop_mount;
vfs_unmount_t fuse_vfsop_unmount;
vfs_root_t fuse_vfsop_root;
vfs_statfs_t fuse_vfsop_statfs;
vfs_vget_t fuse_vfsop_vget;

void virtiofs_teardown(void *arg);

#endif /* _FUSE_VFSOPS_H_ */
