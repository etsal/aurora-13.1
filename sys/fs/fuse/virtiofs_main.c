/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/buf.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>

#include "fuse.h"
#include "fuse_file.h"
#include "fuse_ipc.h"
#include "fuse_internal.h"
#include "fuse_node.h"

extern struct vfsops virtiofs_vfsops;
extern struct cdevsw virtiofs_cdevsw;

static struct vfsconf virtiofs_vfsconf = {
	.vfc_version = VFS_VERSION,
	.vfc_name = "virtiofs",
	.vfc_vfsops = &virtiofs_vfsops,
	.vfc_typenum = -1,
	.vfc_flags = VFCF_JAIL | VFCF_SYNTHETIC
};

static int
virtiofs_loader(struct module *m, int what, void *arg)
{
	int error = 0;

	switch (what) {
	case MOD_LOAD:			
		error = vfs_modevent(NULL, what, &virtiofs_vfsconf);
		break;
	case MOD_UNLOAD:
		error = vfs_modevent(NULL, what, &virtiofs_vfsconf);
		break;
	default:
		return (EINVAL);
	}

	return (error);
}

/* Registering the module */

static moduledata_t virtiofs_moddata = {
	"virtiofs",
	virtiofs_loader,
	&virtiofs_vfsconf
};

DECLARE_MODULE(virtiofs, virtiofs_moddata, SI_SUB_VFS, SI_ORDER_MIDDLE);
MODULE_DEPEND(virtiofs, fusefs, 1, 1, 1);
MODULE_DEPEND(virtiofs, vtfs, 1, 1, 1);
MODULE_VERSION(virtiofs, 1);
