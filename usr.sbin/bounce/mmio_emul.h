/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _MMIO_EMUL_H_
#define _MMIO_EMUL_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/nv.h>
#include <sys/_pthreadtypes.h>

#include <assert.h>

enum mmio_devstate {
	MIDEV_INVALID,
	MIDEV_ACKNOWLEDGED,
	MIDEV_DRIVER_FOUND,
	MIDEV_FEATURES_OK,
	MIDEV_LIVE,
	MIDEV_FAILED,
	MIDEV_DEVICE_STATES,
};

struct mmio_devinst {
	struct mmio_devemu 	*mi_d;
	char	  		mi_name[FILENAME_MAX];	/* XXX Change to be device type - independent */
	char 	  		*mi_mmio;	/* Memory mapped region */
	size_t	  		mi_size;	/* Size of region in bytes */
	int			mi_fd;		/* File descriptor for the region. */
	enum mmio_devstate	mi_state;	

	void      *mi_arg;		/* devemu-private data */
};

struct mmio_devemu {
	const char      *me_emu;	/* Name of device emulation */

	/* instance creation */
	int       (*me_init)(struct mmio_devinst *, nvlist_t *);
	const char *me_alias;

	/* mmio space read/write callbacks */
	int	(*me_cfgwrite)(struct mmio_devinst *mi, int offset,
			       int bytes, uint32_t val);
	int	(*me_cfgread)(struct mmio_devinst *mi, int offset,
			      int bytes, uint32_t *retval);

	void      (*me_write)(struct mmio_devinst *mi, uint64_t offset,
				int size, uint32_t value);
	uint64_t  (*me_read)(struct mmio_devinst *mi, uint64_t offset,
				int size);

};
#define MMIO_EMUL_SET(x)   DATA_SET(mmio_devemu_set, x)

static __inline void
mmio_set_cfgdata8(struct mmio_devinst *mi, int offset, uint8_t val)
{
	*(uint8_t *)(mi->mi_mmio + offset) = val;
}

static __inline void
mmio_set_cfgdata16(struct mmio_devinst *mi, int offset, uint16_t val)
{
	*(uint16_t *)(mi->mi_mmio + offset) = htole16(val);
}

static __inline void
mmio_set_cfgdata32(struct mmio_devinst *mi, int offset, uint32_t val)
{
	*(uint32_t *)(mi->mi_mmio + offset) = htole32(val);
}

static __inline uint8_t
mmio_get_cfgdata8(struct mmio_devinst *mi, int offset)
{
	return (*(uint8_t *)(mi->mi_mmio + offset));
}

static __inline uint16_t
mmio_get_cfgdata16(struct mmio_devinst *mi, int offset)
{
	return le16toh((*(uint16_t *)(mi->mi_mmio + offset)));
}

static __inline uint32_t
mmio_get_cfgdata32(struct mmio_devinst *mi, int offset)
{
	return le32toh((*(uint32_t *)(mi->mi_mmio + offset)));
}

#endif /* _MMIO_EMUL_H_ */
