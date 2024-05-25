/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2013  Chris Torek <torek @ torek net>
 * All rights reserved.
 * Copyright (c) 2019 Joyent, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <pthread_np.h>

#include <dev/virtio/dbg/virtio_dbg.h>

#include "debug.h"
#include "iov_emul.h"
#include "mmio_emul.h"
#include "virtio.h"

/*
 * Functions for dealing with generalized "virtual devices" as
 * defined by <https://www.google.com/#output=search&q=virtio+spec>
 */

/*
 * In case we decide to relax the "virtio softc comes at the
 * front of virtio-based device softc" constraint, let's use
 * this to convert.
 */
#define	DEV_SOFTC(vs) ((void *)(vs))

/*
 * Link a virtio_softc to its constants, the device softc, and
 * the PCI emulation.
 */
void
vi_softc_linkup(struct virtio_softc *vs, struct virtio_consts *vc,
		void *dev_softc, struct mmio_devinst *mdi,
		struct vqueue_info *queues)
{
	int i;

	/* vs and dev_softc addresses must match */
	assert((void *)vs == dev_softc);
	vs->vs_vc = vc;
	vs->vs_mi = mdi;

	vs->vs_queues = queues;
	for (i = 0; i < vc->vc_nvq; i++) {
		queues[i].vq_vs = vs;
		queues[i].vq_num = i;
	}
}

/*
 * Deliver an interrupt to the guest on the given virtual queue.
 *
 * XXX Instead of handling the interrupt from the userspace thread, have
 * a dedicated kernel thread for interrupting as noted in the transport.
 */

struct vq_interrupt_args {
	pthread_t thr;
	int fd;
};

static void *
vq_do_interrupt(void *arg)
{
	struct vq_interrupt_args *args = (struct vq_interrupt_args *)arg;
	int fd = args->fd;
	int error;

	error = ioctl(fd, VIRTIO_DBG_KICK);
	if (error != 0)
		EPRINTLN("device kick failed with %d\n", error);

	free(arg);

	pthread_exit(NULL);

}

static void
vq_interrupt(struct virtio_softc *vs)
{
	struct vq_interrupt_args *arg = malloc(sizeof(*arg));
	
	arg->fd = vs->vs_mi->mi_fd;

	mmio_set_cfgdata32(vs->vs_mi, VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_INT_VRING);
	pthread_create(&arg->thr, NULL, vq_do_interrupt, (void *)arg);
}

/*
 * Reset device (device-wide).  This erases all queues, i.e.,
 * all the queues become invalid (though we don't wipe out the
 * internal pointers, we just clear the VQ_ALLOC flag).
 *
 * It resets negotiated features to "none".
 */
void
vi_reset_dev(struct virtio_softc *vs)
{
	struct mmio_devinst *mdi = vs->vs_mi;
	struct vqueue_info *vq;
	int i, nvq;

	if (vs->vs_mtx)
		assert(pthread_mutex_isowned_np(vs->vs_mtx));

	nvq = vs->vs_vc->vc_nvq;
	for (vq = vs->vs_queues, i = 0; i < nvq; vq++, i++) {
		vq->vq_flags = 0;
		vq->vq_last_avail = 0;
		vq->vq_next_used = 0;
		vq->vq_save_used = 0;
		/* XXX Is this right? How should we actually set it? */
		vq->vq_offset = UINT_MAX;
	}
	vs->vs_negotiated_caps = 0;
	vs->vs_curq = 0;

	mdi->mi_state = MIDEV_INVALID;
	mmio_set_cfgdata32(mdi, VIRTIO_MMIO_INTERRUPT_STATUS, 0);
	mmio_set_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_READY, 0);

}

/*
 * Initialize the currently-selected virtio queue (vs->vs_curq).
 * The guest just gave us a page frame number, from which we can
 * calculate the addresses of the queue.
 */
/* XXX Switch it back to using the virtio softc. */
static void
vi_vq_init(struct mmio_devinst *mdi, struct vqueue_info *vq)
{
	uint64_t offset;

	offset = mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_DESC_HIGH);
	offset <<= 32;
	offset |= mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_DESC_LOW);
	vq->vq_desc = (struct vring_desc *)(mdi->mi_addr + offset);

	offset = mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_AVAIL_HIGH);
	offset <<= 32;
	offset |= mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_AVAIL_LOW);
	vq->vq_avail = (struct vring_avail *)(mdi->mi_addr + offset);

	offset = mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_USED_HIGH);
	offset <<= 32;
	offset |= mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_USED_LOW);
	vq->vq_used = (struct vring_used *)(mdi->mi_addr + offset);

	/* Mark queue as allocated, and start at 0 when we use it. */
	vq->vq_flags = VQ_ALLOC;
	vq->vq_last_avail = 0;
	vq->vq_next_used = 0;
	vq->vq_save_used = 0;
}


/*
 * Helper inline for vq_getchain(): record the i'th "real"
 * descriptor.
 */
static inline void
_vq_record(int i, struct vring_desc *vd, struct iovec *iov,
    int n_iov, struct vi_req *reqp, struct iov_emul *wiove,
    struct iov_emul *riove)
{
	if (i >= n_iov)
		return;

	/* XXX Handle OOM scenarios leading to iove_add failures. */

	/* Preallocate a descriptor data region for the descriptor */
	if ((vd->flags & VRING_DESC_F_WRITE) == 0) {
		if (iove_add(riove, vd->addr, vd->len, &iov[i]) != 0)
			return;

		reqp->readable++; 
	} else {
		if (iove_add(wiove, vd->addr, vd->len, &iov[i]) != 0)
			return;

		reqp->writable++;
	}
}
#define	VQ_MAX_DESCRIPTORS	512	/* see below */

static int
vq_import_indirect(struct vring_desc __unused **vdp)
{
	/* XXX Use the provided vd address to read in the indirect descriptor */
	printf("UNIMPLEMENTED %s\n", __func__);
	exit(1);
}

/*
 * Examine the chain of descriptors starting at the "next one" to
 * make sure that they describe a sensible request.  If so, return
 * the number of "real" descriptors that would be needed/used in
 * acting on this request.  This may be smaller than the number of
 * available descriptors, e.g., if there are two available but
 * they are two separate requests, this just returns 1.  Or, it
 * may be larger: if there are indirect descriptors involved,
 * there may only be one descriptor available but it may be an
 * indirect pointing to eight more.  We return 8 in this case,
 * i.e., we do not count the indirect descriptors, only the "real"
 * ones.
 *
 * Basically, this vets the "flags" and "next" field of each
 * descriptor and tells you how many are involved.  Since some may
 * be indirect, this also needs the vmctx (in the pci_devinst
 * at vs->vs_pi) so that it can find indirect descriptors.
 *
 * As we process each descriptor, we copy and adjust it (guest to
 * host address wise, also using the vmtctx) into the given iov[]
 * array (of the given size).  If the array overflows, we stop
 * placing values into the array but keep processing descriptors,
 * up to VQ_MAX_DESCRIPTORS, before giving up and returning -1.
 * So you, the caller, must not assume that iov[] is as big as the
 * return value (you can process the same thing twice to allocate
 * a larger iov array if needed, or supply a zero length to find
 * out how much space is needed).
 *
 * If some descriptor(s) are invalid, this prints a diagnostic message
 * and returns -1.  If no descriptors are ready now it simply returns 0.
 *
 * You are assumed to have done a vq_ring_ready() if needed (note
 * that vq_has_descs() does one).
 */
int
vq_getchain(struct vqueue_info *vq, struct iovec *iov, int niov,
	    struct vi_req *reqp)
{
	int i;
	u_int ndesc, n_indir;
	u_int idx, next;
	struct vi_req req;
	struct vring_desc *vdir, *vindir, *vp;
	struct virtio_softc *vs;
	const char *name;
	int error;
	struct iov_emul	*riove, *wiove;
	int fd;

	vs = vq->vq_vs;
	fd = vs->vs_mi->mi_fd;
	name = vs->vs_vc->vc_name;
	memset(&req, 0, sizeof(req));

	vindir = NULL;
	riove = iove_alloc();
	wiove = iove_alloc();
	if (riove == NULL || wiove == NULL) {
		iove_free(riove);
		iove_free(wiove);
		return (ENOMEM);
	}

	/*
	 * Note: it's the responsibility of the guest not to
	 * update vq->vq_avail->idx until all of the descriptors
         * the guest has written are valid (including all their
         * "next" fields and "flags").
	 *
	 * Compute (vq_avail->idx - last_avail) in integers mod 2**16.  This is
	 * the number of descriptors the device has made available
	 * since the last time we updated vq->vq_last_avail.
	 *
	 * We just need to do the subtraction as an unsigned int,
	 * then trim off excess bits.
	 */
	idx = vq->vq_last_avail;
	ndesc = (uint16_t)((u_int)vq->vq_avail->idx - idx);
	if (ndesc == 0)
		return (0);
	if (ndesc > vq->vq_qsize) {
		/* XXX need better way to diagnose issues */
		EPRINTLN(
		    "%s: ndesc (%u) out of range, driver confused?",
		    name, (u_int)ndesc);
		return (-1);
	}

	/*
	 * Now count/parse "involved" descriptors starting from
	 * the head of the chain.
	 *
	 * To prevent loops, we could be more complicated and
	 * check whether we're re-visiting a previously visited
	 * index, but we just abort if the count gets excessive.
	 */
	req.idx = next = vq->vq_avail->ring[idx & (vq->vq_qsize - 1)];
	req.iove = wiove;
	vq->vq_last_avail++;
	for (i = 0; i < VQ_MAX_DESCRIPTORS; next = vdir->next) {
		if (next >= vq->vq_qsize) {
			EPRINTLN(
			    "%s: descriptor index %u out of range, "
			    "driver confused?",
			    name, next);
			goto error;
		}
		vdir = &vq->vq_desc[next];
		if ((vdir->flags & VRING_DESC_F_INDIRECT) == 0) {
			_vq_record(i, vdir, iov, niov, &req, wiove, riove);
			i++;
		} else if ((vs->vs_vc->vc_hv_caps &
		    VIRTIO_RING_F_INDIRECT_DESC) == 0) {
			EPRINTLN(
			    "%s: descriptor has forbidden INDIRECT flag, "
			    "driver confused?",
			    name);
			goto error;
		} else {
			n_indir = vdir->len / 16;
			if ((vdir->len & 0xf) || n_indir == 0) {
				EPRINTLN(
				    "%s: invalid indir len 0x%x, "
				    "driver confused?",
				    name, (u_int)vdir->len);
				goto error;
			}

			error = vq_import_indirect(&vindir);
			if (error != 0)
				goto error;
			/*
			 * Indirects start at the 0th, then follow
			 * their own embedded "next"s until those run
			 * out.  Each one's indirect flag must be off
			 * (we don't really have to check, could just
			 * ignore errors...).
			 */
			next = 0;
			for (;;) {
				vp = &vindir[next];
				if (vp->flags & VRING_DESC_F_INDIRECT) {
					EPRINTLN(
					    "%s: indirect desc has INDIR flag,"
					    " driver confused?",
					    name);
					goto error;
				}
				_vq_record(i, vp, iov, niov, &req, wiove, riove);
				if (++i > VQ_MAX_DESCRIPTORS) {
					EPRINTLN(
					"%s: descriptor loop? count > %d - driver confused?",
					name, i);
					goto error;
				}
				if ((vp->flags & VRING_DESC_F_NEXT) == 0)
					break;
				next = vp->next;
				if (next >= n_indir) {
					EPRINTLN(
					    "%s: invalid next %u > %u, "
					    "driver confused?",
					    name, (u_int)next, n_indir);
					goto error;
				}
			}
		}
		if ((vdir->flags & VRING_DESC_F_NEXT) == 0)
			goto done;
	}

error:
	iove_free(riove);
	iove_free(wiove);
	free(vindir);

	return (-1);

done:
	/* Read in readable descriptors from the kernel. */
	error = iove_import(fd, riove);
	iove_free(riove);
	free(vindir);

	if (error != 0) {
		EPRINTLN("Reading in data failed with %d", error);
		return (-1);
	}

	*reqp = req;
	return (i);
}

/*
 * Return the first n_chain request chains back to the available queue.
 *
 * (These chains are the ones you handled when you called vq_getchain()
 * and used its positive return value.)
 */
void
vq_retchains(struct vqueue_info *vq, uint16_t n_chains)
{

	vq->vq_last_avail -= n_chains;
}

void
vq_relchain_prepare(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	struct vring_used *vuh;
	struct vring_used_elem *vue;
	uint16_t mask;

	/*
	 * Notes:
	 *  - mask is N-1 where N is a power of 2 so computes x % N
	 *  - vuh points to the "used" data shared with guest
	 *  - vue points to the "used" ring entry we want to update
	 */
	mask = vq->vq_qsize - 1;
	vuh = vq->vq_used;

	vue = &vuh->ring[vq->vq_next_used++ & mask];
	vue->id = idx;
	vue->len = iolen;
}

void
vq_relchain_publish(struct vqueue_info *vq)
{
	/*
	 * Ensure the used descriptor is visible before updating the index.
	 * This is necessary on ISAs with memory ordering less strict than x86
	 * (and even on x86 to act as a compiler barrier).
	 */
	atomic_thread_fence_rel();
	vq->vq_used->idx = vq->vq_next_used;
}

/*
 * Return specified request chain to the guest, setting its I/O length
 * to the provided value.
 *
 * (This chain is the one you handled when you called vq_getchain()
 * and used its positive return value.)
 */
void
vq_relchain(struct vqueue_info *vq, uint16_t idx, uint32_t iolen)
{
	vq_relchain_prepare(vq, idx, iolen);
	vq_relchain_publish(vq);
}

/*
 * Driver has finished processing "available" chains and calling
 * vq_relchain on each one.  If driver used all the available
 * chains, used_all should be set.
 *
 * If the "used" index moved we may need to inform the guest, i.e.,
 * deliver an interrupt.  Even if the used index did NOT move we
 * may need to deliver an interrupt, if the avail ring is empty and
 * we are supposed to interrupt on empty.
 *
 * Note that used_all_avail is provided by the caller because it's
 * a snapshot of the ring state when he decided to finish interrupt
 * processing -- it's possible that descriptors became available after
 * that point.  (It's also typically a constant 1/True as well.)
 */
void
vq_endchains(struct vqueue_info *vq, int used_all_avail)
{
	struct virtio_softc *vs;
	uint16_t event_idx, new_idx, old_idx;
	int intr;

	/*
	 * Interrupt generation: if we're using EVENT_IDX,
	 * interrupt if we've crossed the event threshold.
	 * Otherwise interrupt is generated if we added "used" entries,
	 * but suppressed by VRING_AVAIL_F_NO_INTERRUPT.
	 *
	 * In any case, though, if NOTIFY_ON_EMPTY is set and the
	 * entire avail was processed, we need to interrupt always.
	 */
	vs = vq->vq_vs;
	old_idx = vq->vq_save_used;
	vq->vq_save_used = new_idx = vq->vq_used->idx;

	/*
	 * Use full memory barrier between "idx" store from preceding
	 * vq_relchain() call and the loads from VQ_USED_EVENT_IDX() or
	 * "flags" field below.
	 */
	atomic_thread_fence_seq_cst();
	if (used_all_avail &&
	    (vs->vs_negotiated_caps & VIRTIO_F_NOTIFY_ON_EMPTY))
		intr = 1;
	else if (vs->vs_negotiated_caps & VIRTIO_RING_F_EVENT_IDX) {
		event_idx = VQ_USED_EVENT_IDX(vq);
		/*
		 * This calculation is per docs and the kernel
		 * (see src/sys/dev/virtio/virtio_ring.h).
		 */
		intr = (uint16_t)(new_idx - event_idx - 1) <
			(uint16_t)(new_idx - old_idx);
	} else {
		intr = new_idx != old_idx &&
		    !(vq->vq_avail->flags & VRING_AVAIL_F_NO_INTERRUPT);
	}
	if (intr)
		vq_interrupt(vs);
}

/* Note: these are in sorted order to make for a fast search */
static struct config_reg {
	uint16_t	cr_offset;	/* register offset */
	uint8_t		cr_ro;		/* true => reg is read only */
	const char	*cr_name;	/* name of reg */
} config_regs[] = {
	{ VIRTIO_MMIO_MAGIC_VALUE, 	  1,"MMIO_MAGIC_VALUE" },		
	{ VIRTIO_MMIO_VERSION,		  1, "VERSION" },		
	{ VIRTIO_MMIO_DEVICE_ID, 	  1, "DEVICE_ID" },		
	{ VIRTIO_MMIO_VENDOR_ID, 	  1, "VENDOR_ID" },		
	{ VIRTIO_MMIO_HOST_FEATURES, 	  1, "HOST_FEATURES" },		
	{ VIRTIO_MMIO_HOST_FEATURES_SEL,  0, "HOST_FEATURES_SEL" },		
	{ VIRTIO_MMIO_GUEST_FEATURES, 	  0, "GUEST_FEATURES" },		
	{ VIRTIO_MMIO_GUEST_FEATURES_SEL, 0, "GUEST_FEATURES_SEL" },  
	{ VIRTIO_MMIO_QUEUE_SEL, 	  0, "QUEUE_SEL" },		
	{ VIRTIO_MMIO_QUEUE_NUM_MAX, 	  1, "QUEUE_NUM_MAX" },		
	{ VIRTIO_MMIO_QUEUE_NUM, 	  0, "QUEUE_NUM" },		
	{ VIRTIO_MMIO_QUEUE_READY, 	  0, "QUEUE_READY" },
	{ VIRTIO_MMIO_QUEUE_NOTIFY, 	  0, "QUEUE_NOTIFY" },		
	{ VIRTIO_MMIO_INTERRUPT_STATUS,   1, "INTERRUPT_STATUS" },		
	{ VIRTIO_MMIO_INTERRUPT_ACK, 	  0, "INTERRUPT_ACK" },		
	{ VIRTIO_MMIO_STATUS,		  0, "STATUS" },		
	{ VIRTIO_MMIO_QUEUE_DESC_LOW, 	  0, "QUEUE_DESC_LOW" },		
	{ VIRTIO_MMIO_QUEUE_DESC_HIGH, 	  0, "QUEUE_DESC_HIGH" },		
	{ VIRTIO_MMIO_QUEUE_AVAIL_LOW, 	  0, "QUEUE_AVAIL_LOW" },		
	{ VIRTIO_MMIO_QUEUE_AVAIL_HIGH,   0, "QUEUE_AVAIL_HIGH" },		
	{ VIRTIO_MMIO_QUEUE_USED_LOW, 	  0, "QUEUE_USED_LOW" },		
	{ VIRTIO_MMIO_QUEUE_USED_HIGH, 	  0, "QUEUE_USED_HIGH" },		
	{ VIRTIO_MMIO_CONFIG_GENERATION,  1, "CONFIG_GENERATION" },		
};

static inline struct config_reg *
vi_find_cr(int offset) {
	u_int hi, lo, mid;
	struct config_reg *cr;

	lo = 0;
	hi = sizeof(config_regs) / sizeof(*config_regs) - 1;
	while (hi >= lo) {
		mid = (hi + lo) >> 1;
		cr = &config_regs[mid];
		if (cr->cr_offset == offset)
			return (cr);
		if (cr->cr_offset < offset)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return (NULL);
}

static void
vi_handle_state_change(struct mmio_devinst *mdi, uint32_t status)
{
	switch (mdi->mi_state) {
	case MIDEV_INVALID:
		if (status & VIRTIO_CONFIG_STATUS_ACK)
			mdi->mi_state = MIDEV_ACKNOWLEDGED;
		break;

	case MIDEV_ACKNOWLEDGED:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER)
			mdi->mi_state = MIDEV_DRIVER_FOUND;
		break;

	case MIDEV_DRIVER_FOUND:
		if (status & VIRTIO_CONFIG_S_FEATURES_OK)
			mdi->mi_state = MIDEV_FEATURES_OK;
		break;

	case MIDEV_FEATURES_OK:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			mdi->mi_state = MIDEV_LIVE;

		break;

	case MIDEV_LIVE:
		break;

	case MIDEV_FAILED:
		mdi->mi_state = MIDEV_FAILED;
		break;

	default:
		EPRINTLN("invalid device state %d", mdi->mi_state);
		exit(1);
	}
}

static void
vi_handle_status(struct virtio_softc *vs, uint32_t status)
{

	struct mmio_devinst *mdi = vs->vs_mi;

	if (status & VIRTIO_CONFIG_STATUS_FAILED) {
		mdi->mi_state = MIDEV_FAILED;
		return;
	}

	if (status & VIRTIO_CONFIG_STATUS_RESET) {
		mdi->mi_state = MIDEV_INVALID;
		vi_reset_dev(vs);
		return;
	}

	vi_handle_state_change(mdi, status);
}

static void
vi_handle_host_features_sel(struct virtio_softc *vs, uint32_t sel)
{
	uint64_t caps = vs->vs_vc->vc_hv_caps;
	struct mmio_devinst *mdi = vs->vs_mi;

	if (sel > 1) {
		EPRINTLN("HOST_FEATURES SEL 0x%x, "
			"driver confused?", sel);
		return;
	}
	
	if (sel == 1) {
		mmio_set_cfgdata32(mdi, VIRTIO_MMIO_HOST_FEATURES,
			(uint32_t)(caps >> 32));
	} else {
		mmio_set_cfgdata32(mdi, VIRTIO_MMIO_HOST_FEATURES,
			(uint32_t)caps);
	}
}

static void
vi_handle_guest_features(struct virtio_softc *vs, uint32_t features)
{
	struct mmio_devinst *mdi = vs->vs_mi;
	struct virtio_consts *vc = vs->vs_vc;
	uint64_t caps;
	int hi;

	/* 
	 * XXX Add asserts to ensure we are negotiating w/ the device
	 * and not in the middle of an operation.
	 */

	hi = mmio_get_cfgdata32(mdi, VIRTIO_MMIO_GUEST_FEATURES_SEL);
	if (hi > 1) {
		EPRINTLN("GUEST_FEATURES_SEL 0x%x, "
			"driver confused?", hi);
		return;
	}

	if (hi == 1) {
		/* Update the upper bits, keep the lower ones intact. */
		caps = (vc->vc_hv_caps | features) >> 32;
		vs->vs_negotiated_caps &= (vs->vs_negotiated_caps & (((1UL << 32) - 1)) << 32);
		vs->vs_negotiated_caps |= (caps << 32);
	} else {
		/* Update the lower bits, keep the upper ones intact. */
		caps = (uint32_t)(vc->vc_hv_caps | features);
		vs->vs_negotiated_caps &= (vs->vs_negotiated_caps & ((1UL << 32) - 1));
		vs->vs_negotiated_caps |= caps;

		/* The LSBs get sent second, we are ready to apply the features. */
		if (vc->vc_apply_features)
			(*vc->vc_apply_features)(DEV_SOFTC(vs),
				vs->vs_negotiated_caps);
	}

}


static void
vi_handle_queue_sel(struct virtio_softc *vs)
{
	struct mmio_devinst *mdi = vs->vs_mi;
	struct vqueue_info *vq;

	vs->vs_curq = mmio_get_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_SEL);

	if (vs->vs_curq < 0 || vs->vs_curq >= vs->vs_vc->vc_nvq) {
		EPRINTLN("Selected queue %d, driver confused?", vs->vs_curq);
		return;
	}

	vq = &vs->vs_queues[vs->vs_curq];
	if (vq_ring_ready(vq)) {
		mmio_set_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_READY, 1);
		return;
	}

	/* Part of virtqueue initialization. */
	mmio_set_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_NUM_MAX, vq->vq_qsize);
	mmio_set_cfgdata32(mdi, VIRTIO_MMIO_QUEUE_READY, 0);

	return;
}

static void
vi_handle_queue_num(struct virtio_softc *vs, int32_t qsize)
{
	struct vqueue_info *vq = &vs->vs_queues[vs->vs_curq];

	if (qsize > vq->vq_qsize || !powerof2(qsize)) {
		EPRINTLN("QUEUE_NUM %d is invalid, driver confused?", qsize);
		return;
	}

	vq->vq_qsize = qsize;
}

static void
vi_handle_queue_ready(struct virtio_softc *vs, uint32_t ready)
{
	struct vqueue_info *vq = &vs->vs_queues[vs->vs_curq];
	struct mmio_devinst *mdi = vs->vs_mi;

	if (ready > 1) {
		EPRINTLN("QUEUE_READY has value %d, driver confused?", ready);
		return;
	}

	if (ready == 1 && !vq_ring_ready(vq)) {
		vi_vq_init(mdi, vq);
		return;
	}
}

static void
vi_handle_interrupt_ack(struct virtio_softc *vs, uint32_t ack)
{
	struct mmio_devinst *mdi = vs->vs_mi;

	/* 
	 * Follow the protocol even if we are executing the 
	 * interrupt ourselves, so we are the ones that sent
	 * the ACK from the kernel in the first place.
	 */
	if (ack != 1) {
		EPRINTLN("INTERRUPT_ACK has value %d, "
			"driver confused?", ack);
		return;
	}

	mmio_set_cfgdata32(mdi, VIRTIO_MMIO_INTERRUPT_ACK, 0);
}

static void
vi_handle_queue_notify(struct virtio_softc *vs, uint32_t ind)
{
	struct virtio_consts *vc = vs->vs_vc;
	struct vqueue_info *vq;

	if (ind >= (unsigned int)vc->vc_nvq) {
		EPRINTLN("%s: queue %d notify out of range",
			vc->vc_name, ind);
	}

	vq = &vs->vs_queues[ind];
	if (vq->vq_notify) {
		(*vq->vq_notify)(DEV_SOFTC(vs), vq);
	} else if (vc->vc_qnotify) {
		(*vc->vc_qnotify)(DEV_SOFTC(vs), vq); 
	} else {
		EPRINTLN("%s: qnotify value %d: missing vq/vc notify",
			vc->vc_name, ind);
	}

}

void
vi_mmio_write(struct virtio_softc *vs, uint64_t offset)
{
	/* Reported writes are always 32-bit. */
	const int size = 4; 

	struct mmio_devinst *mdi = vs->vs_mi;
	struct virtio_consts *vc;
	struct config_reg *cr;
	const char *name;
	uint32_t newoff;
	int32_t value;
	uint64_t max;
	int error;

	if (vs->vs_mtx)
		pthread_mutex_lock(vs->vs_mtx);

	vc = vs->vs_vc;
	name = vc->vc_name;

	/* If writing in the config space, */
	if (offset >= VIRTIO_MMIO_CONFIG) {
		newoff = offset - VIRTIO_MMIO_CONFIG;
		max = vc->vc_cfgsize ? vc->vc_cfgsize : (mdi->mi_bytes - VIRTIO_MMIO_CONFIG);
		if (newoff + size > max)
			goto bad;

		value = mmio_get_cfgdata32(mdi, offset);

		if (vc->vc_cfgwrite != NULL)
			error = (*vc->vc_cfgwrite)(DEV_SOFTC(vs), newoff, size, value);
		else
			error = 0;
		if (!error)
			goto done;
	}

bad:
	cr = vi_find_cr(offset);
	if (cr == NULL)  {
		EPRINTLN("%s: write to bad offset %jd",
			name, (uintmax_t)offset);
		goto done;

	}

	if (cr->cr_ro) {
		EPRINTLN("%s: write to read-only reg %s",
			name, cr->cr_name);
		goto done;
	}

	value = mmio_get_cfgdata32(mdi, cr->cr_offset);

	switch (cr->cr_offset) {
	case VIRTIO_MMIO_STATUS:		    
		vi_handle_status(vs, value);
		break;

	case VIRTIO_MMIO_HOST_FEATURES_SEL:  		
		vi_handle_host_features_sel(vs, value);
		break;

	case VIRTIO_MMIO_GUEST_FEATURES: 	    	
		vi_handle_guest_features(vs, value);
		break;

	case VIRTIO_MMIO_QUEUE_SEL: 	    
		vi_handle_queue_sel(vs);
		break;

	case VIRTIO_MMIO_QUEUE_NUM:
		vi_handle_queue_num(vs, value);
		break;

	case VIRTIO_MMIO_QUEUE_READY:
		vi_handle_queue_ready(vs, value);
		break;

	case VIRTIO_MMIO_QUEUE_NOTIFY:
		vi_handle_queue_notify(vs, value);
		break;

	case VIRTIO_MMIO_INTERRUPT_ACK: 	    	
		vi_handle_interrupt_ack(vs, value);
		break;
	default:
		EPRINTLN("Unhandled offset %d\n", cr->cr_offset);
		assert(0);
	}

	goto done;

done:

	if (vs->vs_mtx)
		pthread_mutex_unlock(vs->vs_mtx);
}
