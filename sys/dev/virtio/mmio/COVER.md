Brief walkthrough of the kernel module. We change existing files minimally, and 
contain almost all new code in the new transport. For existing files we list the 
changes we made, while for new files we give a brief overview of the code.

 [EXISTING FILES]
 sys/dev/virtio/mmio/virtio_mmio.c
 	- Add the ring allocation callback argument to virtqueue_alloc().

 sys/dev/virtio/mmio/virtio_mmio.h
 	- Allow using the header from userspace to access the MMIO register offsets.
	- Add the virtqueue_alloc() ring allocation callback to the vtmmio_softc.

 sys/dev/virtio/pci/virtio_pci.c                
 	- Add the ring allocation callback argument to virtqueue_alloc().

 sys/dev/virtio/virtqueue.c                     
 	- If provided, use the callback for vring allocation in virtqueue_alloc().

 sys/dev/virtio/virtqueue.h                     
 	- Add the ring allocation callback argument to virtqueue_alloc()'s signature.

[NEW FILES]
 sys/dev/virtio/mmio/virtio_mmio_bounce_ioctl.h
 	The five ioctl() calls:
		- INIT: Create the requested virtio device and add it to the vtmmio bus.
		- FINI: <UNIMPLEMENTED> Detach and destroy the virtio device. We need to 
		  model this after regular detach calls.
		- KICK: Execute a device interrupt on behalf of the device. [MAYBE REMOVE]
		- ACK: Allows a bus write that is waiting on userspace handling to continue
		- TRANSFER: Do a vector IO between userspace and the kernel. Used during
		  device reads/writes of data pointed to by vq descriptors.

 sys/dev/virtio/mmio/virtio_mmio_bounce.c
 	The bus/device methods:
		- note(): Called during a write to a control register. Has two uses 
			- Rewrites on the fly any registers that hold the addresses of vrings.
			  These registers normally hold guest physical addresses to be interpreted
			  by the host VMM. We rewrite them to hold offsets into the shared kernel/user mapping 
			  that holds the virtqueue device regions (more on that on open(), below).
			- Notifies the userspace VMM of a write to specific registers. Writing to 
			  these registers happens during device initialization, virtqueue initialization,
			  or virtqueue use. For each case, we activate a knote and wait for userspace to handle 
			  the driver's write.

		- setup_intr(): Registers the interrupt handler with the device softc context. The handler and
		its argument are executed by the VMM as part of the KICK ioctl.

		- attach(): Set the device platform before attaching the device. Setting the platform makes
		  the generic mmio transport call our own setup_intr() during "interrupt" setup, and makes
		  all writes to config registers also call note(). We use note() to communicate with the
		  VMM in userspace, as explained above.

		- probe(): Turned off, we never dynamically find devices because we explicitly create them.

	The control device VFS methods:
		- open(): Create a new softc and attach it to the file descriptor. Also create the virtqueue
		  device region object that is mapped in both the kernel and userspace. Map the region into
		  the kernel.
		- ioctl(): Accesses one of the five calls described above.
		- mmap(): Return the virtqueue device region object.
		- close() (implicit): The close() call triggers the dtor() function for the softc created
		  during open(). The dtor() destroys the virtqueue device region

	The control device cdev methods:
		- create(): Creates the control device.
		- destroy(): Destroys the control device.


OPERATION
---------

1) The VMM calls open() to get a new fd from the control device. The fd is passed a new softc, representing an
emulated virtio device.

2) The VMM uses mmap() to access the virtqueue device region. It then sets up the device state in userspace.

3) The VMM uses the INIT ioctl() to initialize the device. The call triggers the attach process, creating a 
Newbus device and attaching it to the system. 

4) The transport and virtio layers of the driver start the device initialization process. This includes reading
and writing to device config registers. Writes to certain registers propagate during initialization activate
the device knote. The VMM receives the event and executes its part of the initialization protocol. It then 
notifies the driver using the ACK ioctl.

5) After device initialization, the kernel runs the device-specific driver. This driver include
Attaching this system will propagate upwards towards the virtio
device driver, eventually creating the emulated device and exposing it through /dev.

4) XXX Using the device

5) XXX Interrupts

	


