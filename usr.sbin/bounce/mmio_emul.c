#include <sys/param.h>
#include <sys/mman.h>
#include <sys/nv.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dev/virtio/mmio/virtio_mmio_bounce_ioctl.h>

#include "config.h"
#include "debug.h"
#include "mmio_emul.h"

SET_DECLARE(mmio_devemu_set, struct mmio_devemu);

static struct mmio_devemu *
mmio_emul_finddev(const char *name)
{
	struct mmio_devemu **mdpp, *mdp;

	SET_FOREACH(mdpp, mmio_devemu_set) {
		mdp = *mdpp;
		if (!strcmp(mdp->me_emu, name)) {
			return (mdp);
		}
	}

	return (NULL);
}

static int
mmio_emul_control_init(struct mmio_devinst *mdi)
{
	char *mmio;
	int error;
	int fd;

	fd = open(MMIO_CTRDEV, O_RDWR);
	if (fd == -1) {
		EPRINTLN("Control device open error: %s",
		    strerror(errno));
		return (-1);
	}

	mmio = mmap(NULL, MMIO_TOTAL_SIZE, PROT_READ | PROT_WRITE,
			MAP_FILE | MAP_SHARED, fd, 0);
	if (mmio == MAP_FAILED) {
		EPRINTLN("Control device mapping error: %s",
		    strerror(errno));
		close(fd);
		return (-1);
	}

	error = ioctl(fd, VIRTIO_BOUNCE_INIT);
	if (error < 0) {
		EPRINTLN("Control device initialization error: %s",
		    strerror(errno));
		munmap(mmio, MMIO_TOTAL_SIZE);
		close(fd);
		return (-1);
	}

	mdi->mi_fd = fd;
	mdi->mi_addr = mmio;
	mdi->mi_bytes = MMIO_TOTAL_SIZE;
	return (0);
}

static int
mmio_emul_init(struct mmio_devemu *mde, nvlist_t *nvl)
{
	struct mmio_devinst *mdi;
	int err;

	mdi = calloc(1, sizeof(struct mmio_devinst));
	if (mdi == NULL)
		return (ENOMEM);

	snprintf(mdi->mi_name, sizeof(mdi->mi_name), "%s@mmio", mde->me_emu);
	mdi->mi_state = MIDEV_INVALID;
	mdi->mi_fd = -1;

	err = mmio_emul_control_init(mdi);
	if (err != 0) {
		free(mdi);
		return (err);
	}

	err = (*mde->me_init)(mdi, nvl);
	if (err != 0) {
		free(mdi);
		return (err);
	}

	return (0);
}

int
mmio_parse_device(nvlist_t *nvl, char *opt)
{
	struct mmio_devemu *mde;
	char *emul = opt;

	mde = mmio_emul_finddev(emul);
	if (mde == NULL) {
		EPRINTLN("unknown mmio device %s\n", emul);
		return (EINVAL);
	}

	if (get_config_value_node(nvl, "devtype") != NULL) {
		EPRINTLN("device type already defined!");
		return (EINVAL);
	}

	set_config_value_node(nvl, "devtype", mde->me_emu);

	return (0);
}


void
mmio_print_supported_devices(void)
{
	struct mmio_devemu **mdpp, *mdp;

	SET_FOREACH(mdpp, mmio_devemu_set) {
		mdp = *mdpp;
		printf("%s\n", mdp->me_emu);
	}
}

int
init_mmio(nvlist_t *nvl)
{
	struct mmio_devemu *mde;
	const char *emul;

	emul = get_config_value_node(nvl, "devtype");
	if (emul == NULL) {
		EPRINTLN("mmio device missing devtype value");
		return (EINVAL);
	}

	mde = mmio_emul_finddev(emul);
	if (mde == NULL) {
		EPRINTLN("mmio unknown device \"%s\"", emul);
		return (EINVAL);
	}

	return (mmio_emul_init(mde, nvl));
}
