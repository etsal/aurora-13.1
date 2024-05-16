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

	mmio = mmap(NULL, MMIO_VQ_SIZE, PROT_READ | PROT_WRITE,
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
		munmap(mmio, MMIO_VQ_SIZE);
		close(fd);
		return (-1);
	}

	mdi->mi_fd = fd;
	mdi->mi_addr = mmio;
	mdi->mi_bytes = MMIO_VQ_SIZE;
	return (0);
}

static void
mmio_emul_control_fini(struct mmio_devinst *mdi)
{
	munmap(mdi->mi_addr, mdi->mi_bytes);

	if (ioctl(mdi->mi_fd, VIRTIO_BOUNCE_FINI) == -1) {
		EPRINTLN("Control device teardown error: %s",
		    strerror(errno));
	}
	close(mdi->mi_fd);
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
		mmio_emul_control_fini(mdi);
		free(mdi);
		return (err);
	}

	return (0);
}

int
mmio_parse_device(char *opt)
{
	char node_name[sizeof("mmio")];
	struct mmio_devemu *mde;
	char *emul, *config, *str, *cp;
	nvlist_t *nvl;
	int error;

	error = -1;
	str = strdup(opt);

	emul = str;
	config = NULL;
	if ((cp = strchr(str, ',')) == NULL)
		return (EINVAL);

	*cp = '\0';
	config = cp + 1;

	mde = mmio_emul_finddev(emul);
	if (mde == NULL) {
		EPRINTLN("unknown mmio device %s:%s\n", emul, config);
		goto done;
	}

	nvl = find_config_node(node_name);
	if (nvl != NULL) {
		EPRINTLN("mmio slot %s already occupied!", node_name);
		goto done;
	}

	nvl = create_config_node(node_name);
	set_config_value_node(nvl, "device", mde->me_emu);

done:
	free(str);
	return (error);
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
init_mmio(void)
{
	char node_name[sizeof("mmio")];
	struct mmio_devemu *mde;
	nvlist_t *nvl;
	const char *emul;

	nvl = find_config_node(node_name);
	if (nvl == NULL) {
		/* XXX error handling */
		assert(0);
	}

	snprintf(node_name, sizeof(node_name), "mmio");
	nvl = find_config_node(node_name);
	if (nvl == NULL) {
		EPRINTLN("mmio namespace not found");
		return (EINVAL);
	}

	emul = get_config_value_node(nvl, "device");
	if (emul == NULL) {
		EPRINTLN("mmio device missing device value");
		return (EINVAL);
	}

	mde = mmio_emul_finddev(emul);
	if (mde == NULL) {
		EPRINTLN("mmio unknown device \"%s\"", emul);
		return (EINVAL);
	}

	return (mmio_emul_init(mde, nvl));
}
