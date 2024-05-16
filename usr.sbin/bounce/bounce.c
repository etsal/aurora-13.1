#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "config.h"
#include "debug.h"
#include "mevent.h"
#include "mmio_emul.h"


#if 0
/*==========================================================*/
/* XXX Move to virtio.c */
static void
handle_state_change(struct mmio_devinst *mi, uint32_t status)
{
	switch (mi->mi_state) {
	case MIDEV_INVALID:
		if (status & VIRTIO_CONFIG_STATUS_ACK)
			mi->mi_state = MIDEV_ACKNOWLEDGED;
		break;

	case MIDEV_ACKNOWLEDGED:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER)
			mi->mi_state = MIDEV_DRIVER_FOUND;
		break;

	case MIDEV_DRIVER_FOUND:
		if (status & VIRTIO_CONFIG_S_FEATURES_OK)
			mi->mi_state = MIDEV_FEATURES_OK;
		break;

	case MIDEV_FEATURES_OK:
		if (status & VIRTIO_CONFIG_STATUS_DRIVER_OK)
			mi->mi_state = MIDEV_LIVE;

		break;

	case MIDEV_LIVE:
		break;

	case MIDEV_FAILED:
		mi->mi_state = MIDEV_FAILED;
		break;

	default:
		errx(EXIT_FAILURE, "Invalid state %d", mi->mi_state);
		exit(1);
	}
}

static void
handle_status(struct mmio_devinst *mi, uint32_t status)
{
	if (status & VIRTIO_CONFIG_STATUS_FAILED) {
		mi->mi_state = MIDEV_FAILED;
		return;
	}

	if (status & VIRTIO_CONFIG_STATUS_RESET) {
		/* XXX Call a device reset. */
		//vi_reset_dev();
		mi->mi_state = MIDEV_INVALID;
		return;
	}

	handle_state_change(mi, status);
}

/* XXX Use vi_mmio_write as a main loop instead. */
static void
handle_mmio(struct mmio_devinst *mi, uint64_t offset)
{
	uint32_t status;
	/* XXX Handle configuration space changes */

	switch (offset) {
	case VIRTIO_MMIO_STATUS:
		status = 0;
		handle_status(mi, status);
		break;

	default:
		errx(EXIT_FAILURE, "Invalid offset %lx\n", offset);

	}
}
/*==========================================================*/
#endif

static void
bounce_usage(int code)
{
	const char *progname;

	progname = getprogname();

	fprintf(stderr,
	    "Usage: %s [-hot]\n"
	    "       -h: help\n"
	    "       -o: set config 'var' to 'value'\n"
	    "       -t: MMIO device type\n",
	    progname);
	exit(code);
}

static bool
bounce_parse_config_option(const char *option)
{
	const char *value;
	char *path;

	value = strchr(option, '=');
	if (value == NULL || value[1] == '\0')
		return (false);
	path = strndup(option, value - option);
	if (path == NULL)
		err(4, "Failed to allocate memory");
	set_config_value(path, value + 1);
	return (true);
}


static void
bounce_optparse(int argc, char **argv)
{
	const char *optstr;
	int c;

	optstr = "ho:t:";
	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 't':
			if (strncmp(optarg, "help", strlen(optarg)) == 0) {
				mmio_print_supported_devices();
				exit(0);
			} else if (mmio_parse_device(optarg) != 0)
				exit(4);
			else
				break;
		case 'o':
			if (!bounce_parse_config_option(optarg)) {
				errx(EX_USAGE,
				    "invalid configuration option '%s'",
				    optarg);
			}
			break;
		case 'h':
			bounce_usage(0);
		default:
			bounce_usage(1);
		}
	}
}

int
main(int argc, char *argv[])
{
	init_config();
	bounce_optparse(argc, argv);

	/* Exit if a device emulation finds an error in its initialization */
	if (init_mmio() != 0) {
		EPRINTLN("Device emulation initialization error: %s",
		    strerror(errno));
		exit(4);
	}
	
	/* Head off to the main event dispatch loop. */
	mevent_dispatch();

	exit(4);
}
