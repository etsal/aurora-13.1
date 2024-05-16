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
