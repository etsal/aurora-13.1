/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2005 Jean-Sebastien Pedron
 * Copyright (c) 2005 Csaba Henk 
 * All rights reserved.
 *
 * Copyright (c) 2019 The FreeBSD Foundation
 *
 * Portions of this software were developed by BFF Storage Systems under
 * sponsorship from the FreeBSD Foundation.
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
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <paths.h>

#include "mntopts.h"

void	__usage_short(void);
void	usage(void);
void	helpmsg(void);

static struct mntopt mopts[] = {
	{ "neglect_shares",      0, 0x02, 1 },
	{ "push_symlinks_in",    0, 0x04, 1 },
	{ "allow_other",         0, 0x08, 1 },
	{ "default_permissions", 0, 0x10, 1 },
	#define ALTF_MAXREAD 0x20
	{ "max_read=",           0, ALTF_MAXREAD, 1 },
	#define ALTF_SUBTYPE 0x40
	{ "subtype=",            0, ALTF_SUBTYPE, 1 },
	#define ALTF_FSTAG 0x80
	{ "tag=",             0, ALTF_FSTAG, 1 },
	/*
	 * MOPT_AUTOMOUNTED, included by MOPT_STDOPTS, does not fit into
	 * the 'flags' argument to nmount(2).  We have to abuse altflags
	 * to pass it, as string, via iovec.
	 */
	#define ALTF_AUTOMOUNTED 0x100
	{ "automounted",	0, ALTF_AUTOMOUNTED, 1 },
	#define ALTF_INTR 0x200
	{ "intr",		0, ALTF_INTR, 1 },
	/* "nonempty", just the first two chars are stripped off during parsing */
	{ "nempty",              0, 0x00, 1 },
	{ "async",               0, MNT_ASYNC, 0},
	{ "noasync",             1, MNT_ASYNC, 0},
	MOPT_STDOPTS,
	MOPT_END
};

struct mntval {
	int mv_flag;
	void *mv_value;
	int mv_len;
};

static struct mntval mvals[] = {
	{ ALTF_MAXREAD, NULL, 0 },
	{ ALTF_SUBTYPE, NULL, 0 },
	{ ALTF_FSTAG, NULL, 0 },
	{ 0, NULL, 0 }
};

int
main(int argc, char *argv[])
{
	struct iovec *iov;
	int mntflags, iovlen;
	char *dir = NULL, mntpath[MAXPATHLEN];
	char *tag;
	int done = 0, reject_allow_other = 0; 
	int altflags = 0;
	int __altflags = 0;
	int ch = 0;
	struct mntopt *mo;
	struct mntval *mv;
	static struct option longopts[] = {
		{"reject-allow_other", no_argument, NULL, 'A'},
		{"help", no_argument, NULL, 'h'},
		{0,0,0,0}
	};

	/*
	 * We want a parsing routine which is not sensitive to
	 * the position of args/opts; it should extract the
	 * first two args and stop at the beginning of the rest.
	 * (This makes it easier to call mount_fusefs from external
	 * utils than it is with a strict "util flags args" syntax.)
	 */

	iov = NULL;
	iovlen = 0;
	mntflags = 0;
	do {
		switch(ch) {
		case 'A':
			reject_allow_other = 1;
			break;
		case 'o':
			getmntopts(optarg, mopts, &mntflags, &altflags);
			for (mv = mvals; mv->mv_flag; ++mv) {
				if (! (altflags & mv->mv_flag))
					continue;
				for (mo = mopts; mo->m_flag; ++mo) {
					char *p, *q;

					if (mo->m_flag != mv->mv_flag)
						continue;
					p = strstr(optarg, mo->m_option);
					if (p) {
						p += strlen(mo->m_option);
						q = p;
						while (*q != '\0' && *q != ',')
							q++;
						mv->mv_len = q - p + 1;
						mv->mv_value = malloc(mv->mv_len);
						if (mv->mv_value == NULL)
							err(1, "malloc");
						memcpy(mv->mv_value, p, mv->mv_len - 1);
						((char *)mv->mv_value)[mv->mv_len - 1] = '\0';
						break;
					}
				}
			}
			break;
		case 'h':
			helpmsg();
			break;
		case '\0':
			break;
		case '?':
		default:
			usage();
		}
		if (done)
			break;
	} while ((ch = getopt_long(argc, argv, "Aho:", longopts, NULL)) != -1);
	argc -= optind;
	argv += optind;

	if (argc <= 0)
		errx(1, "missing tag");

	tag = *argv++;

	if (argc <= 0)
		errx(1, "missing mntpath");

	dir = *argv++;

	for (mo = mopts; mo->m_flag; ++mo) {
		if (altflags & mo->m_flag) {
			int iov_done = 0;

			if (reject_allow_other &&
			    strcmp(mo->m_option, "allow_other") == 0)
				/*
				 * reject_allow_other is stronger than a
				 * negative of allow_other: if this is set,
				 * allow_other is blocked, period.
				 */
				errx(1, "\"allow_other\" usage is banned by respective option");

			for (mv = mvals; mv->mv_flag; ++mv) {
				if (mo->m_flag != mv->mv_flag)
					continue;
				if (mv->mv_value) {
					build_iovec(&iov, &iovlen, mo->m_option, mv->mv_value, mv->mv_len);
					iov_done = 1;
					break;
				}
			}
			if (! iov_done)
				build_iovec(&iov, &iovlen, mo->m_option,
				    __DECONST(void *, ""), -1);
		}
		if (__altflags & mo->m_flag) {
			char *uscore_opt;

			if (asprintf(&uscore_opt, "__%s", mo->m_option) == -1)
				err(1, "failed to allocate memory");
			build_iovec(&iov, &iovlen, uscore_opt,
			    __DECONST(void *, ""), -1);
			free(uscore_opt);
		}
	}


	/*
	 * Resolve the mountpoint with realpath(3) and remove unnecessary
	 * slashes from the devicename if there are any.
	 */
	if (checkpath(dir, mntpath) != 0)
		err(1, "%s", mntpath);

	/* Prepare the options vector for nmount(). build_iovec() is declared
	 * in mntopts.h. */
	build_iovec(&iov, &iovlen, "fstype", __DECONST(void *, "virtiofs"), -1);
	build_iovec(&iov, &iovlen, "fspath", mntpath, -1);
	build_iovec(&iov, &iovlen, "tag", tag, -1);

	if (nmount(iov, iovlen, mntflags) < 0)
		err(EX_OSERR, "%s on %s", tag, mntpath);

	exit(0);
}

void
__usage_short(void) {
	fprintf(stderr,
	    "usage:\n%s [-A|-v|-h|-o option...] tag node\n\n",
	    getprogname());
}

void
usage(void)
{
	struct mntopt *mo;

	__usage_short();

	fprintf(stderr, "known options:\n");
	for (mo = mopts; mo->m_flag; ++mo)
		fprintf(stderr, "\t%s\n", mo->m_option);

	fprintf(stderr, "\n(use -h for a detailed description of these options)\n");
	exit(EX_USAGE);
}

void
helpmsg(void)
{
	if (! getenv("MOUNT_FUSEFS_CALL_BY_LIB")) {
		__usage_short();
		fprintf(stderr, "description of options:\n");
	}

	/*
	 * The main use case of this function is giving info embedded in general
	 * FUSE lib help output. Therefore the style and the content of the output
	 * tries to fit there as much as possible.
	 */
	fprintf(stderr,
	        "    -o allow_other         allow access to other users\n"
	        /* "    -o nonempty            allow mounts over non-empty file/dir\n" */
	        "    -o default_permissions enable permission checking by kernel\n"
		"    -o intr                interruptible mount\n"
	        "    -o fsname=NAME         set filesystem name\n"
		/*
	        "    -o large_read          issue large read requests (2.4 only)\n"
		 */
	        "    -o subtype=NAME        set filesystem type\n"
	        "    -o max_read=N          set maximum size of read requests\n"
	        "    -o noprivate           allow secondary mounting of the filesystem\n"
	        "    -o neglect_shares      don't report EBUSY when unmount attempted\n"
	        "                           in presence of secondary mounts\n" 
	        "    -o push_symlinks_in    prefix absolute symlinks with mountpoint\n"
	        );
	exit(EX_USAGE);
}
