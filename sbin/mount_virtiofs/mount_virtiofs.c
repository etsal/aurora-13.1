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

static void
usage(void)
{
	fprintf(stderr, "usage:\n%s tag node\n", getprogname());

	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	char mntpath[MAXPATHLEN];
	int mntflags, iovlen;
	struct iovec *iov;
	char *dir, *tag;

	iov = NULL;
	iovlen = 0;
	mntflags = 0;

	if (argc != 3)
		usage();

	tag = argv[1];
	dir = argv[2];

	/* Resolve the mountpoint with realpath(3), remove unnecessary slashes. */
	if (checkpath(dir, mntpath) != 0)
		err(1, "%s", mntpath);

	/* The build_iovec() call is declared in mntopts.h. */
	build_iovec(&iov, &iovlen, "fstype", __DECONST(void *, "virtiofs"), -1);
	build_iovec(&iov, &iovlen, "fspath", mntpath, -1);
	build_iovec(&iov, &iovlen, "tag", tag, -1);

	if (nmount(iov, iovlen, mntflags) < 0)
		err(EX_OSERR, "%s on %s", tag, mntpath);

	exit(0);
}

