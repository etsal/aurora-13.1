PACKAGE=runtime
PROG=	mount_virtiofs
SRCS=	mount_virtiofs.c getmntopts.c
MAN8=

MOUNT=	${.CURDIR:H}/mount
CFLAGS+=	-I${MOUNT}

.PATH: ${MOUNT}

.include <bsd.prog.mk>
