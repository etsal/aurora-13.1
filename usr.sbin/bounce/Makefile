.include <src.opts.mk>

PROG=	bounce
PACKAGE=	bounce

BHYVE_SYSDIR?=${SRCTOP}

.PATH:	${SRCTOP}/sys/libkern		\
	${SRCTOP}/sys/cam/ctl

SRCS=	block_if.c \
	bounce.c \
	config.c \
	iov.c \
	iov_emul.c \
	mevent.c \
	mmio_virtio_block.c \
	virtio.c

CFLAGS+=-I${.CURDIR}		\
	-I${SRCTOP}/sys

LIBADD+= md nv pthread z util 

# Disable thread safety analysis since it only finds very simple bugs and
# yields many false positives.
NO_WTHREAD_SAFETY=

NO_WCAST_ALIGN=

.include <bsd.prog.mk>
