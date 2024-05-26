PROG=	virtiodbg

.PATH:	${SRCTOP}/sys/libkern	

SRCS=	block_if.c \
	config.c \
	iov.c \
	iov_emul.c \
	mevent.c \
	mmio_virtio_block.c \
	mmio_emul.c \
	virtio.c \
	virtiodbg.c

MAN=

CFLAGS+=-I${.CURDIR}		\
	-I${SRCTOP}/sys

LIBADD+= md nv pthread 

# Disable thread safety analysis since it only finds very simple bugs and
# yields many false positives.
NO_WTHREAD_SAFETY=

NO_WCAST_ALIGN=

.include <bsd.prog.mk>
