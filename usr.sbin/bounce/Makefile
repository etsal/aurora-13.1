# XXX Temporary till we hook this into the kernel build system

all: bounce

bounce: bounce.c
	$(CC) -Wall -O0 -lpthread -o bounce bounce.c pci_virtio_block.c

clean:
	rm -f bounce *.o
