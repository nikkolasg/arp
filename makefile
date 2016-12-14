CC=clang
CFLAGS=-g -Wextra -Wmissing-prototypes -Wstrict-prototypes -lpcap

all:
	$(CC) $(CFLAGS) main.c  arp.c packet_print.c pcap_routines.c network.c packet_struct.c -o parp


