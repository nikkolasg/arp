all:
	gcc -Wextra -Wmissing-prototypes -Wstrict-prototypes -lpcap main.c  arp.c packet_print.c pcap_routines.c network.c -o parp


