all:
	gcc -lpcap  own_sniff.c packet_print.c pcap_routines.c network.c arp.c -o sniff

debug:
	gcc -lpcap -g  own_sniff.c packet_print.c pcap_routines.c network.c arp.c -o sniff
training:
	gcc -lpcap network.c test.c -o test

