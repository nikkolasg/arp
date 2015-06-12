/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  to run some test in C
 *
 *        Version:  1.0
 *        Created:  12/24/2014 11:07:33 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (mn), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet_struct.h"
#include "network.h"

    int
main ( int argc, char *argv[] )
{
    char arr[4] = {192,168,1,4};
    struct in_addr * arrstruct;
    struct in_addr network;
    struct ether_addr ether;
    int s = ARP_PACKET_SIZE;
    int i = 0;
    printf("Size of a struct arp : %d bytes\n",s);

    char interface[] = "wlp3s0";
    unsigned char mac[6] = {'0'};
    struct in_addr ipaddr;
    
    if(get_mac_address(interface,mac) == 0) {
        printf("MAC Address : %02X:%02X:%02X:%02X:%02X:%02X\n",mac[0],mac[1],
                mac[2],mac[3],
                mac[4],mac[5]);
    } else {
        printf("Unable to get mac address ... \n");
        exit(EXIT_FAILURE);
    }
    if(get_mac_address_struct(interface,&ether) == 0) {
        printf("MAC Address with Struct : %s\n",ether_ntoa(&ether));
    }
   get_ip_address(interface,&ipaddr);

   if (1) {
        printf("IP Address : %s\n",inet_ntoa(ipaddr));
    } else {
        printf("Unable to get ip address ... \n");
        exit(EXIT_FAILURE);
    }


    return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
