/*
 * =====================================================================================
 *
 *       Filename:  network.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/25/2014 04:46:14 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (mn), 
 *        Company:  
 *
 * =====================================================================================
 */

#ifndef NETWORK_
#define NETWORK_

#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#define BROADCAST_MAC "ff:ff:ff:ff:ff:ff"
#define NULL_MAC "00:00:00:00:00:00"
#define ETHER_ATON(X) ((void *) ether_aton(X))
#define ETHER_NTOA(X) (ether_ntoa(X))
#define INET_ATON(X)  ((void *)inet_aton(X))
#define INET_NTOA(X)  (inet_ntoa(X))

int get_socketudp(void);
struct ifreq get_ifreq(const char * interface);
int get_mac_address(const char * interface,struct ether_addr * ether);
int get_mac_address_old(char * interface,unsigned char mac[6]);
int get_ip_address(const char * interface,struct in_addr * addr);


/* Code from internet. See implementation for details */
struct route_info
{
    struct in_addr dstAddr;
    struct in_addr srcAddr;
    struct in_addr gateWay;
    char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, size_t buf_size, unsigned int seqNum, unsigned int pId);
int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo);
int get_gatewayip(char gatewayip[INET_ADDRSTRLEN]);

#endif
