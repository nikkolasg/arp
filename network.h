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

int get_socketudp();
struct ifreq get_ifreq(const char * interface);
<<<<<<< Updated upstream
int get_mac_address(const char * interface,unsigned char mac[6]);
struct in_addr get_ip_address(const char * interface);
int get_mac_addr(char * interface,unsigned char mac[6]);
=======
int get_mac_address(const char * interface,struct ether_addr * ether);
int get_mac_address_old(char * interface,unsigned char mac[6]);
int get_ip_address(const char * interface,struct in_addr * addr);
void print_ioctl_error(void);

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
>>>>>>> Stashed changes

#endif
