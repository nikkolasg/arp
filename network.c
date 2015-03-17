/*
 * =====================================================================================
 *
 *       Filename:  network.c
 *
 *    Description:  small routines for network operations
 *
 *        Version:  1.0
 *        Created:  12/23/2014 06:40:32 PM
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
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>



/*
 * Return a UDP socket 
 * */
int get_socketudp() {
    int fd;
    fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd == -1) {
        fprintf(stderr,"Unable to open socket.\nAbort.");
        exit(EXIT_FAILURE);
    }
    return fd;
}

/*
 * Return a ifreq structure for this interface
 * */
    struct ifreq
get_ifreq ( const char * interface )
{

    struct ifreq ifr;
    size_t if_len;


    if_len = strlen(interface);
    if (if_len >= sizeof(ifr.ifr_name)){
        fprintf(stderr,"Interface name too long to open descriptor.\nAbort.");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name,interface,if_len);

    return ifr;
}


/*
 * Returns the mac address of the interface
 * */
    int
get_mac_address (const char * interface,unsigned char mac[6] )
{
    int fd ;
    struct ifreq ifr = get_ifreq(interface);
    fd = get_socketudp();

    if(ioctl(fd,SIOCGIFHWADDR,&ifr) == -1) {
        close(fd);
        fprintf(stderr,"Error while operating IOCTL (MAC resolving).\nAbort.");
        return -1;
    } 
    close(fd);
    memcpy(mac,ifr.ifr_hwaddr.sa_data,6);
    return 0;
}		/* -----  end of function mac_address  ----- */

/*
 * returns the first ip address associated with this interface 
 * */
    struct in_addr
get_ip_address ( const char * interface)
{
    int fd;
    struct sockaddr_in * ipaddr;
    struct ifreq ifr = get_ifreq(interface);
    fd = get_socketudp();

    if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        close(fd);
        fprintf(stderr,"Error while operating IOCTL.\nAbort.");
        return ;
    }
    ipaddr = (struct sockaddr_in *) &ifr.ifr_addr;
    close(fd);

    return (struct in_addr) ipaddr->sin_addr;
}		/* -----  end of function ip_address  ----- */


/*
 * Copy the mac address of the interface into the buffer chMAC
 * */
int get_mac_addr(  char * interface,unsigned char chMAC[6]) {
    
    struct ifreq ifr;
    
    int sock;
    
    char * ifname = interface;

    sock=socket(AF_INET,SOCK_DGRAM,0);
    strcpy( ifr.ifr_name, ifname );
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0) {
        fprintf(stderr,"Error while ioctl MAC address\n");
        return -1;
    }
    memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6);
        close(sock);
    return 0;

}

