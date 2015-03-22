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
#include <netinet/ether.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "network.h"




/*
 * Return a UDP socket 
 * */
int get_socketudp(void) {
    int fd;
    fd = socket(AF_INET,SOCK_DGRAM,0);
    if(fd == -1) {
        fprintf(stderr,"Unable to open socket.\n");
        return -1;
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

    memset(ifr.ifr_name,0x00,IFNAMSIZ);
    if_len = strlen(interface);
    if (if_len >= IFNAMSIZ){
        fprintf(stderr,"Interface name too long to open descriptor.\nAbort.");
        exit(EXIT_FAILURE);
    }

    strncpy(ifr.ifr_name,interface,if_len);

    return ifr;
}

int 
get_mac_address(const char * interface, struct ether_addr * ether) {
    int fd ;
    struct ifreq ifr = get_ifreq(interface);
    if((fd = get_socketudp()) == -1) {
        fprintf(stderr,"Unable to get mac address.\n");
        return -1;
    };
    
    if(ioctl(fd,SIOCGIFHWADDR,&ifr) == -1) {
        fprintf(stderr,"%s\n",strerror(fd));
        fprintf(stderr,"Error while operating IOCTL (MAC resolving).\n");
        close(fd);
        return -1;
    } 
    close(fd);
    memcpy(ether,&ifr.ifr_hwaddr.sa_data,ETH_ALEN);
    return 0;

}
/*
 * Set the first  ip address associated with this interface 
 * return 0 on success, -1 otherwise
 * */
int
get_ip_address ( const char * interface,struct in_addr * addr)
{
    int fd;
    struct sockaddr_in * ipaddr;
    struct ifreq ifr = get_ifreq(interface);
    fd = get_socketudp();

    if(ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        fprintf(stderr,"%s\n",strerror(errno));
        fprintf(stderr,"\nError while operating IOCTL (%s).\n",interface);
        close(fd);
        return -1;
    }
    ipaddr = (struct sockaddr_in *) &ifr.ifr_addr;
    close(fd);

    *addr = (struct in_addr) ipaddr->sin_addr;
    return 0;
}		/* -----  end of function ip_address  ----- */

/*
 * * Returns the mac address of the interface
 * * */
int
get_mac_addr (const char * interface,unsigned char mac[6] )
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
} /* ----- end of function mac_address ----- */

/*
 * Copy the mac address of the interface into the buffer chMAC
 * */
int get_mac_address_old(  char * interface,unsigned char chMAC[6]) {
    
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

void print_ioctl_error(void) {
    switch(errno) {
        case EBADF:
            printf("Not a valid descriptor.");
            break;
        case EFAULT:
            printf("Argp is referencing inacessible memory area.");
            break;
        case EINVAL:
            printf("Request or argp is not valid.");
            break;
        case ENOTTY:
            printf("Request not available on this device.");
            break;
        default:
            printf("%s",strerror(errno));
            break;
    }
    fflush(stdout);

}
/*-----------------------------------------------------------------------------
 *  Gateway part : fetch the default gateway associated with the network
 *  Code taken from : http://www.linuxquestions.org/questions/linux-networking-3/howto-find-gateway-address-through-code-397078/

 *-----------------------------------------------------------------------------*/

#define BUFSIZE 8192

#include <sys/socket.h>
#include <net/if.h>
#include <linux/rtnetlink.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "network.h"

int readNlSock(int sockFd, char *bufPtr, size_t buf_size,unsigned int seqNum, unsigned int pId)
{
    struct nlmsghdr *nlHdr;
    int readLen = 0,  msgLen = 0;

    do
    {
        /* Recieve response from the kernel */
        if((readLen = recv(sockFd, bufPtr, buf_size - msgLen, 0)) < 0)
        {
            perror("SOCK READ: ");
            return -1;
        }

        nlHdr = (struct nlmsghdr *)bufPtr;

        /* Check if the header is valid */
        if((NLMSG_OK(nlHdr, (unsigned)readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR))
        {
            perror("Error in recieved packet");
            return -1;
        }

        /* Check if the its the last message */
        if(nlHdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }
        else
        {
            /* Else move the pointer to buffer appropriately */
            bufPtr += readLen;
            msgLen += readLen;
        }

        /* Check if its a multi part message */
        if((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            /* return if its not */
            break;
        }
    }
    while((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}

/* parse the route info returned */
int parseRoutes(struct nlmsghdr *nlHdr, struct route_info *rtInfo)
{
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;

    rtMsg = (struct rtmsg *)NLMSG_DATA(nlHdr);

    /* If the route is not for AF_INET or does not belong to main routing table then return. */
    if((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN))
        return -1;

    /* get the rtattr field */
    rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);

    for(; RTA_OK(rtAttr,rtLen); rtAttr = RTA_NEXT(rtAttr,rtLen))
    {
        switch(rtAttr->rta_type)
        {
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(rtAttr), rtInfo->ifName);
                break;

            case RTA_GATEWAY:
                memcpy(&rtInfo->gateWay, RTA_DATA(rtAttr), sizeof(rtInfo->gateWay));
                break;

            case RTA_PREFSRC:
                memcpy(&rtInfo->srcAddr, RTA_DATA(rtAttr), sizeof(rtInfo->srcAddr));
                break;

            case RTA_DST:
                memcpy(&rtInfo->dstAddr, RTA_DATA(rtAttr), sizeof(rtInfo->dstAddr));
                break;
        }
    }

    return 0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_gatewayip
 *  Description:  Store the gateway ip address (in dot notation) in 
 *  the gatewayip char pointer. 
 *  The char array must be of size INET_ADDRSTRLEN at least to store the ad
 *  Return 0 if found. Otherwise -1.
 * =====================================================================================
 */
int get_gatewayip(char gatewayip[INET_ADDRSTRLEN])
{
    socklen_t size = INET_ADDRSTRLEN;
    
    int found_gatewayip = 0;

    struct nlmsghdr *nlMsg;
    struct rtmsg *rtMsg;
    struct route_info route_info;
    char msgBuf[BUFSIZE]; // pretty large buffer

    int sock, len, msgSeq = 0;

    /* Create Socket */
    if((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0)
    {
        perror("Socket Creation: ");
        return(-1);
    }

    /* Initialize the buffer */
    memset(msgBuf, 0, sizeof(msgBuf));

    /* point the header and the msg structure pointers into the buffer */
    nlMsg = (struct nlmsghdr *)msgBuf;
    rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);

    /* Fill in the nlmsg header*/
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)); // Length of message.
    nlMsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .

    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
    nlMsg->nlmsg_seq = msgSeq++; // Sequence of the message packet.
    nlMsg->nlmsg_pid = getpid(); // PID of process sending the request.

    /* Send the request */
    if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0)
    {
        fprintf(stderr, "Write To Socket Failed...\n");
        return -1;
    }

    /* Read the response */
    if((len = readNlSock(sock, msgBuf, sizeof(msgBuf), msgSeq, getpid())) < 0)
    {
        fprintf(stderr, "Read From Socket Failed...\n");
        return -1;
    }

    /* Parse and print the response */
    for(; NLMSG_OK(nlMsg,(unsigned)len); nlMsg = NLMSG_NEXT(nlMsg,len))
    {
        memset(&route_info, 0, sizeof(route_info));
        if ( parseRoutes(nlMsg, &route_info) < 0 )
            continue;  // don't check route_info if it has not been set up

        // Check if default gateway
        if (strstr((char *)inet_ntoa(route_info.dstAddr), "0.0.0.0"))
        {
            // copy it over
            inet_ntop(AF_INET, &route_info.gateWay, gatewayip, size);
            found_gatewayip = 1;
            break;
        }
    }

    close(sock);

    return found_gatewayip;
}


