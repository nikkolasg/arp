/*
 * =====================================================================================
 *
 *       Filename:  test_misc.c
 *
 *    Description:  diverses test
 *
 *        Version:  1.0
 *        Created:  03/18/2015 09:11:30 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (mn), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <string.h>
typedef char * PACKET;
typedef char ADDRESS;
typedef const char CADDR;
typedef struct ether_addr MAC;
typedef struct in_addr IP;
#define BROAD "ff:ff:ff:ff:ff:ff"
#define TO_CHAR(X) (  ether_ntoa(X))
#define TO_ETHER(X) ( (void *) ether_aton(X))

struct Host {
    IP ip;
    MAC mac;
};

int compare_mac(MAC * m1,MAC * m2) {
    return memcmp(m1,m2,6);
}
int compare_ip(IP * ip1,IP * ip2) {
    return memcmp(ip1,ip2,4);
} 
    int
main ( int argc, char *argv[] )
{
    PACKET p1 = "Hello You";
    char add[] = "Aie";
    char macadd[6];
    ADDRESS a[4];
    CADDR ca[] = "Const";
    MAC null = (MAC) {{0}};
    IP nullip = (IP) { 0 };
    struct Host h1 = { nullip,null };
    MAC * eth = TO_ETHER(BROAD);
    MAC * eth2 = TO_ETHER(BROAD);
    h1.mac = (MAC) *eth;
    strcpy(a,add);
    printf("%s\n",p1);
    printf("%s\n",a);
    printf("%s\n",ca);
    printf("%s\n",TO_CHAR(eth));
    printf("sizeof(struct ether_addr) %lu vs %lu sizeof(unsigned char [6])\n",sizeof(struct ether_addr),sizeof(macadd));
    printf("IP struct : %lu vs %lu IP char[4]\n",sizeof(struct in_addr),sizeof(a));
    printf("ether memcmp => %d\n",memcmp(eth,eth2,6));
    printf("ether null : %s\n",ether_ntoa(&null));
    printf("host = null ? (ip => %d) (mac => %d)\n",compare_ip(&h1.ip,&nullip),compare_mac(&h1.mac,&null));
    return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
