/*
 * =====================================================================================
 *
 *       Filename:  packet_struct.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  03/20/2015 02:59:56 PM
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
#include <string.h>
#include "packet_struct.h"

int cmp_mac(const MAC * m1,const MAC * m2) {
    return memcmp(m1,m2,ETH_ADDR_SIZE);
}
int cmp_ip(const IP * i1,const IP * i2) {
    return memcmp(i1,i2,IP_ADDR_SIZE);
}
int cmp_host(const struct Host * h1,const struct Host * h2) {
    return cmp_mac(&h1->mac,&h2->mac) ||  cmp_ip(&h1->ip,&h2->ip);
}
void copy_mac(MAC * m1,const MAC * m2) {
    memcpy(m1,m2,ETH_ADDR_SIZE);
}
void copy_ip(IP * i1,const IP * i2) {
    memcpy(i1,i2,IP_ADDR_SIZE);
}
void copy_host(struct Host * h1,const  struct Host * h2) {
    copy_mac(&h1->mac,&h2->mac);
    copy_ip(&h1->ip,&h2->ip);
}

void print_host(const struct Host * host) {
    printf("Host: %s || %s\n",inet_ntoa(host->ip),ether_ntoa(&host->mac));
}
void print_mac(const MAC * mac) {
    printf("MAC : %s\n",ether_ntoa(mac));
}
void print_ip(const IP * ip) {
    printf("IP : %s\n",inet_ntoa(*ip));
}


