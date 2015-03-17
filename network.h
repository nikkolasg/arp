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
int get_mac_address(const char * interface,unsigned char mac[6]);
int get_mac_addr(char * interface,unsigned char mac[6]);
struct in_addr get_ip_address(const char * interface);

#endif
