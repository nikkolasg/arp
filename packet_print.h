/*
 * =====================================================================================
 *
 *       Filename:  packet_print.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/27/2014 05:42:35 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (mn), 
 *        Company:  
 *
 * =====================================================================================
 */

#ifndef PACKET_PRINT_
#define PACKET_PRINT_

void print_pkt_eth(const pkt_eth * eth);
void print_pkt_arp(const pkt_arp * arp);
void print_pkt_ip(const pkt_ip * ip);

#endif
