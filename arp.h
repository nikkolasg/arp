/*
 * =====================================================================================
 *
 *       Filename:  arp.h
 *
 *    Description:  headers of the ARP handle
 *
 *        Version:  1.0
 *        Created:  12/22/2014 08:53:47 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (mn), 
 *        Company:  
 *
 * =====================================================================================
 */

#ifndef ARP_
#define ARP_
#include <pcap.h>
#include "packet_struct.h"
void handle_arp(const u_char * packet);
void handle_arp_request(const u_char* packet);
void handle_arp_reply(const u_char * packet);
int arp_poison(const u_char * packet);
int arp_poison_pkt(const u_char * bytes);
void try_send_packet(const u_char * bytes);
int is_from_victim(const struct pkt_arp * packet);
int is_router_packet(const struct pkt_arp  * packet);
int is_gratuitous_packet(const struct pkt_arp  * packet);
int is_broadcast_request(const struct pkt_arp  * packet);
#endif

