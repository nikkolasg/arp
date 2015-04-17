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

#define REQUEST 1
#define REPLY 0

#define RESOLV_RETRY 3

int arp_resolve_mac ( struct Host * host );
void arp_analyzer_resolv(const Packet * packet,size_t size  );
void nullify_ip(IP *ip);
void nullify_mac(MAC * mac);

/*-----------------------------------------------------------------------------
 *  Injection pArt
 *-----------------------------------------------------------------------------*/

Packet * arp_packet(int opcode);
void arp_set_ethernet_frame(Packet * pkt,const MAC * src,const MAC * dst);
void arp_set_hard_addr(Packet * pkt,const MAC * src,const MAC * dst);
void arp_set_proto_addr(Packet * pkt, const IP * src,const IP * dst);

/*-----------------------------------------------------------------------------
 *  SNIFFING PART
 *-----------------------------------------------------------------------------*/
//void handle_arp(const u_char * packet);
//void handle_arp_request(const u_char* packet);
//void handle_arp_reply(const u_char * packet);
//int arp_poison(const u_char * packet);
//int arp_poison_pkt(const u_char * bytes);
//void try_send_packet(const u_char * bytes);
//int is_from_victim(const struct pkt_arp * packet);
//int is_router_packet(const struct pkt_arp  * packet);
//int is_gratuitous_packet(const struct pkt_arp  * packet);
//int is_broadcast_request(const struct pkt_arp  * packet);
#endif

