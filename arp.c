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
#include <net/if_arp.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include "packet_struct.h"
#include "packet_print.h"

#include "arp.h"

extern MAC mac;
extern IP ip;
extern char * interface;

/* Just some useful vars */
const MAC broadcast_mac = { 0xff,0xff,0xff,0xff,0xff,0xff };
const MAC  null_mac = { 0x00,0x00,0x00,0x00,0x00,0x00 };
const IP broadcast_ip = { 0xffffffff };
const IP null_ip = { 0x00000000 };
const struct Host null_host = {{ 0x00000000 },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }};

/* Empty mac address which can be used as a temp variable */
/* ether_null & ip_null defined as macro in arp.h
 * so we can instantiate with null default values */
MAC tmp_mac = { 0x00,0x00,0x00,0x00,0x00,0x00 };
IP tmp_ip = { 0x00000000 };

int arp_sent = 0;
int arp_success = 0;



/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  arp_resolve_mac
 *  Description:  find the MAC address associated to the IP address in the network
 *  It sends an ARP request then wait for the reply. 
 * =====================================================================================
 */
    int
arp_resolve_mac ( struct Host * host )
{
    int retry = 0;
    struct pkt_arp * arp;
    struct pkt_eth * eth;
    /*Create the request packet */
    Packet * request = arp_packet(REQUEST);
    eth = (struct pkt_eth *) (request);
    arp = (struct pkt_arp *) (request + ETH_SIZE);

    copy_mac(&eth->dest,&broadcast_mac);
    copy_mac(&eth->src,&mac);
    //arp_set_ethernet_frame(request,&mac,&broadcast_mac);

    /* arp request => mac dest address set to null */
    //arp_set_hard_addr(request,&mac,&null_mac);
    //memcpy(&arp->hard_addr_send,&mac,ETH_ADDR_SIZE);
    //arp->hard_addr_dest = null_mac;
    copy_mac(&arp->hard_addr_send,&mac);
    copy_mac(&arp->hard_addr_dest,&null_mac);

    /* arp request => target ip ! */
    //arp_set_proto_addr(request,&ip,&host->ip);
    //arp->proto_addr_send = ip;
    //inet_aton("10.0.0.2",&arp->proto_addr_dest);
    copy_ip(&arp->proto_addr_send,&ip);
    copy_ip(&arp->proto_addr_dest,&host->ip);

    /* Set up sniffing. Better to do it before so less 
     * prepare time and if any error occurs, no need to send
     * the packet. less intrusive */
    pcap_init(interface,"arp");
    pcap_set_arp_analyzer(arp_analyzer_resolv);

    /* Sets the tmp ip variable so we will know if it the right
     * response we get or a response coming from another source */
    tmp_ip = host->ip;
    
    /* Will try to resolv. Sometimes, we receive another ARP
     * packet coming from the network instead of the reply we want,
     * so better try a few times instead of just leaving */
    while(retry < RESOLV_RETRY) { 
       
        /* sends the packet */
        if(pcap_send_packet(request,ARP_PACKET_SIZE) == -1) {
            fprintf(stderr,"Error while sending ARP request packet.\n");
            return -1;
        }
       
        /* Sniff a packet, hopefully it will be our response */ 
        pcap_sniff(1);
       
        /* Test if we have found the right MAC 
         * i.e. if our tmp var is not null */ 
        if(cmp_mac(&tmp_mac,&null_mac) == 0) {
            fprintf(stderr,"ARP Resolve did not find MAC associated with %s.\n",inet_ntoa(ip));
            fflush(stderr); 
            retry++;
        } else {
            retry = RESOLV_RETRY + 1;
        }
    }

    /* leave if not found */
    if(retry == RESOLV_RETRY) return -1;

    /* cpy into the receptor */
    copy_mac(&host->mac,&tmp_mac);
    /* empty out */
    nullify_ip(&tmp_ip);
    nullify_mac(&tmp_mac);
    free(request);
    
    return 1;
}		/* -----  end of function arp_resolve_MAC  ----- */



/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  arp_analyzer_resolv
 *  Description:  Anayze the ARP packets sniffed by pcap.
 *                Will find if it is the response to the request
 *                we made
 * =====================================================================================
 */
    void
arp_analyzer_resolv (const u_char * packet,size_t size  )
{
    const struct pkt_arp * arp = (const struct pkt_arp *) (packet + ETH_SIZE);
    /* check operation code */
    if(ntohs(arp->opcode) != ARPOP_REPLY) {
        fprintf(stderr,"Received a ARP Request. Skip.\n");
        return;
    }
    /* check address consistency with our precedent request */
    if(memcmp(&arp->proto_addr_send,&tmp_ip,IP_ADDR_SIZE) != 0) {
        fprintf(stderr,"ARP Reply ip sender is not the right one.Skip.\n");
        return;
    }
    if(memcmp(&arp->proto_addr_dest,&ip,IP_ADDR_SIZE) != 0) {
        fprintf(stderr,"ARP Reply ip target is not ours.Skip.\n");
        return;
    }
    if(memcmp(&arp->hard_addr_dest,&mac,ETH_ADDR_SIZE) != 0) {
        fprintf(stderr,"ARP Reply mac target is not ours.Skip.\n");
        return;
    }
    /* Everything is good ;) */
    /* copy the sender MAC address into our tmp var */
    memcpy(&tmp_mac,&arp->hard_addr_send,ETH_ADDR_SIZE);
    return ;
}		/* -----  end of function arp_analyzer  ----- */



    void
nullify_ip ( IP * ip )
{
    memset(ip,0x00,IP_ADDR_SIZE);
    return ;
}		/* -----  end of function nullify_ip  ----- */

void nullify_mac( MAC * mac) {
    memset(mac,0x00,ETH_ADDR_SIZE);
}

/*-----------------------------------------------------------------------------
 *  INJECTION PART : you can here create custom ARP packets
 *  lots of methods 
 *-----------------------------------------------------------------------------*/

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  arp_empty
 *  Description:  Returns a ARP packet of specified type (Reply or Request)
 *  Request = 1; Reply = 0
 *  It also sets the hard_proto & target_proto length fields
 * =====================================================================================
 */
    Packet *
arp_packet ( int opcode )
{
    struct pkt_arp * arp;
    struct pkt_eth * eth;
    Packet * bytes = (Packet *) malloc(ARP_PACKET_SIZE);
    if(bytes == NULL) {
        fprintf(stderr,"Could not alloc ARP packet.\n");
        return NULL;
    }
    eth = (struct pkt_eth *) (bytes);
    eth->type = htons(ETHERTYPE_ARP);
    /* length about hard / proto  ... */
    arp = (struct pkt_arp *) (bytes + ETH_SIZE);
    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hard_addr_len = ETH_ADDR_SIZE;
    arp->proto_addr_len = IP_ADDR_SIZE;
    /* reply or request */
    arp->opcode = opcode == REQUEST ? htons(ARPOP_REQUEST) : htons(ARPOP_REPLY);

    return bytes;
}		/* -----  end of function arp_empty  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  arp_set_ethernet_frame
 *  Description:  Set the destination & Source in the ethernet frame
 * =====================================================================================
 */
void
arp_set_ethernet_frame(Packet * pkt,const MAC * src,const MAC * dst) {
    struct pkt_eth * eth = (struct pkt_eth *) pkt;
    memcpy(&eth->dest,dst,ETH_ADDR_SIZE);
    memcpy(&eth->src,src,ETH_ADDR_SIZE);
}


    void
arp_set_hard_addr (Packet * pkt,const MAC * src,const MAC * dst )
{
    struct pkt_arp * arp = (struct pkt_arp *) (pkt + ETH_SIZE);
    arp->hard_addr_send = *src;
    arp->hard_addr_dest = *dst;
    //memcpy(&arp->hard_addr_send,src,ETH_ADDR_SIZE);
    //memcpy(&arp->hard_addr_dest,dst,ETH_ADDR_SIZE);
}		/* -----  end of function arp_set_hard_addr  ----- */


    void
arp_set_proto_addr (Packet * pkt,const IP * src,const IP * dst)
{
    struct pkt_arp * arp = (struct pkt_arp *) (pkt + ETH_SIZE);
    arp->proto_addr_send = *src;
    arp->proto_addr_dest = *dst;
    //memcpy(&arp->proto_addr_send,src,IP_ADDR_SIZE);
    //memcpy(&arp->proto_addr_dest,dst,IP_ADDR_SIZE);
    // printf("arp ip  frame => %s ",inet_ntoa(*src));
    // printf("|| %s\n",inet_ntoa(*dst));
}		/* -----  end of function arp_set_proto_addr  ----- */


