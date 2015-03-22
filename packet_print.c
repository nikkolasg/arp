#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "packet_struct.h"
#include "packet_print.h"

void print_mac_addr(const u_char * bytes) {
    int i = 0;
    for(i =0; i < ETH_ADDR_SIZE;i++) {
        fprintf(stdout,"%02X:",bytes[i]);
    }
}

void print_pkt_eth(const pkt_eth * eth) {
	int i = 0;
	
	fprintf(stdout,"Ethernet Layer \n");
	fprintf(stdout,"\tSource:\t%s",ether_ntoa(&eth->src));
    //fprintf(stdout,"%s",to_addr(eth->src,ETH_ADDR_SIZE));
	fprintf(stdout,"\n\tDest:\t%s",ether_ntoa(&eth->dest)); 

	if(ntohs(eth->type) == ETHERTYPE_IP)
		fprintf(stdout,"\n\tType:\t IPv4");
    else if(ntohs(eth->type) == ETHERTYPE_ARP)
        fprintf(stdout,"\n\tType:\t ARP");
    printf("\n");
}

void print_pkt_arp(const pkt_arp * arp) {
    int op = 0;
    int i = 0;
   printf("ARP Layer \n");
      printf("\tHardware type:\t%02X\n",ntohs(arp->htype)); 
      printf("\tProtocol type:\t%04X\n",ntohs(arp->ptype));
      op = ntohs(arp->opcode);
      printf("\tOperation code:\t");
          op == 1 ? printf("request\n") : printf("reply\n");
      printf("\tHardware sender:\t%s",ether_ntoa(&arp->hard_addr_send));

      printf("\n\tSoftware sender:\t");
      printf("%s",inet_ntoa(arp->proto_addr_send));
      
      printf("\n\tHardware destination:\t%s",ether_ntoa(&arp->hard_addr_dest));

      printf("\n\tSoftware destination:\t");
      printf("%s",inet_ntoa(arp->proto_addr_dest));

      printf("\n");

}

void print_pkt_ip(const pkt_ip * ip) {
    int i = 0;
    printf("IPv4 Layer \n");
        printf("\tProtocol code:\t%d\n",ip->proto);
        printf("\tIP source:\t");

        printf("%s",inet_ntoa(ip->addr_src));

        printf("\n\tIP Destination:\t");
        printf("%s",inet_ntoa(ip->addr_dest));

        printf("\n");

}

void print_packet(const Packet * p) {
    struct pkt_eth * eth = (struct pkt_eth *) p;
    struct pkt_arp * arp = (struct pkt_arp *) (p + ETH_SIZE);
    print_pkt_eth(eth);
    if (ntohs(eth->type) == ETHERTYPE_ARP) {
        print_pkt_arp(arp);
    } 
    
}
