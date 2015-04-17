/*
 * =====================================================================================
 *
 *       Filename:  pcap_routines.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/22/2014 11:47:56 AM
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
#include <pcap.h>
#include <signal.h>

#include "pcap_routines.h"
#include "arp.h"

#define SNAP_LEN 1518
#define MAX_PKT_NUMBER 5

/* the main structure used by pcap */
static pcap_t * handle;
/* used to filter the incoming packets by pcap */
struct bpf_program bpf;

Packet_analyzer arp_analyzer = NULL;
Packet_analyzer ip_analyzer = NULL;

int initialized = 0;
static int packet_count = 0;
/**
 * Send a raw array of bytes
 * return 0 in success, -1 in failure
 * */
int pcap_send_packet(const u_char * bytes,int size) {
    if(pcap_inject(handle,bytes,size) != size) {
        fprintf(stderr,"Packet could not be sent.\n");
        return -1;
    } 
    return 0;
}



/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_set_arp_analyzer
 *  Description:  Simply sets the arp pointer function right
 *  so that function receives the packets when sniffing later.
 * =====================================================================================
 */
    void
pcap_set_arp_analyzer ( Packet_analyzer arp )
{
    arp_analyzer = arp;
    return ;
}		/* -----  end of function pcap_set_arp_analyzer  ----- */


    void
pcap_set_ip_analyzer ( Packet_analyzer ip )
{
    ip_analyzer = ip;
    return ;
}		/* -----  end of function pcap_set_ip_analyzer  ----- */

/**
 * Main loop function that receives packets
 * */
void sniff_callback(u_char * user, const struct  pcap_pkthdr * h,const u_char * bytes) {
    int i = 0;
    printf("Received packet number %d ==> %d bytes\n",packet_count++,h->len);
    const struct pkt_eth * eth;
    unsigned short eth_type;

    unsigned int captureLength = h->caplen;
    unsigned int packetLength = h->len;

    if(captureLength != packetLength) {
        fprintf(stderr,"Error : received packet with %d available instead of %d \n",captureLength,packetLength);
        return;
    }
    if(captureLength < ETH_SIZE) {
        fprintf(stderr,"Error : received too small packet , %d bytes",captureLength);
        return;
    }

    eth = (struct pkt_eth*)(bytes);

    // print the packet
//    print_packet(bytes);

    eth_type = ntohs(eth->type);

    if(eth_type == ETHERTYPE_ARP && arp_analyzer != NULL) {
       arp_analyzer(bytes,h->len); 
    } else if (eth_type == ETHERTYPE_IP && ip_analyzer != NULL) {
        ip_analyzer(bytes,h->len);
    }
    
    //printf("\n");for(i=0; i < 25; i++) { printf("-"); }; printf("\n\n");

    return;
   
}

/* returns 0 if everything went well */
int set_options(pcap_t * handle) {
	int ret = 0;
		
    printf("Options : ");
	ret = pcap_set_promisc(handle,1);
	if(ret != 0) {
		fprintf(stderr,"Error setting promiscuous mode\n");
		return ret;
	}
    printf("promisc");
	ret = pcap_set_snaplen(handle,SNAP_LEN);
	if(ret != 0) {
		fprintf(stderr,"Error setting snapshot length\n");
		return ret;
	}
    printf(", snaplen");
   
	ret = pcap_set_timeout(handle,1000);
	if(ret != 0) {
		fprintf(stderr,"Error setting timeout\n");
		return ret;
	}
    printf(", timeout ");
    
	return ret;
}
/* simply activate the interface we're listening on */
int activate(pcap_t * handle) {
	int ret = pcap_activate(handle);
	switch(ret) {
		case 0:
			fprintf(stdout,"Activation complete\n");
			break;
		case PCAP_WARNING_PROMISC_NOTSUP:
		       fprintf(stderr,"Promiscuous mode not supported\n");
	       	       return ret;
		case PCAP_ERROR_PERM_DENIED:
		       fprintf(stderr,"Not have the permission required\n");
		       return ret;
	/*	case PCAP_ERROR_PROMISC_PERM_DENIED:
		       fprintf(stderr,"Not have the permission required for promiscuous\n");
		       return ret;
		*/default:
		       fprintf(stderr,"Error occured during activation, see code\n");
		       return ret;
	}
	return ret;	
}

/* Will activate device , filter & call the sniffing loop */
/* Return 0 on success otherwise exit application */
int pcap_init(char * interface, char * filter) {
    
    char err[PCAP_ERRBUF_SIZE]; //error buffer

    bpf_u_int32 mask; // network mask 
    bpf_u_int32 ip; // network ip
    struct in_addr addr; // network number

    int ret;
    if(initialized) return;
    /* get mask & ip */
    if(pcap_lookupnet(interface, &ip, &mask, err) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",interface,err);
        exit(EXIT_FAILURE);
    } 
        
    handle = pcap_create(interface,err);
	if (handle == NULL) {
		fprintf(stderr,"Error pcap_create() : %s \n",err);
		exit(EXIT_FAILURE);
	}
	if(set_options(handle) != 0) {
		fprintf(stderr,"Exiting\n");
		exit(EXIT_FAILURE);
	}
	if (activate(handle) != 0) {
		fprintf(stderr,"Exiting\n");
		exit(EXIT_FAILURE);
	}
	
    /* FILTER PART */
    if(filter != NULL) {
        if(pcap_compile(handle,&bpf,filter,0,ip) == -1){
            fprintf(stderr,"Couldn't compile filter expr %s : %s\n",filter,pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        if(pcap_setfilter(handle, &bpf) == -1) {
            fprintf(stderr,"Couldn't install filter %s : %s\n",filter,pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }
    initialized = 1;
    return 0;
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_exit
 *  Description:  free up the memory
 * =====================================================================================
 */

    void
pcap_exit_ (void )
{
    pcap_breakloop(handle);
    pcap_freecode(&bpf);
    pcap_close(handle);
    return ;
}		/* -----  end of function pcap_close  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  pcap_sniff
 *  Description:  simply a wrapper around the sniffing method of pcap
 * =====================================================================================
 */
    void
pcap_sniff ( int packet_count )
{
    printf("Sniffing started ...");
    pcap_loop(handle,packet_count,sniff_callback,NULL);
    printf(" Ok ;)");
    fflush(stdout);
    return ;
}		/* -----  end of function pcap_sniff  ----- */

