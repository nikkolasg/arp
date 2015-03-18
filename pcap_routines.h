/*
 * =====================================================================================
 *
 *       Filename:  pcap_routines.h
 *
 *    Description:  methods headers 
 *
 *        Version:  1.0
 *        Created:  12/22/2014 12:00:06 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  nikkolasg (mn), 
 *        Company:  
 *
 * =====================================================================================
 */
#ifndef PCAP_ROUTINES
#define PCAP_ROUTINES

#include <pcap.h>
void pcap_exit_(void); //signal handler SIGINT
void sniff_callback(u_char * user, const struct  pcap_pkthdr * h,const u_char * bytes) ;

int set_options(pcap_t * handle); 

int activate(pcap_t * handle) ;
int sniffing_method(char * interface, char * filter,int packet_count) ;

void handle_ip(const u_char * bytes);
int pcap_send_packet(const u_char * bytes,int size);
int init_pcap(char * interface, char * filter);
#endif
