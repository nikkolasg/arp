#ifndef DEF_PACKET_STRUCT
#define DEF_PACKET_STRUCT

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#define BUFF_SIZE 1518
#define ETH_SIZE 14
#define ARP_SIZE 28
#define ARP_PACKET_SIZE (ETH_SIZE+ARP_SIZE)
#define ETH_ADDR_SIZE 6
#define IP_ADDR_SIZE 4

typedef u_char Packet;
typedef struct in_addr IP;
typedef struct ether_addr MAC;

struct Host {
    IP ip;
    MAC mac;
};

/*-----------------------------------------------------------------------------
 *  Helper methods to compare MAC , IP & Hosts
 *-----------------------------------------------------------------------------*/
int cmp_mac(const MAC * m1,const MAC * m2);
int cmp_ip(const IP * i1,const IP * i2) ;
int cmp_host(const struct Host * h1,const struct Host * h2) ;
void copy_mac(MAC * m1,const MAC * m2); 
void copy_ip(IP * i1,const IP * i2) ;
void copy_host(struct Host * h1, const struct Host * h2) ;

void print_host(const struct Host * host);
void print_mac(const MAC * mac);
void print_ip(const IP * ip);

typedef struct __attribute__ ((__packed__)) pkt_eth {
	MAC dest;
	MAC src;
	u_short type;
} pkt_eth;

#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2
typedef struct __attribute__ ((__packed__)) pkt_arp {
	u_short htype;/* hardware type => ethernet , etc */
	u_short ptype; /*protocol type => ipv4 or ipv6 */
	u_char hard_addr_len; /* usually 6 bytes for ethernet */
	u_char proto_addr_len; /*usually 8 bytes for ipv4 */
    u_short opcode; /* type of arp */
	MAC hard_addr_send;
	IP proto_addr_send;
	MAC hard_addr_dest;
    IP proto_addr_dest;
} pkt_arp;

#define ETHERTYPE_IP 0x0800
typedef struct pkt_ip {
	u_char vhl;
	u_char tos;
	u_short len;
	u_short id;
	u_short off;
	u_char ttl;
	u_char proto;
	u_short crc;
    IP addr_src;
    IP addr_dest;
} pkt_ip;

#endif
