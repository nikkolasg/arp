#ifndef DEF_PACKET_STRUCT
#define DEF_PACKET_STRUCT

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#define BUFF_SIZE 1518
#define ETH_SIZE 14
#define ARP_SIZE 28
#define ARP_PACKET_SIZE (ETH_SIZE+ARP_SIZE)
/* in bytes */
#define ETH_ADDR_SIZE 6
#define IP_ADDR_SIZE 4


typedef u_char Packet;
typedef struct in_addr IP;
typedef struct ether_addr MAC;
typedef u_char Address;

typedef struct pkt_eth {
	Address dest[ETH_ADDR_SIZE];
	Address src[ETH_ADDR_SIZE];
	u_short type;
} pkt_eth;

#define ETHERTYPE_ARP 0x0806
#define ARP_REQUEST 1
#define ARP_REPLY 2
typedef struct pkt_arp {
	u_short htype;/* hardware type => ethernet , etc */
	u_short ptype; /*protocol type => ipv4 or ipv6 */
	u_char hard_addr_len; /* usually 6 bytes for ethernet */
	u_char proto_addr_len; /*usually 8 bytes for ipv4 */
    u_short opcode; /* type of arp */
	Address hard_addr_send[ETH_ADDR_SIZE];
	Address proto_addr_send[IP_ADDR_SIZE];
	Address hard_addr_dest[ETH_ADDR_SIZE];
    Address proto_addr_dest[IP_ADDR_SIZE];
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
    Address addr_src[IP_ADDR_SIZE];
    Address addr_dest[IP_ADDR_SIZE];
} pkt_ip;

#endif
