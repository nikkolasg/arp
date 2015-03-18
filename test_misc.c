/*
 * =====================================================================================
 *
 *       Filename:  test_misc.c
 *
 *    Description:  diverses test
 *
 *        Version:  1.0
 *        Created:  03/18/2015 09:11:30 AM
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
#include <netinet/ether.h>

#include <string.h>
typedef char * PACKET;
typedef char ADDRESS;
typedef const char CADDR;
typedef struct ether_addr MAC;
#define BROAD "ff:ff:ff:ff:ff:ff"
#define TO_CHAR(X) (  ether_ntoa(X))
#define TO_ETHER(X) ( (void *) ether_aton(X))

    int
main ( int argc, char *argv[] )
{
    PACKET p1 = "Hello You";
    char add[] = "Aie";
    ADDRESS a[4];
    CADDR ca[] = "Const";

    MAC * eth = TO_ETHER(BROAD);
    strcpy(a,add);
    printf("%s\n",p1);
    printf("%s\n",a);
    printf("%s\n",ca);
    printf("%s\n",TO_CHAR(eth));
    return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
