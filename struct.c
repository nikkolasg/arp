/*
 * =====================================================================================
 *
 *       Filename:  struct.c
 *
 *    Description:  various test with the struct key word
 *
 *        Version:  1.0
 *        Created:  03/16/2015 04:58:33 PM
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

struct basic {
    int num;
    char * value;
};
    int
main ( int argc, char *argv[] )
{
    struct basic b1;
    const struct basic b2;
    printf("sizeof normal / const : %d vs %d\n",sizeof(b1),sizeof(b2));
    return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
