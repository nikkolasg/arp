/*
 * =====================================================================================
 *
 *       Filename:  test_opts.c
 *
 *    Description:  test to learn get_opts in C
 *
 *        Version:  1.0
 *        Created:  03/17/2015 02:31:47 PM
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
#include <unistd.h>
#include <string.h>

    void
usage (  )
{
    printf("opts: [mitm|flood] -i interface -a hostA -b hostB");
    return ;
}		/* -----  end of function usage  ----- */
    int
main ( int argc, char *argv[] )
{
    char * operation = NULL;
    char * interface = NULL;
    char * hostA = NULL;
    char * hostB = NULL;

    int c;

    while((c = getopt(argc,argv,"m:i:a:b:")) != -1){
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
                break;
            case 'b':
                hostB = optarg;
                break;
            case '?':
                fprintf(stderr,"Option %c requires an argument",optopt);
                abort();
        }
    }
    printf("Arguments are :");
    printf("\n\tMethod : %s",operation);
    printf("\n\tInterface : %s",interface);
    printf("\n\thostA : %s",hostA);
    printf("\n\thostB : %s\n",hostB);

    return EXIT_SUCCESS;
}				/* ----------  end of function main  ---------- */
