#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "sniff.h"
#include "analysis.h"
#include "arrayset.h"

// Command line options
#define OPTSTRING "vi:"
static struct option long_opts[] = {
    {"interface", optional_argument, NULL, 'i'},
    {"verbose",   optional_argument, NULL, 'v'}
};

void print_usage(char *progname)
{
    fprintf(stderr, "A Packet Sniffer/Intrusion Detection System tutorial\n");
    fprintf(stderr, "Usage: %s [OPTIONS]...\n\n", progname);
    fprintf(stderr, "\t-i [interface]\tSpecify network interface to sniff\n");
    fprintf(stderr, "\t-v\t\tEnable verbose mode. Useful for Debugging\n");
}

int main(int argc, char *argv[])
{
    // Parse command line arguments
    char* interface = "eth0";
    int verbose = 0;
    int optc;

    while ((optc = getopt_long(argc, argv, OPTSTRING, long_opts, NULL)) != EOF)
    {
        switch (optc)
        {
            case 'v':
                verbose = 1;
                break;
            case 'i':
                interface = strdup(optarg);
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    // Print out settings
    printf("%s invoked. Settings:\n", argv[0]);
    printf("\tInterface: %s\n\tVerbose: %d\n", interface, verbose);

    // Invoke Intrusion Detection System
    sniff(interface, verbose);
    free(interface);

    return 0;
}
