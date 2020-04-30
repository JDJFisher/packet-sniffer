#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <pcap.h>

typedef const char* packet_data;

typedef struct packet
{
    packet_data data;
    size_t length;
} packet;

void sniff(char *interface, int verbose);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *data);
void debug_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *data);
void signal_catcher(int signal);
void dump(packet p);

#endif
