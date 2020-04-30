#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <time.h>
#include "sniff.h"
#include "arrayset.h"

typedef struct ether_header eth_header;
typedef struct iphdr ip_header;
typedef struct tcphdr tcp_header;
typedef struct arphdr arp_message;

typedef struct traffic_stat
{
    unsigned int syn_count;
    arrayset syn_senders;
    struct timeval first_syn_time;
    struct timeval last_syn_time;
    unsigned int arp_response_count;
    unsigned int bl_violations;
    pthread_mutex_t syn_lock;
    pthread_mutex_t arp_lock;
    pthread_mutex_t bl_lock;
} traffic_stat;

void analyse(packet p);
void syn_flood_check(ip_header ip_h, tcp_header tcp_h);
void arp_poison_check(arp_message arp_m);
void blacklist_url_check(tcp_header tcp_h, packet_data data);
void report();
char* find_host_name(const char* hhtpMessage);
void traffic_stat_init();
void traffic_stat_destroy();

#endif
