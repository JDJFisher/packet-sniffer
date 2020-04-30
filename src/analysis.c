#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>

#include "analysis.h"
#include "arrayset.h"
#include "blacklist.h"

#define HTTP_PORT 80

static traffic_stat ts;

void analyse(packet p)
{
    eth_header eth_head = *(eth_header*) p.data;
    packet_data eth_body = p.data + sizeof(eth_header);

    // Fork the analysis depending on the packet structure
    switch (ntohs(eth_head.ether_type))
    {
        case ETHERTYPE_IP:;
            // Seperate both the IP and TCP headers from the packets payload
            ip_header ip_head = *(ip_header*) eth_body;
            packet_data ip_body = eth_body + sizeof(ip_header);
            tcp_header tcp_head = *(tcp_header*) ip_body;
            packet_data payload = ip_body + sizeof(tcp_header);

            syn_flood_check(ip_head, tcp_head);
            blacklist_url_check(tcp_head, payload);
            break;
        case ETHERTYPE_ARP:;
            // Cast the packet into the ARP message struct
            arp_message arp_mes = *(arp_message*) eth_body;

            // Determine whether the message is malicious
            arp_poison_check(arp_mes);
            break;
        default:;
    }
}

void syn_flood_check(ip_header ip_h, tcp_header tcp_h)
{
    // Filter packets with only the SYN flag set
    if(tcp_h.th_flags == TH_SYN)
    {
        // Get the current time
        struct timeval tv;
        gettimeofday(&tv, NULL);

        // Ensure SYN statistics are updated safely
        pthread_mutex_lock(&ts.syn_lock);

        // If this is the first SYN packet store the time
        if(ts.syn_count == 0) ts.first_syn_time = tv;

        // Update SYN packet statistics
        ts.last_syn_time = tv;
        ts.syn_count++;
        arrayset_add(&ts.syn_senders, ip_h.saddr);

        pthread_mutex_unlock(&ts.syn_lock);
    }
}

void arp_poison_check(arp_message arp_m)
{
    if (ntohs(arp_m.ar_op) == ARPOP_REPLY)
    {   // Filter only ARP response messages
        pthread_mutex_lock(&ts.arp_lock);
        // Safely increment ARP response count
        ts.arp_response_count++;
        pthread_mutex_unlock(&ts.arp_lock);
    }
}

void blacklist_url_check(tcp_header tcp_h, packet_data data)
{
    // Filter only out-bound HTTP traffic (Port 80)
    if (ntohs(tcp_h.dest) == HTTP_PORT)
    {
        // Extract host name from HTTP message
        char* host = find_host_name(data);
        // Return if the message is not a request (Not POST or GET)
        if (host == NULL) return;

        if (is_blacklisted(host))
        {   // The host name is blacklisted
            pthread_mutex_lock(&ts.bl_lock);
            // Safely increment violation count
            ts.bl_violations++;
            pthread_mutex_unlock(&ts.bl_lock);
        }

        free(host);
    }
}

void report()
{
    // Determine the number of seconds between recieving the first and last SYN packet
    float syn_interval = ts.last_syn_time.tv_sec - ts.first_syn_time.tv_sec;
    syn_interval += (ts.last_syn_time.tv_usec - ts.first_syn_time.tv_usec) / 1000000.0;

    // Calculate SYN flood conditions
    float unqiue_syn_rate = ts.syn_senders.size / syn_interval;
    float unqiue_syn_ratio = ts.syn_senders.size / (float)ts.syn_count;

    // Format report
    printf("\nIntrusion Detection Report:\n");

    if (unqiue_syn_rate > 100 && unqiue_syn_ratio >= 0.9)
    {   // SYN statistics suggest a SYN flood is possible
        printf("SYN flood attack possible\n");
        printf("%d SYN packets detected from %lu IP addresses in %f seconds\n", ts.syn_count, arrayset_size(&ts.syn_senders), syn_interval);
    }
    else
    {
        printf("No SYN flooding attack detected\n");
    }

    printf("%d ARP responses (cache poisoning)\n", ts.arp_response_count);
    printf("%d URL Blacklist violations\n\n", ts.bl_violations);
}

char* find_host_name(const char* hhtpMessage)
{
    const char* tag = "Host: ";
    // Find pointer of substring beginning with the host tag
    char* sub_str = strstr(hhtpMessage, tag);
    // No such substring exists
    if(sub_str == NULL) return NULL;

    // Move pointer forward to exclude host tag
    sub_str += strlen(tag);
    // Determine length of host name
    int host_length = strlen(sub_str) - strlen(strchr(sub_str, '\n')) - 1;

    // Copy host name into a new string
    char* host = calloc(host_length + 1, sizeof(char));
    strncpy(host, sub_str, host_length);

    return host;
}

void traffic_stat_init()
{
    ts.syn_count = 0;
    ts.arp_response_count = 0;
    ts.bl_violations = 0;

    // Create set for SYN source IPs
    arrayset_init(&ts.syn_senders);

    // Initialise traffic stat mutex locks
    pthread_mutex_init(&ts.syn_lock, NULL);
    pthread_mutex_init(&ts.arp_lock, NULL);
    pthread_mutex_init(&ts.bl_lock,  NULL);
}

void traffic_stat_destroy()
{
    // Destroy IP set
    arrayset_destroy(&ts.syn_senders);

    // Destroy traffic stat mutex locks
    pthread_mutex_destroy(&ts.syn_lock);
    pthread_mutex_destroy(&ts.arp_lock);
    pthread_mutex_destroy(&ts.bl_lock);
}
