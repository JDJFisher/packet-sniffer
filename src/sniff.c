#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"
#include "blacklist.h"

static pcap_t *pcap_handle;

// Application main sniffing loop
void sniff(char *interface, int verbose)
{
    // Open network interface for packet capture
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
    if (pcap_handle == NULL)
    {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    printf("%s opened for capture\n", interface);

    // Override signal catcher
    if (signal(SIGINT, signal_catcher) == SIG_ERR)
    {
        perror("Failed to setup SIGINT signal catcher");
        exit(EXIT_FAILURE);
    }

    // Load blacklist of host names
    blacklist_load("./hosts.txt", verbose);
    // Create struct to store statistics on packet traffic
    traffic_stat_init();

    // Setup thread pool dispatch
    dispatch* d;
    if (!verbose)
    {
        d = dispatch_init(verbose);
        if (d == NULL)
        {
            perror("Failed to initialise thread pool");
            exit(EXIT_FAILURE);
        }
    }

    // Capture an unbounded number of packets over the network interface and send them to the handler
    printf("RUNNING\n");
    pcap_loop(pcap_handle, 0, verbose ? debug_handler : packet_handler, (u_char*)d);

    // Clean-up
    printf("\nEXITING\n");

    if (!verbose)
    {   // Destroy the thread pool
        dispatch_destroy(d);
    }

    pcap_close(pcap_handle); // Close the interface connection
    report();                // Issue the report
    blacklist_destroy();     // Free the blacklist
    traffic_stat_destroy();  // Free traffic statistics
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *data)
{
    // Box raw packet data with length and send it to dispatch
    dispatch* d = (dispatch*) args;
    packet p = {(packet_data)data, header->len};

    dispatch_packet(d, p);
}

void debug_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *data)
{
    // Box raw packet data with length
    packet p = {(packet_data)data, header->len};

    dump(p);
    analyse(p);
}

void signal_catcher(int signal)
{
    // Stop sniffing for packets on the interface
    pcap_breakloop(pcap_handle);
}

void print_ip(u_int32_t ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8 ) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void print_mac(u_char mac[])
{
    unsigned int i;
    for (i = 0; i < 6; ++i)
    {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

// Dump packet information for debugging
void dump(packet p)
{
    static size_t packet_count = 0;

    eth_header eth_head = *(eth_header*) p.data;
    packet_data data = p.data + sizeof(eth_header);
    size_t data_bytes = p.length - sizeof(eth_header);

    printf("\n========== PACKET %06lu ==========\n", packet_count++);

    printf("Source MAC:       ");
    print_mac(eth_head.ether_shost);
    printf("\nDestination MAC:  ");
    print_mac(eth_head.ether_dhost);

    switch (ntohs(eth_head.ether_type))
    {
        case ETHERTYPE_IP:;
            // Seperate both the IP and TCP headers from the packets payload
            ip_header ip_head = *(ip_header*) data;
            data += sizeof(ip_header);
            tcp_header tcp_head = *(tcp_header*) data;
            data += sizeof(tcp_header);
            data_bytes -= (sizeof(ip_header) + sizeof(eth_header));

            printf("\nPacket type:      TCP/IP");
            printf("\nSource IP:        ");
            print_ip(ntohl(ip_head.saddr));
            printf("\nDestination IP:   ");
            print_ip(ntohl(ip_head.daddr));
            printf("\nSource Port:      %d", ntohs(tcp_head.source));
            printf("\nDestination Port: %d", ntohs(tcp_head.dest));

            break;
        case ETHERTYPE_ARP:;
            // Cast the ARP packet into the appropiatly formatted struct
            arp_message arp_mes = *(arp_message*) data;
            data += sizeof(arp_message);
            data_bytes -= sizeof(arp_message);
            printf("\nPacket type:      ARP");
            printf("\nARP operation:    %d", ntohs(arp_mes.ar_op));

            break;
        default:;
            printf("\nPacket type:      UNKNOWN");
            break;
    }

    // Dump payload in ascii form
    if(data_bytes > 0)
    {
        printf("\n============= PAYLOAD =============\n");

        unsigned int i;
        for (i = 0; i < data_bytes; i++)
        {
            char byte = data[i];
            if (byte > 31 && byte < 127)
            {   // Byte is in printable ascii range
                printf("%c", byte);
            }
            else
            {
                printf(".");
            }

            // Start new line after printing 35 bytes
            if (i % 35 == 0) printf("\n");
        }
    }

    printf("\n===================================\n\n");
}
