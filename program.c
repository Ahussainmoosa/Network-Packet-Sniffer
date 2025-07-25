#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>

int packet_count=0; //decleration acounter with int value
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {//loop foir catching pakets.
    packet_count++; // counter increment
    struct ip *ip_header = (struct ip *)(packet + 14); 
    
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
    printf("packet catched number \n",packet_count);  // print the counter
    printf("Source IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dest_ip);

    if (ip_header->ip_p == IPPROTO_TCP) {
        printf("Protocol: TCP\n");
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        printf("Protocol: UDP\n");
    } else {
        printf("Protocol: Other\n");
    }

    printf("\n");
    printf("====================================\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf); 

    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}