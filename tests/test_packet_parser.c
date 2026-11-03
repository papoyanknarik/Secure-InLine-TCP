#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "packet_parser.h"

int main(void) {
    unsigned char buffer[128] = {0};
    const char text[] = "Hello TCP";

    size_t data_size = strlen(text);
    size_t ip_size = sizeof(struct iphdr);
    size_t tcp_size = sizeof(struct tcphdr);
    size_t packet_size = ip_size + tcp_size + data_size;

    struct iphdr *ip_header = (struct iphdr *)buffer;

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->tot_len = htons((uint16_t)packet_size);
    ip_header->saddr = inet_addr("10.0.1.1");
    ip_header->daddr = inet_addr("10.0.3.2");

    struct tcphdr *tcp_header =
        (struct tcphdr *)(buffer + ip_size);

    tcp_header->doff = 5;
    tcp_header->source = htons(12345);
    tcp_header->dest = htons(5000);

    memcpy(buffer + ip_size + tcp_size, text, data_size);

    ParsedPacket packet_info;

    if (parse_tcp_packet(buffer, packet_size, &packet_info) == 0) {
        fprintf(stderr, "ERROR: TCP packet parsing failed!\n");
        return 1;
    }

    printf("SUCCESS: TCP packet parsed!\n");

    if (packet_info.ip_header_len != ip_size ||
        packet_info.tcp_header_len != tcp_size ||
        packet_info.payload_len != data_size ||
        packet_info.source_port != 12345 ||
        packet_info.destination_port != 5000) {
        fprintf(stderr, "ERROR: Packet information is incorrect!\n");
        return 1;
    }

    printf("SUCCESS: Packet headers and ports checked!\n");

    if (memcmp(packet_info.payload, text, data_size) != 0) {
        fprintf(stderr, "ERROR: Payload verification failed!\n");
        return 1;
    }

    printf("SUCCESS: Payload verified!\n");

    if (parse_tcp_packet(buffer, 10, &packet_info) != 0) {
        fprintf(stderr, "ERROR: Invalid packet was accepted!\n");
        return 1;
    }

    printf("SUCCESS: Incomplete packet rejected!\n");

    return 0;
}
