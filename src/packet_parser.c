#include "packet_parser.h"

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

int parse_tcp_packet(
    const unsigned char *data,
    size_t length,
    ParsedPacket *parsed
) {
    if (data == NULL || parsed == NULL ||
        length < sizeof(struct iphdr)) {
        return 0;
    }

    memset(parsed, 0, sizeof(*parsed));

    const struct iphdr *ip_header =
        (const struct iphdr *)data;

    if (ip_header->version != 4 ||
        ip_header->protocol != IPPROTO_TCP) {
        return 0;
    }

    size_t ip_size = ip_header->ihl * 4U;

    if (ip_size < sizeof(struct iphdr) || ip_size > length) {
        return 0;
    }

    size_t packet_size = ntohs(ip_header->tot_len);

    if (packet_size < ip_size + sizeof(struct tcphdr) ||
        packet_size > length) {
        return 0;
    }

    if ((ntohs(ip_header->frag_off) & 0x3FFF) != 0) {
        return 0;
    }

    const struct tcphdr *tcp_header =
        (const struct tcphdr *)(data + ip_size);

    size_t tcp_size = tcp_header->doff * 4U;

    if (tcp_size < sizeof(struct tcphdr) ||
        tcp_size > packet_size - ip_size) {
        return 0;
    }

    parsed->ip_header = data;
    parsed->ip_header_len = ip_size;

    parsed->tcp_header = data + ip_size;
    parsed->tcp_header_len = tcp_size;

    parsed->payload = data + ip_size + tcp_size;
    parsed->payload_len = packet_size - ip_size - tcp_size;

    parsed->source_ip = ip_header->saddr;
    parsed->destination_ip = ip_header->daddr;

    parsed->source_port = ntohs(tcp_header->source);
    parsed->destination_port = ntohs(tcp_header->dest);

    return 1;
}
