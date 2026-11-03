#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

#include "packet_parser.h"
#include "checksum.h"

static int handle_packet(
    struct nfq_q_handle *queue,
    struct nfgenmsg *message,
    struct nfq_data *packet,
    void *context
) {
    (void)message;
    (void)context;

    struct nfqnl_msg_packet_hdr *header =
        nfq_get_msg_packet_hdr(packet);

    if (header == NULL) {
        return -1;
    }

    uint32_t packet_id = ntohl(header->packet_id);

    unsigned char *packet_data = NULL;

    int packet_size = nfq_get_payload(packet, &packet_data);

    if (packet_size < 0) {
        return nfq_set_verdict(
            queue, packet_id, NF_ACCEPT, 0, NULL
        );
    }

    ParsedPacket parsed;

    if (parse_tcp_packet(packet_data, (size_t)packet_size, &parsed)) {

        char source_ip[INET_ADDRSTRLEN];
        char destination_ip[INET_ADDRSTRLEN];

        struct in_addr source;
        struct in_addr destination;

        source.s_addr = parsed.source_ip;
        destination.s_addr = parsed.destination_ip;

        inet_ntop(AF_INET, &source, source_ip, sizeof(source_ip));

        inet_ntop(AF_INET, &destination,
                  destination_ip, sizeof(destination_ip));

        printf("Packet ID: %u\n", packet_id);

        printf("Source: %s:%u\n",
               source_ip, parsed.source_port);

        printf("Destination: %s:%u\n",
               destination_ip, parsed.destination_port);

        printf("TCP Payload: %zu bytes\n\n",
               parsed.payload_len);

        uint8_t packet_copy[65536];

        if ((size_t)packet_size <= sizeof(packet_copy)) {

            memcpy(packet_copy, packet_data, (size_t)packet_size);

            size_t offset =
                (size_t)(parsed.payload - packet_data);

            if (parsed.payload_len > 0 &&
                offset < (size_t)packet_size &&
                packet_copy[offset] == 'G') {

                printf("Modifying TCP payload...\n");

                packet_copy[offset] = 'H';

                struct iphdr *ip =
                    (struct iphdr *)packet_copy;

                size_t ip_header_length = (size_t)ip->ihl * 4;

                struct tcphdr *tcp =
                    (struct tcphdr *)(packet_copy + ip_header_length);

                tcp->check = 0;

                tcp->check = tcp_checksum(
                    packet_copy, (size_t)packet_size
                );

                printf("Payload modified: G -> H\n");

                printf("TCP checksum updated.\n\n");

                fflush(stdout);

                return nfq_set_verdict(
                    queue,
                    packet_id,
                    NF_ACCEPT,
                    (uint32_t)packet_size,
                    packet_copy
                );
            }

            struct iphdr *ip =
                (struct iphdr *)packet_copy;

            size_t ip_header_length = (size_t)ip->ihl * 4;

            struct tcphdr *tcp =
                (struct tcphdr *)(packet_copy + ip_header_length);

            uint16_t original_checksum = ntohs(tcp->check);

            tcp->check = 0;

            uint16_t calculated_checksum = ntohs(
                tcp_checksum(packet_copy, (size_t)packet_size)
            );

            printf("TCP checksum (packet): 0x%04x\n",
                   original_checksum);

            printf("TCP checksum (calculated): 0x%04x\n\n",
                   calculated_checksum);
        }

        fflush(stdout);
    }

    return nfq_set_verdict(
        queue, packet_id, NF_ACCEPT, 0, NULL
    );
}


int main(void) {

    struct nfq_handle *nf_handle = nfq_open();

    if (nf_handle == NULL) {
        fprintf(stderr, "Error: Cannot open NFQUEUE\n");
        return EXIT_FAILURE;
    }

    struct nfq_q_handle *nf_queue =
        nfq_create_queue(nf_handle, 0, &handle_packet, NULL);

    if (nf_queue == NULL) {
        perror("nfq_create_queue");

        fprintf(stderr, "Error: Cannot create queue\n");

        nfq_close(nf_handle);

        return EXIT_FAILURE;
    }

    if (nfq_set_mode(nf_queue, NFQNL_COPY_PACKET, 0xffff) < 0) {

        fprintf(stderr, "Error: Cannot set packet copy mode\n");

        nfq_destroy_queue(nf_queue);

        nfq_close(nf_handle);

        return EXIT_FAILURE;
    }

    int socket_fd = nfq_fd(nf_handle);

    char buffer[65536] __attribute__((aligned));

    printf("Packet modifier started...\n");

    while (1) {

        int bytes_read = recv(
            socket_fd, buffer, sizeof(buffer), 0
        );

        if (bytes_read < 0) {
            perror("recv");
            break;
        }

        nfq_handle_packet(
            nf_handle, buffer, bytes_read
        );
    }

    nfq_destroy_queue(nf_queue);

    nfq_close(nf_handle);

    return EXIT_SUCCESS;
}
