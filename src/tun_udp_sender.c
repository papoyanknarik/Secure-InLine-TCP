#include "tun_device.h"
#include "payload_crypto.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define UDP_PORT 9002
#define PACKET_SIZE 65535

int main(void) {
    unsigned char secret_key[AES_KEY_SIZE];

    FILE *fp = fopen("secrets/tunnel.key", "rb");

    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    size_t key_size = fread(secret_key, 1, AES_KEY_SIZE, fp);

    if (key_size != AES_KEY_SIZE || fgetc(fp) != EOF || ferror(fp)) {
        fprintf(stderr, "Invalid key file\n");
        fclose(fp);
        return 1;
    }

    fclose(fp);

    int tun_fd = tun_open("tun-d1");

    if (tun_fd == -1) {
        perror("tun_open");
        return 1;
    }

    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (udp_fd == -1) {
        perror("socket");
        close(tun_fd);
        return 1;
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(UDP_PORT);

    if (inet_pton(AF_INET, "10.0.2.2", &remote.sin_addr) != 1) {
        fprintf(stderr, "Invalid destination IP\n");
        close(udp_fd);
        close(tun_fd);
        return 1;
    }

    unsigned char nonce_prefix[4];

    if (RAND_bytes(nonce_prefix, sizeof(nonce_prefix)) != 1) {
        fprintf(stderr, "Nonce generation failed\n");
        close(udp_fd);
        close(tun_fd);
        return 1;
    }

    NonceManager nonce_state = {0};

    if (nonce_manager_init(&nonce_state, nonce_prefix) != 1) {
        fprintf(stderr, "Nonce manager initialization failed\n");
        close(udp_fd);
        close(tun_fd);
        return 1;
    }

    unsigned char input_packet[PACKET_SIZE];
    unsigned char output_packet[PACKET_SIZE + PAYLOAD_OVERHEAD];

    printf("TUN device tun-d1 is listening for IPv4 traffic...\n");
    fflush(stdout);

    while (1) {
        ssize_t packet_length = tun_read_packet(
            tun_fd,
            input_packet,
            sizeof(input_packet)
        );

        if (packet_length <= 0) {
            if (packet_length < 0) {
                perror("tun_read_packet");
                break;
            }
            continue;
        }

        if (packet_length < 20 || (input_packet[0] >> 4) != 4) {
            continue;
        }

        size_t output_length = 0;

        if (encrypt_payload(
            secret_key,
            &nonce_state,
            input_packet,
            (size_t)packet_length,
            output_packet,
            sizeof(output_packet),
            &output_length
        ) != 1) {
            fprintf(stderr, "Packet encryption error\n");
            break;
        }

        ssize_t bytes_sent = sendto(
            udp_fd,
            output_packet,
            output_length,
            0,
            (struct sockaddr *)&remote,
            sizeof(remote)
        );

        if (bytes_sent != (ssize_t)output_length) {
            perror("sendto");
            break;
        }

        printf("Packet forwarded: %zd bytes, encrypted size: %zu bytes\n",
               packet_length, output_length);
        fflush(stdout);
    }

    close(udp_fd);
    close(tun_fd);

    return 0;
}
