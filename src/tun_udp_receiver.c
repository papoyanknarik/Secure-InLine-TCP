#include "payload_crypto.h"
#include "replay_protection.h"
#include "tun_device.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define UDP_PORT 9002
#define MAX_PACKET_SIZE 65535

static uint64_t extract_sequence(const unsigned char *nonce) {
    uint64_t value = 0;

    for (int i = 4; i < GCM_NONCE_SIZE; ++i) {
        value = (value << 8) | nonce[i];
    }

    return value;
}

int main(void) {
    unsigned char secret[AES_KEY_SIZE];

    FILE *fp = fopen("secrets/tunnel.key", "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    size_t key_length = fread(secret, 1, AES_KEY_SIZE, fp);
    fclose(fp);

    if (key_length != AES_KEY_SIZE) {
        fprintf(stderr, "Invalid key\n");
        return 1;
    }
int tun = tun_open("tun-d2");

if (tun < 0) {
    perror("tun_open");
    return 1;
}
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in local_address = {0};
    local_address.sin_family = AF_INET;
    local_address.sin_port = htons(UDP_PORT);

    if (inet_pton(AF_INET, "10.0.2.2", &local_address.sin_addr) != 1) {
        close(socket_fd);
        return 1;
    }

    if (bind(socket_fd, (struct sockaddr *)&local_address,
             sizeof(local_address)) == -1) {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    ReplayWindow replay_window = {0};
    unsigned char current_prefix[4] = {0};
    int initialized = 0;

    unsigned char cipher_buffer[MAX_PACKET_SIZE + PAYLOAD_OVERHEAD];
    unsigned char plain_buffer[MAX_PACKET_SIZE];

    printf("Device2 is waiting for encrypted IP packets...\n");
    fflush(stdout);

    while (1) {
        ssize_t data_size = recvfrom(
            socket_fd, cipher_buffer, sizeof(cipher_buffer), 0, NULL, NULL
        );

        if (data_size < (ssize_t)PAYLOAD_OVERHEAD) {
            continue;
        }

        size_t plain_size = 0;

        if (decrypt_payload(
                secret,
                cipher_buffer,
                (size_t)data_size,
                plain_buffer,
                sizeof(plain_buffer),
                &plain_size) != 1) {
            printf("Authentication failed\n");
            fflush(stdout);
            continue;
        }

        if (!initialized) {
            memcpy(current_prefix, cipher_buffer, sizeof(current_prefix));
            initialized = 1;
        }

        if (memcmp(current_prefix, cipher_buffer, sizeof(current_prefix)) != 0) {
            printf("Different session rejected\n");
            fflush(stdout);
            continue;
        }

        uint64_t sequence = extract_sequence(cipher_buffer);

        if (replay_accept(&replay_window, sequence) != 1) {
            printf("Replay rejected: %llu\n",
                   (unsigned long long)sequence);
            fflush(stdout);
            continue;
        }

        if (plain_size < 20 || (plain_buffer[0] >> 4) != 4) {
            printf("Invalid IPv4 packet\n");
            fflush(stdout);
            continue;
        }

        printf("Decrypted IPv4 packet: %zu bytes, sequence=%llu\n",
               plain_size, (unsigned long long)sequence);
 
       fflush(stdout);
        ssize_t written = tun_write_packet(tun, plain_buffer, plain_size);

        if (written != (ssize_t)plain_size) {
            perror("tun_write_packet");
            break;
        }
printf("Packet written to tun-d2: %zd bytes\n", written);
fflush(stdout);
    }
close(tun);
    close(socket_fd);
    return 0;
}
