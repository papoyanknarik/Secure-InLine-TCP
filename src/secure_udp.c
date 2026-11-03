#include "payload_crypto.h"
#include "replay_protection.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT_NUMBER 9001
#define DATA_LIMIT 2048

static int read_key(unsigned char key[AES_KEY_SIZE]) {
    FILE *fp = fopen("secrets/tunnel.key", "rb");

    if (fp == NULL) {
        perror("fopen");
        return 0;
    }

    size_t bytes = fread(key, 1, AES_KEY_SIZE, fp);
    int remaining = fgetc(fp);
    int failed = ferror(fp);

    fclose(fp);

    return bytes == AES_KEY_SIZE && remaining == EOF && !failed;
}

static uint64_t get_sequence(const unsigned char *data) {
    uint64_t value = 0;

    for (int i = 4; i < GCM_NONCE_SIZE; i++) {
        value = (value << 8) | data[i];
    }

    return value;
}

static int receive_messages(const unsigned char key[AES_KEY_SIZE]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in local_addr = {0};
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(PORT_NUMBER);

    if (inet_pton(AF_INET, "10.0.2.2", &local_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid receiver address\n");
        close(sock);
        return 1;
    }

    if (bind(sock, (struct sockaddr *)&local_addr,
             sizeof(local_addr)) == -1) {
        perror("bind");
        close(sock);
        return 1;
    }

    ReplayWindow replay_state = {0};
    unsigned char current_prefix[4] = {0};
    int prefix_ready = 0;

    printf("Secure UDP receiver is active...\n");
    fflush(stdout);

    while (1) {
        unsigned char ciphertext[DATA_LIMIT];
        unsigned char plaintext[DATA_LIMIT];

        ssize_t received = recvfrom(
            sock,
            ciphertext,
            sizeof(ciphertext),
            0,
            NULL,
            NULL
        );

        if (received == -1) {
            perror("recvfrom");
            close(sock);
            return 1;
        }

        if ((size_t)received < PAYLOAD_OVERHEAD) {
            printf("Packet size is invalid\n");
            continue;
        }

        size_t plaintext_size = 0;

        int status = decrypt_payload(
            key,
            ciphertext,
            (size_t)received,
            plaintext,
            sizeof(plaintext) - 1,
            &plaintext_size
        );

        if (status != 1) {
            printf("Packet authentication rejected\n");
            continue;
        }

        if (!prefix_ready) {
            memcpy(current_prefix, ciphertext, sizeof(current_prefix));
            prefix_ready = 1;
        }

        if (memcmp(current_prefix, ciphertext, sizeof(current_prefix)) != 0) {
            printf("Packet from another session rejected\n");
            continue;
        }

        uint64_t sequence = get_sequence(ciphertext);

        if (replay_accept(&replay_state, sequence) != 1) {
            printf("Duplicate or old packet: %llu\n",
                   (unsigned long long)sequence);
            continue;
        }

        plaintext[plaintext_size] = '\0';

        printf("Received [%llu]: %s\n",
               (unsigned long long)sequence,
               plaintext);

        fflush(stdout);
    }
}

static int send_messages(const unsigned char key[AES_KEY_SIZE]) {
    const unsigned char message[] = "Hello securely from Device1";
    unsigned char random_prefix[4];

    if (RAND_bytes(random_prefix, sizeof(random_prefix)) != 1) {
        fprintf(stderr, "Random prefix creation failed\n");
        return 1;
    }

    NonceManager nonce_state = {0};

    if (nonce_manager_init(&nonce_state, random_prefix) != 1) {
        fprintf(stderr, "Nonce initialization error\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in remote_addr = {0};
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(PORT_NUMBER);

    if (inet_pton(AF_INET, "10.0.2.2", &remote_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid destination address\n");
        close(sock);
        return 1;
    }

    for (int index = 0; index < 3; index++) {
        unsigned char ciphertext[DATA_LIMIT];
        size_t ciphertext_size = 0;

        if (encrypt_payload(
            key,
            &nonce_state,
            message,
            sizeof(message) - 1,
            ciphertext,
            sizeof(ciphertext),
            &ciphertext_size
        ) != 1) {
            fprintf(stderr, "Encryption error\n");
            close(sock);
            return 1;
        }

        int repetitions = index == 0 ? 2 : 1;

        for (int copy = 0; copy < repetitions; copy++) {
            ssize_t sent = sendto(
                sock,
                ciphertext,
                ciphertext_size,
                0,
                (struct sockaddr *)&remote_addr,
                sizeof(remote_addr)
            );

            if (sent != (ssize_t)ciphertext_size) {
                perror("sendto");
                close(sock);
                return 1;
            }
        }

        printf("Packet %d transmitted (%d copies)\n",
               index, repetitions);
    }

    close(sock);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s send|receive\n", argv[0]);
        return 1;
    }

    unsigned char secret_key[AES_KEY_SIZE];

    if (!read_key(secret_key)) {
        fprintf(stderr, "Encryption key could not be loaded\n");
        return 1;
    }

    if (strcmp(argv[1], "send") == 0) {
        return send_messages(secret_key);
    }

    if (strcmp(argv[1], "receive") == 0) {
        return receive_messages(secret_key);
    }

    fprintf(stderr, "Unsupported mode\n");
    return 1;
}
