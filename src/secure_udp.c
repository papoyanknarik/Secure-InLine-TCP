#include "payload_crypto.h"

#include <arpa/inet.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT_NUMBER 9001
#define DATA_SIZE 2048

static int read_secret(unsigned char key[AES_KEY_SIZE]) {
    FILE *fp = fopen("secrets/tunnel.key", "rb");

    if (fp == NULL) {
        perror("fopen");
        return 0;
    }

    size_t size = fread(key, 1, AES_KEY_SIZE, fp);
    int remaining = fgetc(fp);
    int failed = ferror(fp);

    fclose(fp);

    return size == AES_KEY_SIZE && remaining == EOF && !failed;
}

static int receive_data(const unsigned char key[AES_KEY_SIZE]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons(PORT_NUMBER);

    if (inet_pton(AF_INET, "10.0.2.2", &local.sin_addr) != 1) {
        fprintf(stderr, "Invalid receiver address\n");
        close(sock);
        return 1;
    }

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) == -1) {
        perror("bind");
        close(sock);
        return 1;
    }

    unsigned char ciphertext[DATA_SIZE];
    unsigned char plaintext[DATA_SIZE];

    printf("Waiting for secure UDP data...\n");
    fflush(stdout);

    ssize_t size = recvfrom(
        sock,
        ciphertext,
        sizeof(ciphertext),
        0,
        NULL,
        NULL
    );

    if (size == -1) {
        perror("recvfrom");
        close(sock);
        return 1;
    }

    size_t plaintext_size = 0;

    int status = decrypt_payload(
        key,
        ciphertext,
        (size_t)size,
        plaintext,
        sizeof(plaintext) - 1,
        &plaintext_size
    );

    if (status != 1) {
        fprintf(stderr, "Message verification failed\n");
        close(sock);
        return 1;
    }

    plaintext[plaintext_size] = '\0';

    printf("Received data size: %zd bytes\n", size);
    printf("Verified plaintext: %s\n", plaintext);

    close(sock);
    return 0;
}

static int send_data(const unsigned char key[AES_KEY_SIZE]) {
    const unsigned char text[] = "Hello securely from Device1";
    unsigned char random_prefix[4];

    if (RAND_bytes(random_prefix, sizeof(random_prefix)) != 1) {
        fprintf(stderr, "Could not generate random prefix\n");
        return 1;
    }

    NonceManager nonce_handler = {0};

    if (nonce_manager_init(&nonce_handler, random_prefix) != 1) {
        fprintf(stderr, "Nonce manager initialization error\n");
        return 1;
    }

    unsigned char ciphertext[DATA_SIZE];
    size_t ciphertext_size = 0;

    if (encrypt_payload(
        key,
        &nonce_handler,
        text,
        sizeof(text) - 1,
        ciphertext,
        sizeof(ciphertext),
        &ciphertext_size
    ) != 1) {
        fprintf(stderr, "Payload encryption error\n");
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(PORT_NUMBER);

    if (inet_pton(AF_INET, "10.0.2.2", &remote.sin_addr) != 1) {
        fprintf(stderr, "Invalid destination address\n");
        close(sock);
        return 1;
    }

    ssize_t result = sendto(
        sock,
        ciphertext,
        ciphertext_size,
        0,
        (struct sockaddr *)&remote,
        sizeof(remote)
    );

    if (result != (ssize_t)ciphertext_size) {
        perror("sendto");
        close(sock);
        return 1;
    }

    printf("Secure UDP data transmitted: %zd bytes\n", result);

    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s send|receive\n", argv[0]);
        return 1;
    }

    unsigned char secret[AES_KEY_SIZE];

    if (!read_secret(secret)) {
        fprintf(stderr, "Failed to read encryption key\n");
        return 1;
    }

    if (strcmp(argv[1], "send") == 0) {
        return send_data(secret);
    }

    if (strcmp(argv[1], "receive") == 0) {
        return receive_data(secret);
    }

    fprintf(stderr, "Unknown operation\n");
    return 1;
}
