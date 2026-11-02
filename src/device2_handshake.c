
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "crypto_utils.h"

#define PORT 6000
#define KEY_SIZE 32
int recv_all(int fd, unsigned char *buf, size_t len) {
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(fd, buf + received, len - received, 0);
        if (n <= 0) return -1;
        received += (size_t)n;
    }

    return 0;
}
int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in address;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *device2_key = NULL;
    EVP_PKEY *peer_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;

    unsigned char public_key[KEY_SIZE];
    unsigned char peer_public_key[KEY_SIZE];
    unsigned char shared_secret[KEY_SIZE];

    size_t public_len = sizeof(public_key);
    size_t secret_len = sizeof(shared_secret);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (!ctx ||
        EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &device2_key) <= 0 ||
        EVP_PKEY_get_raw_public_key(
            device2_key, public_key, &public_len) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);
    address.sin_addr.s_addr = inet_addr("10.0.2.2");

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Device2: Waiting for handshake...\n");

    client_fd = accept(server_fd, NULL, NULL);

    if (client_fd < 0) {
        perror("accept");
        return 1;
    }

    printf("Device2: Device1 connected!\n");

    if (recv(client_fd, peer_public_key, KEY_SIZE,
              MSG_WAITALL) != KEY_SIZE) {
        fprintf(stderr, "Failed to receive public key\n");
        return 1;
    }

    printf("Device2: Received Device1 public key!\n");

    if (send(client_fd, public_key, KEY_SIZE, 0) != KEY_SIZE) {
        perror("Failed to send public key");
        return 1;
    }

    printf("Device2: Public key sent!\n");

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, peer_public_key, KEY_SIZE);

    derive_ctx = EVP_PKEY_CTX_new(device2_key, NULL);

    if (!peer_key || !derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Device2: Shared secret derived successfully!\n");

    unsigned char salt[32];

    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (send(client_fd, salt, sizeof(salt), 0) != sizeof(salt)) {
        perror("Failed to send salt");
        return 1;
    }

    unsigned char session_key[SESSION_KEY_LENGTH];

    if (!generate_session_key(
            shared_secret,
            secret_len,
            salt,
            sizeof(salt),
            session_key)) {
        fprintf(stderr, "HKDF failed!\n");
        return 1;
    }

    printf("Device2: Session key derived successfully!\n");

unsigned char confirmation_key[CONFIRM_KEY_SIZE];

if (!derive_confirmation_key(shared_secret, secret_len,
                             salt, sizeof(salt), confirmation_key)) {
    fprintf(stderr, "Confirmation key derivation failed!\n");
    return 1;
}

unsigned char transcript[96];
memcpy(transcript, peer_public_key, 32);
memcpy(transcript + 32, public_key, 32);
memcpy(transcript + 64, salt, 32);

const unsigned char label[] = "Device2 confirmation";
unsigned char data[sizeof(transcript) + sizeof(label) - 1];

memcpy(data, transcript, sizeof(transcript));
memcpy(data + sizeof(transcript), label, sizeof(label) - 1);

unsigned char confirmation_hmac[HMAC_SIZE];

if (!compute_hmac(confirmation_key, sizeof(confirmation_key),
                  data, sizeof(data), confirmation_hmac)) {
    fprintf(stderr, "HMAC generation failed!\n");
    return 1;
}

printf("Device2: Confirmation HMAC generated!\n");

size_t sent = 0;

while (sent < sizeof(confirmation_hmac)) {
    ssize_t n = send(client_fd, confirmation_hmac + sent,
                     sizeof(confirmation_hmac) - sent, 0);

    if (n <= 0) {
        perror("Failed to send confirmation HMAC");
        return 1;
    }

    sent += n;
}

printf("Device2: Confirmation HMAC sent!\n");
const unsigned char device1_label[] = "Device1 confirmation";
unsigned char device1_data[sizeof(transcript) + sizeof(device1_label) - 1];

memcpy(device1_data, transcript, sizeof(transcript));
memcpy(device1_data + sizeof(transcript),
       device1_label, sizeof(device1_label) - 1);

unsigned char expected_device1_hmac[HMAC_SIZE];
unsigned char received_device1_hmac[HMAC_SIZE];

if (!compute_hmac(confirmation_key, sizeof(confirmation_key),
                  device1_data, sizeof(device1_data),
                  expected_device1_hmac)) {
    fprintf(stderr, "Device1 HMAC generation failed!\n");
    return 1;
}

if (recv_all(client_fd, received_device1_hmac,
             sizeof(received_device1_hmac)) < 0) {
    fprintf(stderr, "Device1 HMAC receive failed!\n");
    return 1;
}

if (CRYPTO_memcmp(expected_device1_hmac,
                  received_device1_hmac, HMAC_SIZE) != 0) {
    fprintf(stderr, "ERROR: Device1 key confirmation failed!\n");
    return 1;
}

printf("SUCCESS: Device1 key confirmation verified!\n");

OPENSSL_cleanse(expected_device1_hmac, sizeof(expected_device1_hmac));
OPENSSL_cleanse(received_device1_hmac, sizeof(received_device1_hmac));
OPENSSL_cleanse(confirmation_key, sizeof(confirmation_key));
OPENSSL_cleanse(confirmation_hmac, sizeof(confirmation_hmac));

    OPENSSL_cleanse(session_key, sizeof(session_key));
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(device2_key);

    close(client_fd);
    close(server_fd);

    return 0;
}
