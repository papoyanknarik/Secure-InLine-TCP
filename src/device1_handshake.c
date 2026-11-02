#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

#define PORT 6000
#define KEY_SIZE 32

int send_all(int fd, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

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
    int sock;
    struct sockaddr_in server;
    EVP_PKEY_CTX *ctx = NULL, *derive_ctx = NULL;
    EVP_PKEY *device1_key = NULL, *peer_key = NULL;

    unsigned char public_key[KEY_SIZE];
    unsigned char peer_public_key[KEY_SIZE];
    unsigned char shared_secret[KEY_SIZE];
    unsigned char salt[32];
    unsigned char session_key[SESSION_KEY_LENGTH];
    unsigned char confirmation_key[CONFIRM_KEY_SIZE];

    size_t public_len = KEY_SIZE;
    size_t secret_len = KEY_SIZE;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);

    if (!ctx ||
        EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &device1_key) <= 0 ||
        EVP_PKEY_get_raw_public_key(device1_key, public_key,
                                    &public_len) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_PKEY_CTX_free(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr("10.0.2.2");

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

    printf("Device1: Connected to Device2!\n");

    if (send_all(sock, public_key, KEY_SIZE) < 0 ||
        recv_all(sock, peer_public_key, KEY_SIZE) < 0) {
        fprintf(stderr, "Public key exchange failed!\n");
        close(sock);
        return 1;
    }

    printf("Device1: Public keys exchanged!\n");

    peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, NULL, peer_public_key, KEY_SIZE);

    derive_ctx = EVP_PKEY_CTX_new(device1_key, NULL);

    if (!peer_key || !derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(derive_ctx, shared_secret, &secret_len) <= 0 ||
        secret_len != KEY_SIZE) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Device1: Shared secret derived successfully!\n");

    if (recv_all(sock, salt, sizeof(salt)) < 0) {
        fprintf(stderr, "Salt receive failed!\n");
        return 1;
    }

    if (!generate_session_key(shared_secret, secret_len,
                              salt, sizeof(salt), session_key)) {
        fprintf(stderr, "HKDF failed!\n");
        return 1;
    }

    printf("Device1: Session key derived successfully!\n");

    if (!derive_confirmation_key(shared_secret, secret_len,
                                 salt, sizeof(salt), confirmation_key)) {
        fprintf(stderr, "Confirmation key derivation failed!\n");
        return 1;
    }

    unsigned char transcript[96];
    memcpy(transcript, public_key, KEY_SIZE);
    memcpy(transcript + KEY_SIZE, peer_public_key, KEY_SIZE);
    memcpy(transcript + 2 * KEY_SIZE, salt, KEY_SIZE);

    const unsigned char label[] = "Device2 confirmation";
    unsigned char data[sizeof(transcript) + sizeof(label) - 1];
    unsigned char expected_hmac[HMAC_SIZE];
    unsigned char received_hmac[HMAC_SIZE];

    memcpy(data, transcript, sizeof(transcript));
    memcpy(data + sizeof(transcript), label, sizeof(label) - 1);

    if (!compute_hmac(confirmation_key, sizeof(confirmation_key),
                      data, sizeof(data), expected_hmac)) {
        fprintf(stderr, "HMAC generation failed!\n");
        return 1;
    }

    if (recv_all(sock, received_hmac, sizeof(received_hmac)) < 0) {
        fprintf(stderr, "HMAC receive failed!\n");
        return 1;
    }

    if (CRYPTO_memcmp(expected_hmac, received_hmac, HMAC_SIZE) != 0) {
        fprintf(stderr, "ERROR: Key confirmation failed!\n");
        return 1;
    }

    printf("SUCCESS: Device2 key confirmation verified!\n");

    const unsigned char device1_label[] = "Device1 confirmation";
    unsigned char device1_data[
        sizeof(transcript) + sizeof(device1_label) - 1
    ];
    unsigned char device1_hmac[HMAC_SIZE];

    memcpy(device1_data, transcript, sizeof(transcript));
    memcpy(device1_data + sizeof(transcript),
           device1_label, sizeof(device1_label) - 1);

    if (!compute_hmac(confirmation_key, sizeof(confirmation_key),
                      device1_data, sizeof(device1_data), device1_hmac)) {
        fprintf(stderr, "Device1 HMAC generation failed!\n");
        return 1;
    }

    if (send_all(sock, device1_hmac, sizeof(device1_hmac)) < 0) {
        fprintf(stderr, "Device1 HMAC send failed!\n");
        return 1;
    }

    printf("Device1: Confirmation HMAC sent!\n");

    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(session_key, sizeof(session_key));
    OPENSSL_cleanse(confirmation_key, sizeof(confirmation_key));
    OPENSSL_cleanse(expected_hmac, sizeof(expected_hmac));
    OPENSSL_cleanse(received_hmac, sizeof(received_hmac));
    OPENSSL_cleanse(device1_hmac, sizeof(device1_hmac));

    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(device1_key);
    close(sock);

    return 0;
}

