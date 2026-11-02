
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include "payload_crypto.h"

int main(void) {
    unsigned char key[AES_KEY_SIZE];
    unsigned char nonce_prefix[4];

    NonceManager nonce_manager;

    const unsigned char data[] = "Hello from PC1 to PC2!";

    unsigned char output[sizeof(data) + PAYLOAD_OVERHEAD];
    unsigned char result[sizeof(data)];

    size_t output_size = 0;
    size_t result_size = 0;

    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(nonce_prefix, sizeof(nonce_prefix)) != 1) {
        fprintf(stderr, "ERROR: Random generation failed!\n");
        return 1;
    }

    if (nonce_manager_init(&nonce_manager, nonce_prefix) == 0)
        return 1;

    if (encrypt_payload(
            key, &nonce_manager, data, sizeof(data),
            output, sizeof(output), &output_size) == 0) {
        fprintf(stderr, "ERROR: Payload encryption failed!\n");
        return 1;
    }

    printf("SUCCESS: Payload encryption completed!\n");

    if (decrypt_payload(
            key, output, output_size,
            result, sizeof(result), &result_size) == 0) {
        fprintf(stderr, "ERROR: Payload decryption failed!\n");
        return 1;
    }

    if (result_size != sizeof(data) ||
        memcmp(data, result, sizeof(data)) != 0) {
        fprintf(stderr, "ERROR: Decrypted data is incorrect!\n");
        return 1;
    }

    printf("SUCCESS: Decrypted data matches the original!\n");

    output[output_size - 1] ^= 0x01;

    if (decrypt_payload(
            key, output, output_size,
            result, sizeof(result), &result_size) != 0) {
        fprintf(stderr, "ERROR: Modified payload was accepted!\n");
        return 1;
    }

    printf("SUCCESS: Modified payload was rejected!\n");

    return 0;
}
