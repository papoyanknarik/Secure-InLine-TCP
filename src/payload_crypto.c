
#include "payload_crypto.h"

#include <stdint.h>
#include <string.h>

int encrypt_payload(
    const unsigned char *key,
    NonceManager *manager,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *output,
    size_t output_capacity,
    size_t *output_len
) {
    if (key == NULL || manager == NULL || plaintext == NULL ||
        output == NULL || output_len == NULL)
        return 0;

    *output_len = 0;

    if (plaintext_len > SIZE_MAX - PAYLOAD_OVERHEAD)
        return 0;

    size_t required = plaintext_len + PAYLOAD_OVERHEAD;

    if (output_capacity < required)
        return 0;

    unsigned char nonce[GCM_NONCE_SIZE];

    if (nonce_manager_next(manager, nonce) == 0)
        return 0;

    unsigned char *ciphertext = output + GCM_NONCE_SIZE;
    unsigned char *tag = ciphertext + plaintext_len;

    if (!aes_gcm_encrypt(
            key, nonce, plaintext, plaintext_len, ciphertext, tag))
        return 0;

    memcpy(output, nonce, GCM_NONCE_SIZE);

    *output_len = required;
    return 1;
}

int decrypt_payload(
    const unsigned char *key,
    const unsigned char *input,
    size_t input_len,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
) {
    if (key == NULL || input == NULL || plaintext == NULL ||
        plaintext_len == NULL)
        return 0;

    *plaintext_len = 0;

    if (input_len < PAYLOAD_OVERHEAD)
        return 0;

    size_t encrypted_len = input_len - PAYLOAD_OVERHEAD;

    if (plaintext_capacity < encrypted_len)
        return 0;

    const unsigned char *nonce = input;
    const unsigned char *ciphertext = input + GCM_NONCE_SIZE;
    const unsigned char *tag = input + GCM_NONCE_SIZE + encrypted_len;

    if (aes_gcm_decrypt(
            key, nonce, ciphertext, encrypted_len, tag, plaintext) == 0)
        return 0;

    *plaintext_len = encrypted_len;
    return 1;
}
