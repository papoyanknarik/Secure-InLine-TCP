#include "payload_crypto.h"
#include "nonce_manager.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char encryption_key[AES_KEY_SIZE];
    unsigned char invalid_key[AES_KEY_SIZE];
    unsigned char nonce_prefix[4] = {5, 10, 15, 20};

    for (size_t j = 0; j < AES_KEY_SIZE; j++) {
        encryption_key[j] = (unsigned char)(j + 10);
        invalid_key[j] = (unsigned char)(j + 20);
    }

    NonceManager nonce_state = {0};

    assert(nonce_manager_init(&nonce_state, nonce_prefix));

    const unsigned char message[] = "TCP Payload Security Check";
    size_t message_size = strlen((const char *)message);

    unsigned char cipher_a[256] = {0};
    unsigned char cipher_b[256] = {0};
    unsigned char output[256] = {0};

    size_t cipher_a_size = 0;
    size_t cipher_b_size = 0;
    size_t output_size = 0;

    /* Test encryption */
    int result = encrypt_payload(
        encryption_key,
        &nonce_state,
        message,
        message_size,
        cipher_a,
        sizeof(cipher_a),
        &cipher_a_size
    );

    assert(result == 1);
    assert(cipher_a_size == message_size + PAYLOAD_OVERHEAD);

    /* Test decryption */
    result = decrypt_payload(
        encryption_key,
        cipher_a,
        cipher_a_size,
        output,
        sizeof(output),
        &output_size
    );

    assert(result == 1);
    assert(output_size == message_size);
    assert(memcmp(output, message, message_size) == 0);

    printf("Payload encryption/decryption test: PASSED\n");

    /* Check nonce uniqueness */
    assert(encrypt_payload(
        encryption_key,
        &nonce_state,
        message,
        message_size,
        cipher_b,
        sizeof(cipher_b),
        &cipher_b_size
    ) == 1);

    assert(cipher_b_size == cipher_a_size);
    assert(memcmp(cipher_a, cipher_b, cipher_a_size) != 0);

    assert(memcmp(
        cipher_a,
        cipher_b,
        GCM_NONCE_SIZE
    ) != 0);

    printf("Nonce uniqueness test: PASSED\n");

    unsigned char modified_data[256] = {0};

    /* Modify encrypted content */
    memcpy(modified_data, cipher_a, cipher_a_size);
    modified_data[GCM_NONCE_SIZE] ^= 0x01;

    output_size = 0;

    assert(decrypt_payload(
        encryption_key,
        modified_data,
        cipher_a_size,
        output,
        sizeof(output),
        &output_size
    ) != 1);

    printf("Modified ciphertext detection: PASSED\n");

    /* Modify authentication tag */
    memcpy(modified_data, cipher_a, cipher_a_size);
    modified_data[cipher_a_size - 1] ^= 0x01;

    output_size = 0;

    assert(decrypt_payload(
        encryption_key,
        modified_data,
        cipher_a_size,
        output,
        sizeof(output),
        &output_size
    ) != 1);

    printf("Authentication tag validation: PASSED\n");

    /* Check incorrect key */
    output_size = 0;

    assert(decrypt_payload(
        invalid_key,
        cipher_a,
        cipher_a_size,
        output,
        sizeof(output),
        &output_size
    ) != 1);

    printf("Invalid key test: PASSED\n");

    /* Check insufficient payload size */
    output_size = 0;

    assert(decrypt_payload(
        encryption_key,
        cipher_a,
        GCM_NONCE_SIZE + GCM_TAG_SIZE - 1,
        output,
        sizeof(output),
        &output_size
    ) != 1);

    printf("Short payload rejection: PASSED\n");

    printf("\nAll payload security tests completed successfully.\n");

    return 0;
}
