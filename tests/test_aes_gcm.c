
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "aes_gcm.h"

int main(void) {
    unsigned char key[AES_KEY_SIZE];
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];

    const unsigned char text[] = "Message from PC1!";
    unsigned char encrypted[sizeof(text)];
    unsigned char original[sizeof(text)];

    if (RAND_bytes(key, sizeof(key)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1) {
        printf("ERROR: Random values could not be generated!\n");
        return 1;
    }

    int encrypted_ok = aes_gcm_encrypt(
        key, nonce, text, sizeof(text), encrypted, tag
    );

    if (!encrypted_ok) {
        printf("ERROR: Encryption process failed!\n");
        return 1;
    }

    printf("SUCCESS: Message encrypted!\n");

    int decrypted_ok = aes_gcm_decrypt(
        key, nonce, encrypted, sizeof(encrypted), tag, original
    );

    if (!decrypted_ok) {
        printf("ERROR: Decryption process failed!\n");
        return 1;
    }

    if (CRYPTO_memcmp(text, original, sizeof(text)) != 0) {
        printf("ERROR: The original message does not match!\n");
        return 1;
    }

    printf("SUCCESS: Original message recovered!\n");

    tag[0] ^= 1;

    if (aes_gcm_decrypt(
            key, nonce, encrypted, sizeof(encrypted), tag, original)) {
        printf("ERROR: Incorrect tag was accepted!\n");
        return 1;
    }

    printf("SUCCESS: Authentication check rejected the wrong tag!\n");

    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(original, sizeof(original));

    return 0;
}
