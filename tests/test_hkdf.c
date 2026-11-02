
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

int main(void) {
    unsigned char secret[32], salt[32];
    unsigned char key1[SESSION_KEY_LENGTH];
    unsigned char key2[SESSION_KEY_LENGTH];

    for (int i = 0; i < 32; i++) {
        secret[i] = i + 1;
        salt[i] = i + 50;
    }

    if (!generate_session_key(secret, 32, salt, 32, key1) ||
        !generate_session_key(secret, 32, salt, 32, key2)) {
        printf("HKDF failed!\n");
        return 1;
    }

    if (CRYPTO_memcmp(key1, key2, SESSION_KEY_LENGTH) == 0)
        printf("SUCCESS: Keys match!\n");
    else
        printf("ERROR: Keys do not match!\n");

    OPENSSL_cleanse(key1, sizeof(key1));
    OPENSSL_cleanse(key2, sizeof(key2));

    return 0;
}

