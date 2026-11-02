
#include <stdio.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

int main(void) {
    unsigned char hmac1[HMAC_SIZE], hmac2[HMAC_SIZE];

    const unsigned char key[] = "test-key";
    const unsigned char data[] = "Device1-Device2";

    for (int i = 0; i < 2; i++) {
        unsigned char *hmac = (i == 0) ? hmac1 : hmac2;

        if (!compute_hmac(key, sizeof(key) - 1,
                          data, sizeof(data) - 1, hmac)) {
            printf("HMAC failed!\n");
            return 1;
        }
    }

    if (CRYPTO_memcmp(hmac1, hmac2, HMAC_SIZE) == 0)
        printf("SUCCESS: HMAC values match!\n");
    else {
        printf("HMAC mismatch!\n");
        return 1;
    }

    OPENSSL_cleanse(hmac1, sizeof(hmac1));
    OPENSSL_cleanse(hmac2, sizeof(hmac2));

    return 0;
}
