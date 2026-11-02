
#include <stdio.h>
#include <openssl/crypto.h>
#include "crypto_utils.h"

int main(void) {
    unsigned char psk[PSK_SIZE];

    if (load_psk("secrets/device_psk.hex", psk) == 0) {
        printf("ERROR: Could not load PSK.\n");
        return 1;
    }

    printf("PSK was loaded successfully!\n");

    OPENSSL_cleanse(psk, PSK_SIZE);

    return 0;
}
