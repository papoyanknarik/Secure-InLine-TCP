
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "nonce_manager.h"

int main(void) {
    NonceManager nm;

    unsigned char prefix[4] = {
        0x12, 0x34, 0x56, 0x78
    };

    unsigned char first_nonce[GCM_NONCE_SIZE];
    unsigned char second_nonce[GCM_NONCE_SIZE];

    if (nonce_manager_init(&nm, prefix) == 0)
        return 1;

    if (nonce_manager_next(&nm, first_nonce) == 0 ||
        nonce_manager_next(&nm, second_nonce) == 0)
        return 1;

    if (memcmp(first_nonce, second_nonce, GCM_NONCE_SIZE) == 0) {
        fprintf(stderr, "ERROR: Nonce values are identical!\n");
        return 1;
    }

    printf("SUCCESS: Generated nonces are different!\n");

    nm.counter = UINT64_MAX;

    if (nonce_manager_next(&nm, first_nonce) == 0)
        return 1;

    if (nonce_manager_next(&nm, second_nonce) != 0) {
        fprintf(stderr, "ERROR: Counter limit was not detected!\n");
        return 1;
    }

    printf("SUCCESS: Counter limit detected correctly!\n");

    return 0;
}
