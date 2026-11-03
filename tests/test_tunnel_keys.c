#include "tunnel_keys.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char key_one[SESSION_KEY_SIZE];
    unsigned char key_two[SESSION_KEY_SIZE];

    for (size_t i = 0; i < SESSION_KEY_SIZE; ++i) {
        key_one[i] = (unsigned char)i;
        key_two[i] = (unsigned char)(i + 1);
    }

    unsigned char d1_to_d2[TUNNEL_KEY_SIZE];
    unsigned char d2_to_d1[TUNNEL_KEY_SIZE];
    unsigned char repeated_d1[TUNNEL_KEY_SIZE];
    unsigned char repeated_d2[TUNNEL_KEY_SIZE];
    unsigned char changed_d1[TUNNEL_KEY_SIZE];
    unsigned char changed_d2[TUNNEL_KEY_SIZE];

    assert(derive_tunnel_keys(key_one, d1_to_d2, d2_to_d1));

    assert(memcmp(d1_to_d2, d2_to_d1, TUNNEL_KEY_SIZE) != 0);

    assert(derive_tunnel_keys(key_one, repeated_d1, repeated_d2));

    assert(memcmp(d1_to_d2, repeated_d1, TUNNEL_KEY_SIZE) == 0);
    assert(memcmp(d2_to_d1, repeated_d2, TUNNEL_KEY_SIZE) == 0);

    assert(derive_tunnel_keys(key_two, changed_d1, changed_d2));

    assert(memcmp(d1_to_d2, changed_d1, TUNNEL_KEY_SIZE) != 0);
    assert(memcmp(d2_to_d1, changed_d2, TUNNEL_KEY_SIZE) != 0);

    printf("Directional tunnel key tests passed\n");

    return 0;
}
