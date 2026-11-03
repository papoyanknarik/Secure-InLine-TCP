#include "tunnel_session.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    unsigned char master_key[SESSION_KEY_SIZE];

    for (size_t i = 0; i < sizeof(master_key); i++) {
        master_key[i] = (unsigned char)i;
    }

    TunnelSession first_device = {0};
    TunnelSession second_device = {0};

    assert(tunnel_session_init(&first_device, master_key, 1));
    assert(tunnel_session_init(&second_device, master_key, 2));

    assert(first_device.initialized);
    assert(second_device.initialized);

    assert(memcmp(
        first_device.send_key,
        second_device.receive_key,
        TUNNEL_KEY_SIZE
    ) == 0);

    assert(memcmp(
        second_device.send_key,
        first_device.receive_key,
        TUNNEL_KEY_SIZE
    ) == 0);

    assert(memcmp(
        first_device.send_key,
        first_device.receive_key,
        TUNNEL_KEY_SIZE
    ) != 0);

    unsigned char first_nonce[GCM_NONCE_SIZE];
    unsigned char second_nonce[GCM_NONCE_SIZE];

    assert(nonce_manager_next(&first_device.send_nonce, first_nonce));
    assert(nonce_manager_next(&first_device.send_nonce, second_nonce));

    assert(memcmp(
        first_nonce,
        second_nonce,
        GCM_NONCE_SIZE
    ) != 0);

    assert(replay_accept(&second_device.receive_window, 0));
    assert(!replay_accept(&second_device.receive_window, 0));
    assert(replay_accept(&second_device.receive_window, 1));

    tunnel_session_cleanup(&first_device);
    tunnel_session_cleanup(&second_device);

    assert(first_device.initialized == 0);
    assert(second_device.initialized == 0);

    printf("Tunnel session tests passed\n");

    return 0;
}
