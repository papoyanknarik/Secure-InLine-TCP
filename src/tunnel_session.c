#include "tunnel_session.h"

#include <openssl/crypto.h>
#include <string.h>

int tunnel_session_init(
    TunnelSession *session,
    const unsigned char master_key[SESSION_KEY_SIZE],
    int device_id
) {
    if (session == NULL || master_key == NULL ||
        (device_id < 1 || device_id > 2)) {
        return 0;
    }

    memset(session, 0, sizeof(TunnelSession));

    unsigned char key_forward[TUNNEL_KEY_SIZE] = {0};
    unsigned char key_reverse[TUNNEL_KEY_SIZE] = {0};

    int result = derive_tunnel_keys(
        master_key, key_forward, key_reverse
    );

    if (result != 1) {
        goto finish;
    }

    const unsigned char *outgoing;
    const unsigned char *incoming;

    if (device_id == 1) {
        outgoing = key_forward;
        incoming = key_reverse;
    } else {
        outgoing = key_reverse;
        incoming = key_forward;
    }

    memcpy(session->send_key, outgoing, TUNNEL_KEY_SIZE);
    memcpy(session->receive_key, incoming, TUNNEL_KEY_SIZE);

    unsigned char nonce_prefix[4] = {0};

    if (nonce_manager_init(&session->send_nonce, nonce_prefix) != 1) {
        result = 0;
        goto finish;
    }

    session->initialized = 1;

finish:
    OPENSSL_cleanse(key_forward, sizeof(key_forward));
    OPENSSL_cleanse(key_reverse, sizeof(key_reverse));

    if (result != 1) {
        tunnel_session_cleanup(session);
    }

    return result;
}

void tunnel_session_cleanup(TunnelSession *session) {
    if (session != NULL) {
        OPENSSL_cleanse(session, sizeof(*session));
    }
}
