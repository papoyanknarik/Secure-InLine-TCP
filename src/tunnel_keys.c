#include "tunnel_keys.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

static int create_key(
    const unsigned char master[SESSION_KEY_SIZE],
    const char *info,
    unsigned char result[TUNNEL_KEY_SIZE]
) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (context == NULL) {
        return 0;
    }

    size_t length = TUNNEL_KEY_SIZE;
    int status = 0;

    if (EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(
            context, master, SESSION_KEY_SIZE) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            context, (const unsigned char *)info, (int)strlen(info)) > 0 &&
        EVP_PKEY_derive(context, result, &length) > 0 &&
        length == TUNNEL_KEY_SIZE) {
        status = 1;
    }

    EVP_PKEY_CTX_free(context);
    return status;
}

int derive_tunnel_keys(
    const unsigned char session_key[SESSION_KEY_SIZE],
    unsigned char device1_to_device2[TUNNEL_KEY_SIZE],
    unsigned char device2_to_device1[TUNNEL_KEY_SIZE]
) {
    if (!create_key(
            session_key,
            "Secure-Inline-TCP Device1 to Device2 v1",
            device1_to_device2)) {
        return 0;
    }

    return create_key(
        session_key,
        "Secure-Inline-TCP Device2 to Device1 v1",
        device2_to_device1
    );
}
