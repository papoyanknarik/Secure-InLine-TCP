#include "crypto_utils.h"
#include <openssl/hmac.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

int generate_session_key(
    const unsigned char *secret,
    size_t secret_length,
    const unsigned char *salt,
    size_t salt_length,
    unsigned char *key
) {
    if (secret == NULL || secret_length == 0 ||
        salt == NULL || salt_length == 0 ||
        key == NULL) {
        return 0;
    }

    EVP_PKEY_CTX *context =
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (context == NULL) {
        return 0;
    }

    int result = 0;
    size_t output_length = SESSION_KEY_LENGTH;

    const unsigned char context_info[] =
        "Secure-Inline-TCP AES-256-GCM v1";

    if (EVP_PKEY_derive_init(context) <= 0)
        goto finish;

    if (EVP_PKEY_CTX_set_hkdf_md(
            context, EVP_sha256()) <= 0)
        goto finish;

    if (EVP_PKEY_CTX_set1_hkdf_salt(
            context, salt, salt_length) <= 0)
        goto finish;

    if (EVP_PKEY_CTX_set1_hkdf_key(
            context, secret, secret_length) <= 0)
        goto finish;

    if (EVP_PKEY_CTX_add1_hkdf_info(
            context, context_info,
            sizeof(context_info) - 1) <= 0)
        goto finish;

    if (EVP_PKEY_derive(
            context, key, &output_length) <= 0)
        goto finish;

    result = (output_length == SESSION_KEY_LENGTH);

finish:
    EVP_PKEY_CTX_free(context);
    return result;
}
int compute_hmac(
    const unsigned char *key,
    size_t key_len,
    const unsigned char *data,
    size_t data_len,
    unsigned char output[HMAC_SIZE]
) {
    if (!key || !data || !output ||
        key_len > INT_MAX) {
        return 0;
    }

    unsigned int output_len = 0;

    unsigned char *result = HMAC(
        EVP_sha256(),
        key,
        (int)key_len,
        data,
        data_len,
        output,
        &output_len
    );

    return result != NULL && output_len == HMAC_SIZE;
}

int derive_confirmation_key(
    const unsigned char *shared_secret, size_t secret_len,
    const unsigned char *salt, size_t salt_len,
    unsigned char confirmation_key[CONFIRM_KEY_SIZE]
) {
    if (!shared_secret || !secret_len || !salt || !salt_len ||
        !confirmation_key)
        return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return 0;

    size_t key_len = CONFIRM_KEY_SIZE;
    const unsigned char info[] =
        "Secure-Inline-TCP key-confirmation v1";

    int success =
        EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, secret_len) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            ctx, info, sizeof(info) - 1) > 0 &&
        EVP_PKEY_derive(ctx, confirmation_key, &key_len) > 0 &&
        key_len == CONFIRM_KEY_SIZE;

    EVP_PKEY_CTX_free(ctx);
    return success;
}
