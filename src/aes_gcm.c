
#include "aes_gcm.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *plaintext,
    size_t plaintext_len,
    unsigned char *ciphertext,
    unsigned char *tag
) {
    if (key == NULL || nonce == NULL || plaintext == NULL ||
        ciphertext == NULL || tag == NULL || plaintext_len > INT_MAX)
        return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    int out_len = 0, last_len = 0;
    int result = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto end;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_NONCE_SIZE, NULL) != 1)
        goto end;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto end;

    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len,
                          plaintext, (int)plaintext_len) != 1)
        goto end;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &last_len) != 1)
        goto end;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            GCM_TAG_SIZE, tag) != 1)
        goto end;

    result = 1;

end:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext
) {
    if (key == NULL || nonce == NULL || ciphertext == NULL ||
        tag == NULL || plaintext == NULL || ciphertext_len > INT_MAX)
        return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return 0;

    int out_len = 0, last_len = 0;
    int result = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           NULL, NULL, NULL) != 1)
        goto end;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_NONCE_SIZE, NULL) != 1)
        goto end;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto end;

    if (EVP_DecryptUpdate(ctx, plaintext, &out_len,
                          ciphertext, (int)ciphertext_len) != 1)
        goto end;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            GCM_TAG_SIZE, (void *)tag) != 1)
        goto end;

    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &last_len) != 1)
        goto end;

    result = 1;

end:
    if (!result && ciphertext_len > 0)
        OPENSSL_cleanse(plaintext, ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return result;
}
