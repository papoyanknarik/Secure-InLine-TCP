
#include "nonce_manager.h"

#include <string.h>
#include <stdint.h>

int nonce_manager_init(
    NonceManager *manager,
    const unsigned char *prefix
) {
    if (manager == NULL || prefix == NULL)
        return 0;

    memcpy(manager->prefix, prefix, sizeof(manager->prefix));

    manager->counter = 0;
    manager->is_exhausted = 0;

    return 1;
}

int nonce_manager_next(
    NonceManager *manager,
    unsigned char *nonce
) {
    if (manager == NULL || nonce == NULL || manager->is_exhausted)
        return 0;

    memcpy(nonce, manager->prefix, sizeof(manager->prefix));

    uint64_t count = manager->counter;

    for (int i = GCM_NONCE_SIZE - 1; i >= 4; --i) {
        nonce[i] = (unsigned char)(count & 0xFF);
        count >>= 8;
    }

    if (manager->counter == UINT64_MAX)
        manager->is_exhausted = 1;
    else
        manager->counter++;

    return 1;
}
