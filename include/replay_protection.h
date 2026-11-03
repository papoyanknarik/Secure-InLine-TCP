#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stdint.h>
#include <stddef.h>

#define REPLAY_WINDOW_SIZE 64

typedef struct {
    uint64_t max_sequence;
    uint64_t received_bitmap;
    int is_initialized;
} ReplayWindow;

int replay_check(const ReplayWindow *state, uint64_t sequence);
int replay_accept(ReplayWindow *state, uint64_t sequence);

#endif
