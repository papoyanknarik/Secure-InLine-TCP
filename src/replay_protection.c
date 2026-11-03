#include "replay_protection.h"

int replay_check(const ReplayWindow *window, uint64_t sequence) {
    if (window == NULL) {
        return 0;
    }

    if (window->is_initialized == 0 ||
        sequence > window->max_sequence) {
        return 1;
    }

    uint64_t offset = window->max_sequence - sequence;

    if (offset >= REPLAY_WINDOW_SIZE) {
        return 0;
    }

    return (window->received_bitmap &
            (UINT64_C(1) << offset)) == 0;
}

int replay_accept(ReplayWindow *window, uint64_t sequence) {
    if (window == NULL || !replay_check(window, sequence)) {
        return 0;
    }

    if (!window->is_initialized) {
        window->max_sequence = sequence;
        window->received_bitmap = 1;
        window->is_initialized = 1;
        return 1;
    }

    if (sequence > window->max_sequence) {
        uint64_t distance = sequence - window->max_sequence;

        if (distance >= REPLAY_WINDOW_SIZE) {
            window->received_bitmap = 1;
        } else {
            window->received_bitmap =
                (window->received_bitmap << distance) | UINT64_C(1);
        }

        window->max_sequence = sequence;
        return 1;
    }

    uint64_t offset = window->max_sequence - sequence;
    window->received_bitmap |= UINT64_C(1) << offset;

    return 1;
}
