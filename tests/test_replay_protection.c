#include "replay_protection.h"

#include <assert.h>
#include <stdio.h>

int main(void) {
    ReplayWindow replay_state = {0};

    assert(replay_accept(&replay_state, 50) == 1);
    assert(replay_accept(&replay_state, 50) == 0);

    assert(replay_accept(&replay_state, 53) == 1);
    assert(replay_accept(&replay_state, 51) == 1);
    assert(replay_accept(&replay_state, 51) == 0);

    assert(replay_accept(&replay_state, 120) == 1);
    assert(replay_accept(&replay_state, 50) == 0);

    assert(replay_check(&replay_state, 121) == 1);
    assert(replay_accept(&replay_state, 121) == 1);
    assert(replay_accept(&replay_state, 121) == 0);

    printf("Replay protection validation completed successfully\n");

    return 0;
}
