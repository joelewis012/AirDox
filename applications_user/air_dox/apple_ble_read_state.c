#include "apple_ble_read_state.h"

void apple_ble_read_state_init(AppleBleReadState* state) {
    state->active = true;
    state->counter = 0;
}

void apple_ble_read_state_tick(AppleBleReadState* state) {
    if(state->active) {
        state->counter++;
    }
}
