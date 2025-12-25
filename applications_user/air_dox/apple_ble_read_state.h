#pragma once

typedef struct {
    bool active;
    uint32_t counter;
} AppleBleReadState;

void apple_ble_read_state_init(AppleBleReadState* state);
void apple_ble_read_state_tick(AppleBleReadState* state);
