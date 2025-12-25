#include "apple_ble_hash_demo.h"
#include "apple_ble_read_state.h"

#include <furi.h>

#define TAG "AppleHashDemo"

static AppleBleReadState demo_state;

void apple_ble_hash_demo_init(void) {
    apple_ble_read_state_init(&demo_state);
    FURI_LOG_I(TAG, "Apple BLE hash demo initialized");
}
