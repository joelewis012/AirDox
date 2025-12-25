#include "apple_ble_hash_demo.h"
#include "furi_hal.h"
#include "furi_hal_bt.h"
#include "furi.h"

static const char* TAG = "BLE_Hash_Demo";

void start_ble_hash_demo() {
    uint8_t channel = 0; // choose the BLE channel
    furi_hal_bt_start_rx(channel);

    FURI_LOG_I(TAG, "BLE hash demo started on channel %d", channel);
}
