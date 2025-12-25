#include "apple_ble_read_state.h"
#include "furi_hal.h"
#include "furi_hal_bt.h"
#include "furi.h"

static const char* TAG = "BLE_Read_State";

// Callback function (if needed)
static void ble_sniffer_cb(uint8_t channel) {
    FURI_LOG_I(TAG, "Received BLE packet on channel %d", channel);
}

void start_ble_sniffer() {
    // Use the new furi_hal_bt_start_rx API
    uint8_t channel = 0; // replace with correct channel if needed
    furi_hal_bt_start_rx(channel);

    // Log manually since function returns void
    FURI_LOG_I(TAG, "BLE sniffer started on channel %d", channel);
}
