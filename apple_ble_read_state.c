#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <furi_hal_light.h>

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "apple_ble_read_state.h"

#define TAG "AppleBLE"
#define MAX_DEVICES 64
#define MAC_ADDR_LEN 18

/* ---------------- Device Model ---------------- */

typedef struct {
    char mac[MAC_ADDR_LEN];
    int8_t rssi;
    uint32_t last_seen;
} AppleDevice;

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort* view_port;
    Gui* gui;

    AppleDevice devices[MAX_DEVICES];
    size_t device_count;
    size_t scroll;

    bool sniffer_running;
    uint32_t packets;
} AppleBleApp;

/* ---------------- Helpers ---------------- */

static void mac_to_str(const uint8_t* mac, char* out) {
    snprintf(
        out,
        MAC_ADDR_LEN,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2],
        mac[3], mac[4], mac[5]);
}

static AppleDevice* find_or_add_device(
    AppleBleApp* app,
    const uint8_t* mac,
    int8_t rssi) {

    char mac_str[MAC_ADDR_LEN];
    mac_to_str(mac, mac_str);

    for(size_t i = 0; i < app->device_count; i++) {
        if(strcmp(app->devices[i].mac, mac_str) == 0) {
            app->devices[i].rssi = rssi;
            app->devices[i].last_seen = furi_get_tick();
            return &app->devices[i];
        }
    }

    if(app->device_count >= MAX_DEVICES) return NULL;

    AppleDevice* dev = &app->devices[app->device_count++];
    strcpy(dev->mac, mac_str);
    dev->rssi = rssi;
    dev->last_seen = furi_get_tick();
    return dev;
}

/* ---------------- BLE Sniffer Callback ---------------- */

static void ble_sniffer_cb(
    const uint8_t* data,
    uint16_t len,
    int8_t rssi,
    void* ctx) {

    AppleBleApp* app = ctx;
    if(!app || len < 14) return;

    // HCI LE Advertising Report
    if(data[0] != 0x04 || data[1] != 0x3E || data[3] != 0x02) return;

    uint8_t mac[6];
    memcpy(mac, data + 7, 6);

    find_or_add_device(app, mac, rssi);
    app->packets++;

    // LED blink
    furi_hal_light_set(LightBlue, 0xFF);
    furi_delay_ms(10);
    furi_hal_light_set(LightBlue, 0x00);
}

/* ---------------- UI ---------------- */

static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleApp* app = ctx;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "Apple BLE Scanner");

    char buf[32];
    snprintf(buf, sizeof(buf), "Devices: %d", (int)app->device_count);
    canvas_draw_str(canvas, 2, 22, buf);

    snprintf(buf, sizeof(buf), "Packets: %lu", app->packets);
    canvas_draw_str(canvas, 2, 32, buf);

    canvas_set_font(canvas, FontSecondary);

    int y = 44;
    for(size_t i = app->scroll;
        i < app->device_count && y < 64;
        i++) {

        snprintf(
            buf,
            sizeof(buf),
            "%s  %ddBm",
            app->devices[i].mac,
            app->devices[i].rssi);

        canvas_draw_str(canvas, 2, y, buf);
        y += 10;
    }
}

/* ---------------- Input ---------------- */

static void input_cb(InputEvent* evt, void* ctx) {
    AppleBleApp* app = ctx;
    furi_message_queue_put(app->input_queue, evt, 0);
}

/* ---------------- App Entry ---------------- */

int32_t apple_ble_read_state_app(void* p) {
    UNUSED(p);

    AppleBleApp* app = calloc(1, sizeof(AppleBleApp));
    if(!app) return -1;

    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->view_port = view_port_alloc();

    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);

    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    /* --- Start BLE RX --- */
    furi_hal_bt_stop_advertising();
    furi_hal_bt_reinit();
    furi_delay_ms(300);

    if(furi_hal_bt_start_rx(ble_sniffer_cb, app)) {
        app->sniffer_running = true;
        FURI_LOG_I(TAG, "BLE sniffer started");
    } else {
        FURI_LOG_E(TAG, "Failed to start BLE sniffer");
    }

    InputEvent input;
    bool exit = false;

    while(!exit) {
        if(furi_message_queue_get(app->input_queue, &input, 50) == FuriStatusOk) {
            if(input.type == InputTypePress) {
                switch(input.key) {
                    case InputKeyUp:
                        if(app->scroll > 0) app->scroll--;
                        break;
                    case InputKeyDown:
                        if(app->scroll + 1 < app->device_count) app->scroll++;
                        break;
                    case InputKeyBack:
                        exit = true;
                        break;
                    default:
                        break;
                }
            }
        }
        view_port_update(app->view_port);
    }

    if(app->sniffer_running) {
        furi_hal_bt_stop_rx();
    }

    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    free(app);

    return 0;
}
