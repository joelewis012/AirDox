#include "airdox.h"
#include "apple_ble_hash_demo.h"

#include <furi.h>
#include <gui/gui.h>
#include <furi_hal_bt.h>

#define TAG "AirDox"

static bool running = true;

void airdox_draw_callback(Canvas* canvas, void* ctx) {
    UNUSED(ctx);

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);

    canvas_draw_str(canvas, 10, 15, "AirDox");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 10, 30, "Momentum-compatible");
    canvas_draw_str(canvas, 10, 42, "BLE advertising active");
    canvas_draw_str(canvas, 10, 56, "BACK = Exit");
}

void airdox_input_callback(InputEvent* input_event, void* ctx) {
    UNUSED(ctx);

    if(input_event->type == InputTypeShort &&
       input_event->key == InputKeyBack) {
        running = false;
    }
}

int32_t airdox_app(void* p) {
    UNUSED(p);

    FURI_LOG_I(TAG, "AirDox starting (Momentum)");

    if(!furi_hal_bt_is_active()) {
        furi_hal_bt_start_advertising();
        FURI_LOG_I(TAG, "BLE advertising started");
    }

    apple_ble_hash_demo_init();

    Gui* gui = furi_record_open(RECORD_GUI);
    ViewPort* view_port = view_port_alloc();

    view_port_draw_callback_set(view_port, airdox_draw_callback, NULL);
    view_port_input_callback_set(view_port, airdox_input_callback, NULL);

    gui_add_view_port(gui, view_port, GuiLayerFullscreen);

    while(running) {
        furi_delay_ms(100);
    }

    gui_remove_view_port(gui, view_port);
    view_port_free(view_port);
    furi_record_close(RECORD_GUI);

    if(furi_hal_bt_is_active()) {
        furi_hal_bt_stop_advertising();
        FURI_LOG_I(TAG, "BLE advertising stopped");
    }

    FURI_LOG_I(TAG, "AirDox exited cleanly");
    return 0;
}
