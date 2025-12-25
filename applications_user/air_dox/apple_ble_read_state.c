#include "apple_ble_read_state.h"
#include <furi.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <input/input.h>
#include <furi_hal_bt.h>

static void draw(Canvas* c, void* ctx) {
    UNUSED(ctx);
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, 64, 24, AlignCenter, AlignTop, "Passive BLE Scan");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, 64, 40, AlignCenter, AlignTop,
        "Listening only\n(no connections)");
}

int32_t apple_ble_read_state_app(void* p) {
    UNUSED(p);

    ViewPort* vp = view_port_alloc();
    view_port_draw_callback_set(vp, draw, NULL);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, vp, GuiLayerFullscreen);

    /* Momentum dev: RX is channel‑only and returns void */
    furi_hal_bt_start_rx(0);   // passive receive on channel 0

    /* Simple wait loop */
    furi_delay_ms(3000);

    furi_hal_bt_stop_rx();

    gui_remove_view_port(gui, vp);
    furi_record_close(RECORD_GUI);
    view_port_free(vp);
    return 0;
}
