#include "apple_ble_hash_demo.h"
#include <furi.h>
#include <gui/gui.h>
#include <gui/elements.h>

static void draw(Canvas* c, void* ctx) {
    UNUSED(ctx);
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, 64, 20, AlignCenter, AlignTop, "Apple Hash Demo");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str_aligned(c, 64, 36, AlignCenter, AlignTop,
        "Offline correlation\n(no device contact)");
}

int32_t apple_ble_hash_demo_app(void* p) {
    UNUSED(p);
    ViewPort* vp = view_port_alloc();
    view_port_draw_callback_set(vp, draw, NULL);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, vp, GuiLayerFullscreen);

    furi_delay_ms(3000);

    gui_remove_view_port(gui, vp);
    furi_record_close(RECORD_GUI);
    view_port_free(vp);
    return 0;
}
