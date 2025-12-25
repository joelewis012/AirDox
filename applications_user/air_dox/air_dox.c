#include <furi.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <input/input.h>

#include "apple_ble_read_state.h"
#include "apple_ble_hash_demo.h"

typedef enum {
    DemoReadState = 0,
    DemoHashDemo,
    DemoCount,
} DemoIndex;

typedef struct {
    Gui* gui;
    ViewPort* vp;
    FuriMessageQueue* q;
    DemoIndex sel;
} App;

static const char* items[DemoCount] = {
    "BLE Scanner (Passive)",
    "Apple Hash Demo",
};

static void draw(Canvas* c, void* ctx) {
    App* a = ctx;
    canvas_clear(c);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str_aligned(c, 64, 2, AlignCenter, AlignTop, "AirDox");

    canvas_set_font(c, FontSecondary);
    for(size_t i = 0; i < DemoCount; i++) {
        if(i == a->sel) {
            canvas_draw_box(c, 0, 18 + i*12, 128, 11);
            canvas_set_color(c, ColorWhite);
        }
        canvas_draw_str_aligned(c, 64, 20 + i*12, AlignCenter, AlignTop, items[i]);
        canvas_set_color(c, ColorBlack);
    }
}

static void input(InputEvent* e, void* ctx) {
    App* a = ctx;
    furi_message_queue_put(a->q, e, 0);
}

int32_t air_dox_app(void* p) {
    UNUSED(p);
    App* a = malloc(sizeof(App));
    a->q = furi_message_queue_alloc(8, sizeof(InputEvent));
    a->vp = view_port_alloc();
    view_port_draw_callback_set(a->vp, draw, a);
    view_port_input_callback_set(a->vp, input, a);

    a->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(a->gui, a->vp, GuiLayerFullscreen);

    InputEvent e;
    bool exit = false;
    while(!exit) {
        if(furi_message_queue_get(a->q, &e, FuriWaitForever) == FuriStatusOk) {
            if(e.type == InputTypePress) {
                if(e.key == InputKeyUp && a->sel > 0) a->sel--;
                if(e.key == InputKeyDown && a->sel + 1 < DemoCount) a->sel++;
                if(e.key == InputKeyOk) {
                    gui_remove_view_port(a->gui, a->vp);
                    if(a->sel == DemoReadState) apple_ble_read_state_app(NULL);
                    if(a->sel == DemoHashDemo)  apple_ble_hash_demo_app(NULL);
                    gui_add_view_port(a->gui, a->vp, GuiLayerFullscreen);
                }
                if(e.key == InputKeyBack) exit = true;
            }
            view_port_update(a->vp);
        }
    }

    gui_remove_view_port(a->gui, a->vp);
    furi_record_close(RECORD_GUI);
    view_port_free(a->vp);
    furi_message_queue_free(a->q);
    free(a);
    return 0;
}
