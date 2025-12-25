#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <gui/elements.h>
#include <stdlib.h>
#include <string.h>

#include "apple_ble_read_state.h"
#include "apple_ble_hash_demo.h"

#define TAG "AirDox"

/* ---------------- Menu entries ---------------- */

typedef enum {
    DemoAppleBleSniffer = 0,
    DemoAppleBleHashDemo,
    DemoCount,
} DemoIndex;

typedef struct {
    const char* name;
    int32_t (*app)(void*);
} DemoEntry;

static const DemoEntry demos[DemoCount] = {
    { "Apple BLE Sniffer", apple_ble_read_state_app },
    { "AirDrop Hash Demo", apple_ble_hash_demo_app },
};

/* ---------------- App state ---------------- */

typedef struct {
    ViewPort* view_port;
    Gui* gui;
    FuriMessageQueue* input_queue;
    DemoIndex selected;
} AirDoxApp;

/* ---------------- Draw ---------------- */

static void air_dox_draw(Canvas* canvas, void* ctx) {
    AirDoxApp* app = ctx;
    canvas_clear(canvas);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, "AirDox");

    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str_aligned(canvas, 64, 14, AlignCenter, AlignTop, "Select mode");

    int y = 28;
    for(size_t i = 0; i < DemoCount; i++) {
        if(i == app->selected) {
            canvas_draw_box(canvas, 0, y - 2, 128, 12);
            canvas_set_color(canvas, ColorWhite);
        }

        canvas_draw_str_aligned(canvas, 64, y, AlignCenter, AlignTop, demos[i].name);

        if(i == app->selected) {
            canvas_set_color(canvas, ColorBlack);
        }

        y += 14;
    }

    canvas_draw_str_aligned(
        canvas, 64, 64, AlignCenter, AlignBottom,
        "OK = Run   Back = Exit"
    );
}

/* ---------------- Input ---------------- */

static void air_dox_input(InputEvent* event, void* ctx) {
    AirDoxApp* app = ctx;
    furi_message_queue_put(app->input_queue, event, FuriWaitForever);
}

/* ---------------- Main app ---------------- */

int32_t air_dox_app(void* p) {
    UNUSED(p);

    AirDoxApp* app = malloc(sizeof(AirDoxApp));
    if(!app) return -1;
    memset(app, 0, sizeof(AirDoxApp));

    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->view_port = view_port_alloc();

    view_port_draw_callback_set(app->view_port, air_dox_draw, app);
    view_port_input_callback_set(app->view_port, air_dox_input, app);

    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    InputEvent event;
    bool exit = false;

    while(!exit) {
        if(furi_message_queue_get(app->input_queue, &event, FuriWaitForever) == FuriStatusOk) {
            if(event.type == InputTypePress) {
                switch(event.key) {
                case InputKeyUp:
                    if(app->selected > 0) app->selected--;
                    break;

                case InputKeyDown:
                    if(app->selected + 1 < DemoCount) app->selected++;
                    break;

                case InputKeyOk:
                    gui_remove_view_port(app->gui, app->view_port);
                    demos[app->selected].app(NULL);
                    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);
                    break;

                case InputKeyBack:
                    exit = true;
                    break;

                default:
                    break;
                }
            }
            view_port_update(app->view_port);
        }
    }

    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);

    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    free(app);

    return 0;
}
