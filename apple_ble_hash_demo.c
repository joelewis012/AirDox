#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <furi_hal_light.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>
#include <toolbox/stream/buffered_file_stream.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "picohash.h"
#include "tiny_e164.h"

#define TAG "AppleBleHashDemo"
#define MAX_LOG_LINES 10
#define MAX_EXTRACTED_HASHES 8
#define MAX_PHONE_NUMBERS 1000
#define MAX_HASHES 100

typedef struct {
    char log_lines[MAX_LOG_LINES][64];
    int log_count;
    int log_start;
} LogBuffer;

typedef struct {
    uint8_t hash[2];
    char phone[17];
} PhoneHashEntry;

typedef struct {
    PhoneHashEntry entries[MAX_PHONE_NUMBERS];
    size_t count;
} PhoneHashDB;

typedef struct {
    uint8_t extracted_hashes[MAX_EXTRACTED_HASHES][2];
    uint8_t num_extracted_hashes;
    char matched_phone[17];
    char packet_data[32];
    int8_t rssi;
} HashEntry;

typedef struct {
    FuriMessageQueue* input_queue;
    ViewPort* view_port;
    Gui* gui;

    HashEntry hashes[MAX_HASHES];
    size_t hash_count;
    size_t scroll_pos;

    LogBuffer log_buffer;

    bool sniffer_active;
    uint32_t packets_seen;
    uint32_t airdrop_packets_seen;
    uint32_t matches_found;

    bool use_brute_force;
    char brute_force_file[256];

    PhoneHashDB hash_db;
} AppleBleHashDemo;

/* ----- Utils ----- */
static void add_log_message(AppleBleHashDemo* app, const char* msg) {
    int idx = (app->log_buffer.log_start + app->log_buffer.log_count) % MAX_LOG_LINES;
    strncpy(app->log_buffer.log_lines[idx], msg, 63);
    app->log_buffer.log_lines[idx][63] = '\0';
    if(app->log_buffer.log_count < MAX_LOG_LINES) app->log_buffer.log_count++;
    else app->log_buffer.log_start = (app->log_buffer.log_start + 1) % MAX_LOG_LINES;
}

static void compute_phone_hash(const char* phone_number, uint8_t* hash_out) {
    const char* digits = phone_number;
    if(*digits=='+') digits++;
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, digits, strlen(digits));
    uint8_t full_hash[PICOHASH_SHA256_DIGEST_LENGTH];
    picohash_final(&ctx, full_hash);
    hash_out[0] = full_hash[0];
    hash_out[1] = full_hash[1];
}

static void phone_hash_db_add(PhoneHashDB* db, const char* phone, const uint8_t hash[2]) {
    if(db->count >= MAX_PHONE_NUMBERS) return;
    db->entries[db->count].hash[0] = hash[0];
    db->entries[db->count].hash[1] = hash[1];
    strncpy(db->entries[db->count].phone, phone, 16);
    db->entries[db->count].phone[16] = '\0';
    db->count++;
}

static const char* phone_hash_db_lookup(PhoneHashDB* db, const uint8_t hash[2]) {
    for(size_t i=0; i<db->count; i++) {
        if(db->entries[i].hash[0]==hash[0] && db->entries[i].hash[1]==hash[1])
            return db->entries[i].phone;
    }
    return NULL;
}

/* ----- Load phone numbers from file ----- */
static void load_phone_numbers(AppleBleHashDemo* app) {
    if(!app->use_brute_force || strlen(app->brute_force_file)==0) return;

    app->hash_db.count = 0;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    Stream* stream = buffered_file_stream_alloc(storage);
    if(!buffered_file_stream_open(stream, app->brute_force_file, FSAM_READ, FSOM_OPEN_EXISTING)) {
        add_log_message(app, "Failed to open phone file!");
        stream_free(stream);
        furi_record_close(RECORD_STORAGE);
        return;
    }

    FuriString* line = furi_string_alloc();
    while(stream_read_line(stream, line)) {
        const char* line_str = furi_string_get_cstr(line);
        if(furi_string_size(line)==0) continue;

        phone_e164_t phone_parsed;
        if(phone_parse_e164(line_str, &phone_parsed)==0) {
            uint8_t hash[2];
            compute_phone_hash(phone_parsed.e164, hash);
            phone_hash_db_add(&app->hash_db, phone_parsed.e164, hash);
        }
    }

    furi_string_free(line);
    buffered_file_stream_close(stream);
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);

    char log_msg[64];
    snprintf(log_msg, 64, "Loaded %d phone numbers", (int)app->hash_db.count);
    add_log_message(app, log_msg);
}

/* ----- BLE sniffer callback ----- */
static void sniffer_packet_cb(const uint8_t* data, uint16_t len, int8_t rssi, void* ctx) {
    AppleBleHashDemo* app = ctx;
    if(!app) return;

    app->packets_seen++;
    furi_hal_light_set(LightGreen, 0xFF);
    furi_delay_ms(25);
    furi_hal_light_set(LightGreen, 0x00);

    // Placeholder: parsing AirDrop hashes could go here
}

/* ----- GUI ----- */
static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleHashDemo* app = ctx;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 3, AlignCenter, AlignTop, "AirDrop Hash Demo");

    int y = 20;
    for(int i=0; i<app->log_buffer.log_count; i++){
        int idx = (app->log_buffer.log_start + i) % MAX_LOG_LINES;
        canvas_draw_str(canvas, 3, y, app->log_buffer.log_lines[idx]);
        y += 10;
    }
}

static void input_cb(InputEvent* evt, void* ctx) {
    AppleBleHashDemo* app = ctx;
    furi_message_queue_put(app->input_queue, evt, 0);
}

/* ----- Main app ----- */
int32_t apple_ble_hash_demo_app(void* p) {
    UNUSED(p);
    AppleBleHashDemo* app = malloc(sizeof(AppleBleHashDemo));
    memset(app, 0, sizeof(AppleBleHashDemo));

    app->view_port = view_port_alloc();
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->gui = furi_record_open(RECORD_GUI);

    load_phone_numbers(app);

    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, input_cb, app);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    if(furi_hal_bt_start_rx(sniffer_packet_cb, app)) {
        app->sniffer_active = true;
        add_log_message(app, "BLE sniffer started");
    } else {
        add_log_message(app, "Failed to start BLE sniffer");
    }

    bool exit_loop = false;
    InputEvent input;
    while(!exit_loop){
        if(furi_message_queue_get(app->input_queue, &input, 10) == FuriStatusOk){
            if(input.type == InputTypePress && input.key == InputKeyBack)
                exit_loop = true;
        }
        view_port_update(app->view_port);
        furi_delay_ms(10);
    }

    if(app->sniffer_active) furi_hal_bt_stop_rx();
    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    free(app);
    return 0;
}
