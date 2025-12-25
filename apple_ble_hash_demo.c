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

#include "tiny_e164.h"
#include "picohash.h"
#include "apple_ble_hash_demo.h"

#define TAG "AppleBleHashDemo"
#define MAX_HASHES 100
#define MAX_LOG_LINES 10
#define MAX_EXTRACTED_HASHES 8
#define MAX_PHONE_NUMBERS 1000

#define APPLE_COMPANY_ID 0x004C
#define AIRDROP_TYPE 0x05

/* ---------------- App State ---------------- */

typedef enum {
    AppStateConfig,
    AppStateLoading,
    AppStateSniffer
} AppState;

typedef struct {
    uint8_t extracted_hashes[MAX_EXTRACTED_HASHES][2];
    uint8_t num_extracted_hashes;
    uint32_t timestamp;
    uint32_t seen_count;
    char matched_phone[17];
    char packet_data[32];
    int8_t rssi;
} HashEntry;

typedef struct {
    char log_lines[MAX_LOG_LINES][64];
    int log_count;
    int log_start;
} LogBuffer;

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

    AppState state;
    bool use_brute_force;
    char brute_force_file[256];
    int config_selection;

    phone_e164_t* phone_numbers;
    size_t phone_numbers_count;
    size_t phone_numbers_capacity;

    phone_hash_db_t hash_db;
} AppleBleHashDemo;

/* ---------------- Phone Hash DB ---------------- */

int phone_hash_db_init(phone_hash_db_t* db) {
    if(!db) return -1;
    db->entries = NULL;
    db->count = 0;
    db->capacity = 0;
    return 0;
}

void phone_hash_db_free(phone_hash_db_t* db) {
    if(db && db->entries) free(db->entries);
    if(db) {
        db->entries = NULL;
        db->count = 0;
        db->capacity = 0;
    }
}

const char* phone_hash_db_lookup(phone_hash_db_t* db, const uint8_t hash[2]) {
    if(!db || !db->entries) return NULL;
    for(size_t i = 0; i < db->count; i++) {
        if(db->entries[i].hash[0] == hash[0] &&
           db->entries[i].hash[1] == hash[1]) {
            return db->entries[i].phone;
        }
    }
    return NULL;
}

void phone_hash_db_add_entry(phone_hash_db_t* db, const uint8_t hash[2], const char* phone) {
    if(!db || !phone) return;

    if(db->count >= db->capacity) {
        size_t new_capacity = db->capacity == 0 ? 100 : db->capacity * 2;
        if(new_capacity > MAX_PHONE_NUMBERS) new_capacity = MAX_PHONE_NUMBERS;
        phone_hash_lookup_t* new_entries = realloc(db->entries, sizeof(phone_hash_lookup_t)*new_capacity);
        if(!new_entries) return;
        db->entries = new_entries;
        db->capacity = new_capacity;
    }

    if(db->count < db->capacity) {
        db->entries[db->count].hash[0] = hash[0];
        db->entries[db->count].hash[1] = hash[1];
        strncpy(db->entries[db->count].phone, phone, 16);
        db->entries[db->count].phone[16] = '\0';
        db->count++;
    }
}

/* ---------------- Helpers ---------------- */

static const uint8_t* find_ad_type(const uint8_t* data, uint16_t len, uint8_t type, uint8_t* found_len) {
    uint16_t offset = 0;
    while(offset < len) {
        uint8_t ad_len = data[offset];
        if(ad_len == 0 || offset + ad_len + 1 > len) break;
        uint8_t ad_type = data[offset + 1];
        if(ad_type == type) {
            *found_len = ad_len - 1;
            return &data[offset + 2];
        }
        offset += ad_len + 1;
    }
    return NULL;
}

static void compute_phone_hash(const char* phone, uint8_t* out) {
    const char* digits = (*phone == '+') ? phone+1 : phone;
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, digits, strlen(digits));
    uint8_t full_hash[PICOHASH_SHA256_DIGEST_LENGTH];
    picohash_final(&ctx, full_hash);
    out[0] = full_hash[0];
    out[1] = full_hash[1];
}

/* ---------------- Packet Handling ---------------- */

static void sniffer_packet_cb(const uint8_t* data, uint16_t len, int8_t rssi, void* ctx) {
    AppleBleHashDemo* app = ctx;
    if(!app) return;
    app->packets_seen++;
    furi_hal_light_set(LightGreen, 0xFF);
    furi_delay_ms(25);
    furi_hal_light_set(LightGreen, 0x00);
}

/* ---------------- UI ---------------- */

static void draw_cb(Canvas* canvas, void* ctx) {
    AppleBleHashDemo* app = ctx;
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 3, AlignCenter, AlignTop, "AirDrop Hash Demo");
}

/* ---------------- Main App ---------------- */

int32_t apple_ble_hash_demo_app(void* p) {
    UNUSED(p);

    AppleBleHashDemo* app = calloc(1, sizeof(AppleBleHashDemo));
    if(!app) return -1;

    app->view_port = view_port_alloc();
    app->input_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->state = AppStateConfig;
    app->config_selection = 0;

    view_port_draw_callback_set(app->view_port, draw_cb, app);
    view_port_input_callback_set(app->view_port, NULL, app);

    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    /* Simplified loop */
    InputEvent input;
    bool exit = false;
    while(!exit) {
        furi_delay_ms(50);
        view_port_update(app->view_port);
    }

    gui_remove_view_port(app->gui, app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    free(app);

    return 0;
}
