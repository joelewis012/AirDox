#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <furi_hal_light.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>
#include <toolbox/stream/buffered_file_stream.h>
#include "tiny_e164.h"
#include "picohash.h"
#include "apple_ble_hash_demo.h"

#define TAG "AppleBleHashDemo"
#define MAX_PHONE_NUMBERS 1000
#define APPLE_COMPANY_ID 0x004C
#define AIRDROP_TYPE 0x05
#define MAX_HASHES 100
#define MAX_LOG_LINES 10
#define MAX_EXTRACTED_HASHES 8

typedef struct {
    uint8_t hash[2];
    char phone[17];
} phone_hash_lookup_t;

typedef struct {
    phone_hash_lookup_t* entries;
    size_t count;
    size_t capacity;
} phone_hash_db_t;

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

typedef enum {
    AppStateConfig,
    AppStateLoading,
    AppStateSniffer
} AppState;

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

/* ----- Phone hash DB functions ----- */
int phone_hash_db_init(phone_hash_db_t* db) {
    if(!db) return -1;
    db->entries = NULL;
    db->count = 0;
    db->capacity = 0;
    return 0;
}

void phone_hash_db_free(phone_hash_db_t* db) {
    if(db && db->entries) {
        free(db->entries);
        db->entries = NULL;
        db->count = 0;
        db->capacity = 0;
    }
}

const char* phone_hash_db_lookup(phone_hash_db_t* db, const uint8_t hash[2]) {
    if(!db || !db->entries) return NULL;
    for(size_t i=0; i<db->count; i++) {
        if(db->entries[i].hash[0]==hash[0] && db->entries[i].hash[1]==hash[1])
            return db->entries[i].phone;
    }
    return NULL;
}

void phone_hash_db_add_entry(phone_hash_db_t* db, const uint8_t hash[2], const char* phone) {
    if(!db || !phone) return;

    if(db->count >= db->capacity) {
        size_t new_capacity = db->capacity==0 ? 100 : db->capacity*2;
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
        db->entries[db->count].phone[16]='\0';
        db->count++;
    }
}

/* ----- Utils ----- */
static const uint8_t* find_ad_type(const uint8_t* data, uint16_t len, uint8_t type, uint8_t* found_len) {
    uint16_t offset = 0;
    while(offset < len) {
        uint8_t ad_len = data[offset];
        if(ad_len == 0 || offset+1+ad_len>len) break;
        uint8_t ad_type = data[offset+1];
        if(ad_type==type) {
            *found_len = ad_len-1;
            return &data[offset+2];
        }
        offset += ad_len + 1;
    }
    return NULL;
}

static void format_packet_data(const uint8_t* data, uint16_t len, char* str, size_t str_len) {
    size_t bytes_to_show = len>15?15:len;
    size_t pos=0;
    for(size_t i=0;i<bytes_to_show && pos<str_len-3;i++){
        pos += snprintf(str+pos,str_len-pos,"%02X",data[i]);
        if(i<bytes_to_show-1 && pos<str_len-3) str[pos++]=' ';
    }
    if(len>15 && pos<str_len-4) strcpy(str+pos,"...");
    str[str_len-1]='\0';
}

static void compute_phone_hash(const char* phone_number, uint8_t* hash_out) {
    const char* digits = phone_number;
    if(*digits=='+') digits++;
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx,digits,strlen(digits));
    uint8_t full_hash[PICOHASH_SHA256_DIGEST_LENGTH];
    picohash_final(&ctx, full_hash);
    hash_out[0]=full_hash[0];
    hash_out[1]=full_hash[1];
}

/* ----- Log messages ----- */
static void add_log_message(AppleBleHashDemo* app, const char* message) {
    int idx = (app->log_buffer.log_start+app->log_buffer.log_count)%MAX_LOG_LINES;
    strncpy(app->log_buffer.log_lines[idx], message,63);
    app->log_buffer.log_lines[idx][63]='\0';
    if(app->log_buffer.log_count<MAX_LOG_LINES) app->log_buffer.log_count++;
    else app->log_buffer.log_start=(app->log_buffer.log_start+1)%MAX_LOG_LINES;
}

/* ----- Load phone numbers from file ----- */
static void load_phone_numbers(AppleBleHashDemo* app){
    if(!app->use_brute_force || strlen(app->brute_force_file)==0) return;
    if(app->phone_numbers) { free(app->phone_numbers); app->phone_numbers=NULL; app->phone_numbers_count=0; app->phone_numbers_capacity=0; }
    phone_hash_db_free(&app->hash_db);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    Stream* stream = buffered_file_stream_alloc(storage);
    if(!buffered_file_stream_open(stream,app->brute_force_file,FSAM_READ,FSOM_OPEN_EXISTING)){
        add_log_message(app,"Failed to open file!");
        stream_free(stream);
        furi_record_close(RECORD_STORAGE);
        return;
    }

    app->phone_numbers_capacity = 100;
    app->phone_numbers = malloc(sizeof(phone_e164_t)*app->phone_numbers_capacity);
    FuriString* line_buffer = furi_string_alloc();
    while(stream_read_line(stream,line_buffer)){
        const char* line_cstr=furi_string_get_cstr(line_buffer);
        if(furi_string_size(line_buffer)==0) continue;
        phone_e164_t parsed_phone;
        if(phone_parse_e164(line_cstr,&parsed_phone)==0){
            if(app->phone_numbers_count>=app->phone_numbers_capacity){
                size_t new_capacity=app->phone_numbers_capacity*2;
                if(new_capacity>MAX_PHONE_NUMBERS) new_capacity=MAX_PHONE_NUMBERS;
                phone_e164_t* new_array=realloc(app->phone_numbers,sizeof(phone_e164_t)*new_capacity);
                if(new_array){ app->phone_numbers=new_array; app->phone_numbers_capacity=new_capacity; }
                else break;
            }
            app->phone_numbers[app->phone_numbers_count]=parsed_phone;
            app->phone_numbers_count++;
        }
    }
    furi_string_free(line_buffer);
    buffered_file_stream_close(stream);
    stream_free(stream);
    furi_record_close(RECORD_STORAGE);

    if(app->phone_numbers_count>0){
        phone_hash_db_init(&app->hash_db);
        for(size_t i=0;i<app->phone_numbers_count;i++){
            uint8_t hash[2];
            compute_phone_hash(app->phone_numbers[i].e164,hash);
            phone_hash_db_add_entry(&app->hash_db,hash,app->phone_numbers[i].e164);
        }
    }
}

/* ----- BLE Sniffer callback ----- */
static void sniffer_packet_cb(const uint8_t* data, uint16_t len, int8_t rssi, void* ctx){
    AppleBleHashDemo* app = ctx;
    if(!app) return;
    app->packets_seen++;
    furi_hal_light_set(LightGreen,0xFF);
    furi_delay_ms(25);
    furi_hal_light_set(LightGreen,0x00);
}

/* ----- Draw callbacks ----- */
static void draw_cb(Canvas* canvas, void* ctx){
    AppleBleHashDemo* app=ctx;
    canvas_clear(canvas);
    canvas_set_color(canvas,ColorBlack);
    canvas_set_font(canvas,FontPrimary);
    canvas_draw_str_aligned(canvas,64,3,AlignCenter,AlignTop,"AirDrop Hash Demo");
}

/* ----- Input callback ----- */
static void input_cb(InputEvent* evt, void* ctx){
    AppleBleHashDemo* app=ctx;
    furi_message_queue_put(app->input_queue,evt,0);
}

/* ----- Main app ----- */
int32_t apple_ble_hash_demo_app(void* p){
    UNUSED(p);
    AppleBleHashDemo* app=malloc(sizeof(AppleBleHashDemo));
    memset(app,0,sizeof(AppleBleHashDemo));
    app->view_port=view_port_alloc();
    app->input_queue=furi_message_queue_alloc(8,sizeof(InputEvent));
    app->state=AppStateConfig;

    view_port_draw_callback_set(app->view_port,draw_cb,app);
    view_port_input_callback_set(app->view_port,input_cb,app);
    app->gui=furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui,app->view_port,GuiLayerFullscreen);

    bool exit_loop=false;
    InputEvent input;

    while(!exit_loop){
        if(furi_message_queue_get(app->input_queue,&input,10)==FuriStatusOk){
            if(input.type==InputTypePress){
                if(input.key==InputKeyBack) exit_loop=true;
            }
        }
        view_port_update(app->view_port);
        furi_delay_ms(10);
    }

    if(app->sniffer_active) furi_hal_bt_stop_rx();
    view_port_enabled_set(app->view_port,false);
    gui_remove_view_port(app->gui,app->view_port);
    furi_record_close(RECORD_GUI);
    view_port_free(app->view_port);
    furi_message_queue_free(app->input_queue);
    if(app->phone_numbers) free(app->phone_numbers);
    phone_hash_db_free(&app->hash_db);
    free(app);
    return 0;
}
