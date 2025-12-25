#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <furi.h>

/* ---------------- Phone hash structures ---------------- */

typedef struct {
    uint8_t hash[2];
    char phone[17];  // E.164 phone string
} phone_hash_lookup_t;

typedef struct {
    phone_hash_lookup_t* entries;
    size_t count;
    size_t capacity;
} phone_hash_db_t;

/* ---------------- Phone database API ---------------- */

int phone_hash_db_init(phone_hash_db_t* db);
void phone_hash_db_free(phone_hash_db_t* db);
int phone_hash_db_load_from_file(phone_hash_db_t* db, const char* filename);
const char* phone_hash_db_lookup(phone_hash_db_t* db, const uint8_t hash[2]);
void phone_hash_db_add_entry(phone_hash_db_t* db, const uint8_t hash[2], const char* phone);

/* ---------------- Demo entrypoint ---------------- */

int32_t apple_ble_hash_demo_app(void* p);
