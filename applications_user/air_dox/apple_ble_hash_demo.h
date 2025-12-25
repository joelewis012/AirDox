#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t hash[2];
    char phone[17];
} phone_hash_lookup_t;

int32_t apple_ble_hash_demo_app(void* p);
