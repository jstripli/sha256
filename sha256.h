// SPDX-License-Identifier: MIT
// Jeff R. Stripling

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_HASH_SIZE 8

// Core processing functions

void sha256_chunk(uint32_t *hash, uint32_t *chunk);

uint64_t sha256_calc_num_chunks(uint64_t length_in_bits);

// 8-bit message functions

void sha256_char(char *msg, size_t num_bytes, uint32_t *hash);
    
#endif // SHA256_H


