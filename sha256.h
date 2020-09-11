// SPDX-License-Identifier: MIT
// Jeff R. Stripling

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_HASH_SIZE 8

// each chunk is 16 32-bit works, or 512 bits
#define CHUNK_SIZE 16

// Core processing functions

//#define sha256_chunk sha256_chunk_std
#define sha256_chunk sha256_chunk_unroll

extern void sha256_chunk(uint32_t *hash, uint32_t *chunk);

extern uint64_t sha256_calc_num_chunks(uint64_t length_in_bits);

extern unsigned int fill_chunk_uint8(uint8_t *msg, uint32_t *chunk, unsigned int rem_bytes, uint64_t msg_length_in_bits);

extern unsigned int sha256_compare_hash(uint32_t *h1, uint32_t *h2);

extern void sha256_init_hash(uint32_t *hash);

// Utility functions

extern void sha256_print_hash(uint32_t *h);

// 8-bit message functions

extern void sha256_uint8(uint8_t *msg, size_t num_bytes, uint32_t *hash);
    
#endif // SHA256_H


