// SPDX-License-Identifier: MIT
// Jeff R. Stripling

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

// -------------------------------------------------------
//

#define BIG_MSG_NUM_REPS 16777216L

// 64 bytes, 512 bits:   ****----****----****----****----****----****----****----****----
const uint8_t BigMessage[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
uint32_t BigChunk[CHUNK_SIZE];
uint32_t BigHash[SHA256_HASH_SIZE];

const uint32_t BigHashKnown[SHA256_HASH_SIZE] =
{
	0x50e72a0e,0x26442fe2,0x552dc393,0x8ac58658,0x228c0cbf,0xb1d2ca87,0x2ae43526,0x6fcd055e
};


#define BIG_MSG_NUM_BITS (uint64_t)(512 * BIG_MSG_NUM_REPS)
unsigned int test_big_sha(void)
{
	uint8_t *msg = (uint8_t *)BigMessage;

	printf("-- Testing big string %ld times\n", BIG_MSG_NUM_REPS );

	// Initialize hash values
	sha256_init_hash(BigHash);

	fill_chunk_uint8(msg, BigChunk, 64, BIG_MSG_NUM_BITS);

	for (unsigned long k = 0; k < BIG_MSG_NUM_REPS; k++)
	{
		sha256_chunk(BigHash, BigChunk);
	}

	// Fill the buffer with the last part, including the trailing 1 and the size
	fill_chunk_uint8((uint8_t *)BigMessage, BigChunk, 0, BIG_MSG_NUM_BITS);
	sha256_chunk(BigHash, BigChunk);

    sha256_print_hash(BigHash);

	if (sha256_compare_hash(BigHash, (uint32_t *)BigHashKnown))
	{
    	printf("Answer not correct\n");
		return (~0);
	}

	return (0);
}

//
// -------------------------------------------------------
