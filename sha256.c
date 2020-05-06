// SPDX-License-Identifier: MIT
// Jeff R. Stripling

// The algorithms and constants described in this file were taken from
// the wikipedia page for the SHA256 algorthm, from this source
//
// https://en.wikipedia.org/wiki/SHA-2
//
// The author tried to use the same names and conventions as shown
// on that page so that someone familiar with the SHA-256 algorithm
// might recognize the process being used when reading this code

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

#define K_SIZE 64
#define W_SIZE 64

// Initalize hash values

const uint32_t H_INI_VALUES[SHA256_HASH_SIZE] =
{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19	 
};


const uint32_t k[K_SIZE] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


// ---------------------------------------------------------------------
// Helper functions for core algorithm
// ---------------------------------------------------------------------


static inline uint32_t rrot32(uint32_t value, unsigned int count)
{
	// Assumes we are always passed a count in the range 1..31
	return ((value >> count) | (value << (32 - count)));
}

static inline uint32_t w_s0(uint32_t w)
{
	return (rrot32(w,7) ^ rrot32(w,18) ^ (w >> 3));
}

static inline uint32_t w_s1(uint32_t w)
{
	return (rrot32(w,17) ^ rrot32(w,19) ^ (w >> 10));
}

static void init_w(uint32_t *w, uint32_t *chunk)
{
	unsigned int i;
	
	// copy chunk into first 16 words w[0..15] of the message schedule array
	i = 0;
	while (i < 16)
	{
		w[i] = *chunk++;
		i++;
	}

	// extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
	while (i < 64)
	{
		w[i] = w[i-16] + w_s0(w[i-15])+ w[i-7] + w_s1(w[i-2]);
		i++;
	}
}

static inline uint32_t s1(uint32_t e)
{
	return (rrot32(e,6) ^ rrot32(e,11) ^ rrot32(e,25));
}

static inline uint32_t s0(uint32_t a)
{
	return (rrot32(a,2) ^ rrot32(a,13) ^ rrot32(a,22));
}

static inline uint32_t ch(uint32_t e, uint32_t f, uint32_t g)
{
	return ((e & f) ^ ((~e) & g));
}

static inline uint32_t maj(uint32_t a, uint32_t b, uint32_t c)
{
	return ((a & b) ^ (a & c) ^ (b & c));
}

// ------------------------------------------------------------------------
// Core processing function for a 512 bit chunk
// ------------------------------------------------------------------------

// Givin a current hash and a new 512 bit chunk, update the hash values
// using the chunk.	 This function assumes that hash is a pointer to
// an 8 value array and chunk is a pointer to a 16 value array

// Optimization of this function will affect the overall speed of
// the entire process

void sha256_chunk(uint32_t *hash, uint32_t *chunk)
{
	uint32_t w[W_SIZE];
	register uint32_t a,b,c,d,e,f,g,h;
	register uint32_t temp1, temp2;
	
	// for each chunk

	// create a 64 entry message schedule array w[0..62] of 32-bit words
	init_w(w, chunk);

	// Initialize working variables to current hash value
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	f = hash[5];
	g = hash[6];
	h = hash[7];

	// Compression function main loop
	for (unsigned int i = 0; i < 64; i++)
	{
		temp1 = h + s1(e) + ch(e,f,g) + k[i] + w[i];
		temp2 = s0(a) + maj(a,b,c);

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	// Add the compressed chunk to the current hash value
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
	hash[5] += f;
	hash[6] += g;
	hash[7] += h;
}

uint64_t sha256_calc_num_chunks(uint64_t length_in_bits)
{
	unsigned int total_bits;
	unsigned int num_chunks;

	// Figure out how many bits we need to store the message
	total_bits = length_in_bits + 1 + 64;
	num_chunks = total_bits >> 9; // Divide total bits by 512 or 2^9

	// If the number is not equal to a multiple of 512, we need to raise it up to a multiple of 512
	// Do this by adding one more chunk
	if (total_bits & (512-1))
	{
		num_chunks++;
	}

	return (num_chunks);
}


// each chunk is 16 32-bit works, or 512 bits
#define CHUNK_SIZE 16


// ------------------------------------------------------------------------
// Helper Functions for 8 bit messages
// ------------------------------------------------------------------------

static unsigned int fill_chunk_uint8(char *msg, uint32_t *chunk, unsigned int rem_bytes, uint64_t msg_length_in_bits)
{
	uint32_t chk = 0;
	unsigned int count = 0;
	unsigned int rem_chunk_parts = CHUNK_SIZE;
	unsigned int bytes_used = 0;
	
	printf("Chunk:\n");
	while ((rem_bytes) && (rem_chunk_parts))
	{
		chk <<= 8;
		chk |= (*msg++) & 0xff;
		bytes_used++;
		rem_bytes--;
		count++;
		if (count == 4)
		{
			printf("-- %08x\n", chk);
			count = 0;
			*chunk++ = chk;
			rem_chunk_parts--;
		}
	}

	// if we ran out of chunk parts, we are done and can return this chunk
	if (! rem_chunk_parts)
	{
		return (bytes_used);
	}

	// If we wrote bytes on this block or if our message length is a multiple of the block length
	// Add a trailing '1' bit.	Since we know we ended at a byte, this will be an 0x80 value
	if ((bytes_used) || ((msg_length_in_bits % 512) == 0))
	{
		// Otherwise, we need to finish the last chunk
		chk <<= 8;
		chk |= 0x80;
		count++;

		// Then advance to the end of this uint32, since we should have at least whole chunks left for
		// the message length.	This adds zero bits until we reach the end of the uint32
		while (count < sizeof(uint32_t))
		{
			chk <<= 8;
			count++;
		}

		// add the last chunk part with any remaining bits, plus the 1 trailing bit, plus zero pad
		printf("-- %08x\n", chk);
		*chunk++ = chk;
		rem_chunk_parts--;
	}

	// Add space between the last data bits, but stop adding when we have two or fewer left
	while (rem_chunk_parts > 2)
	{
		printf("-z %08x\n", 0);
		*chunk++ = 0;
		rem_chunk_parts--;
	}

	// Add the message length if we have two spots left
	if (rem_chunk_parts >= 2)
	{
		chk = (uint32_t)(msg_length_in_bits >> 32); printf("-# %08x\n", chk);
		*chunk++ = (uint32_t)(msg_length_in_bits >> 32);
		rem_chunk_parts--;
		chk = (uint32_t)(msg_length_in_bits & 0xffffffff); printf("-# %08x\n", chk);
		*chunk++ = (uint32_t)(msg_length_in_bits & 0xffffffff);
		rem_chunk_parts--;
		printf("  Chunk length: %llu\n", msg_length_in_bits);
	}

	// Zero out any spots remaining
	while (rem_chunk_parts)
	{
		printf("-Z %08x\n", 0);
		*chunk++ = 0;
		rem_chunk_parts--;
	}

	return (bytes_used);
}

// Accepts a pointer to a message, the size of the message in bytes, and a place to store
// the 512 byte hash
 
void sha256_char(char *msg, size_t num_bytes, uint32_t *hash)
{
	uint32_t chunk[CHUNK_SIZE];
	uint64_t num_chunks;
	uint64_t ch;
	char *msg_ptr = msg;
	unsigned int rem_bytes = (unsigned int)num_bytes;
	unsigned int bytes_used = 0;
	
	// Initialize hash values
	memcpy(hash, H_INI_VALUES, SHA256_HASH_SIZE * sizeof(uint32_t));

	// Figure out how many 512-bit chunks we will need
	num_chunks = sha256_calc_num_chunks(num_bytes * 8); // 8 bits per byte
	rem_bytes = num_bytes;

	ch = 0;
	while (ch++ < num_chunks)
	{
		bytes_used = fill_chunk_uint8(msg_ptr, chunk, rem_bytes, (num_bytes * 8));
		sha256_chunk(hash, chunk);

		msg_ptr += bytes_used;
		rem_bytes -= bytes_used;
	}
}
	


