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

//#define DBG_PRINTF(...) printf(__VA_ARGS__)
#define DBG_PRINTF(...)

// Initalize hash values

const uint32_t HASH_INI_VALUES[SHA256_HASH_SIZE] =
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

static inline void init_w(uint32_t *w, uint32_t *chunk)
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


// This macro works in a weird way, you really have to understand
// what each iteration of the SHA algorithm is doing.

// Normally the last two lines would be E = D + temp1 and A = temp1 + temp2, but
// you have to set up the results for the next iteration of the unrolled loop

#define QHASH(A,B,C,D,E,F,G,H) \
	temp1 = H + s1(E) + ch(E,F,G) + *kp++ + *wp++; \
	temp2 = s0(A) + maj(A,B,C); \
    D = D + temp1; \
	H = temp1 + temp2; \

//! sha256_chunk_unroll - An unrolled version of the std function to update a hash with new values
/**
 * Givin a current hash and a new 512 bit chunk, update the hash values
 * using the chunk.
 *
 * Optimization of this function will affect the overall speed of
 * the entire process
 *
 * This version unrolls the inner loop by changing the definitions of the 
 * registers used in the main loop.  The loop is about eight times longer
 * and executes eight times, for a total of 64 calculations.  The loop
 * uses a macro and avoids some register shifting between iterations.
 * This should allow a clever compiler to reuse registers and speed up
 * the calculation a bit over the std implementation.
 *
 * @param hash A pointer to an 8 value 32 bit array containting the
 *             current hash.  This value is updated based on
 *             the new chunk passed to it
 *
 * @param chunk A pointer to a 16 value 32 bit array (512 bits)
 *              containing the values used to update the hash
 */

void sha256_chunk_unroll(uint32_t *hash, uint32_t *chunk)
{
	uint32_t w[W_SIZE];
	register uint32_t a,b,c,d,e,f,g,h;
	register uint32_t temp1, temp2;

	register uint32_t *kp = (uint32_t *)k;
	register uint32_t *wp = (uint32_t *)w;

	// for each chunk

	// create a 64 entry message schedule array w[0..63] of 32-bit words
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
	for (unsigned int i = 0; i < 8; i++)
	{
		QHASH(a,b,c,d,e,f,g,h);
		QHASH(h,a,b,c,d,e,f,g);
		QHASH(g,h,a,b,c,d,e,f);
		QHASH(f,g,h,a,b,c,d,e);
		QHASH(e,f,g,h,a,b,c,d);
		QHASH(d,e,f,g,h,a,b,c);
		QHASH(c,d,e,f,g,h,a,b);
		QHASH(b,c,d,e,f,g,h,a);
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

//! sha256_chunk_std - A function to update a hash with new values
/**
 * Givin a current hash and a new 512 bit chunk, update the hash values
 * using the chunk.
 *
 * Optimization of this function will affect the overall speed of
 * the entire process
 *
 * @param hash A pointer to an 8 value 32 bit array containting the
 *             current hash.  This value is updated based on
 *             the new chunk passed to it
 *
 * @param chunk A pointer to a 16 value 32 bit array (512 bits)
 *              containing the values used to update the hash
 */

void sha256_chunk_std(uint32_t *hash, uint32_t *chunk)
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

//! sha256_calc_num_chunks - calculate the number of chunks given a message length
/**
 * Given a length of a message in bits, calculate the number
 * of 512 bit chunks that will be needed to generate the hash
 *
 * The number of chunks is the bit length + 1 + 64, plus one more if the number of
 * bits is not a multiple of 512
 *
 * @param length_in_bits The length of the message in bits
 *
 */

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


// ------------------------------------------------------------------------
// Helper Functions for 8 bit messages
// ------------------------------------------------------------------------

//! fill_chunk_uint8 - fill the next chunk for a message

/**
 * Given a message, the remaining number of bytes to be hashed, and the
 * overall length of the message in bits, fill the next 512 bit chunk to be
 * hashed and return the number of message bytes processed to fill the chunk.
 *
 * This function is also called after all bytes are processed one more time to
 * fill the last chunk with the length of the message.
 *
 * This function zero pads the chunk if needed and will always completely fill
 * the chunk so that it is ready to go to the hashing function.
 *
 * @param msg A pointer to the next value in the message to be used to fill the chunk.
 *            This value should advance through the string as it is processed.
 *
 * @param chunk A pointer to a chunk to be filled
 *
 * @param rem_bytes The number of the bytes in the message that still need to be processed.
 *                  This value will decrease as the message is processed.
 *
 * @param msg_length_in_bits The total number of bits in the message.  This value should remain
 *                           constant for all calls to this function for a given message
 *
 */

unsigned int fill_chunk_uint8(uint8_t *msg, uint32_t *chunk, unsigned int rem_bytes, uint64_t msg_length_in_bits)
{
	uint32_t chk = 0;
	unsigned int count = 0;
	unsigned int rem_chunk_parts = CHUNK_SIZE;
	unsigned int bytes_used = 0;
	
	DBG_PRINTF("Chunk:\n");
	while ((rem_bytes) && (rem_chunk_parts))
	{
		chk <<= 8;
		chk |= (*msg++) & 0xff;
		bytes_used++;
		rem_bytes--;
		count++;
		if (count == 4)
		{
			DBG_PRINTF("-- %08x\n", chk);
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
		DBG_PRINTF("-- %08x\n", chk);
		*chunk++ = chk;
		rem_chunk_parts--;
	}

	// Add space between the last data bits, but stop adding when we have two or fewer left
	while (rem_chunk_parts > 2)
	{
		DBG_PRINTF("-z %08x\n", 0);
		*chunk++ = 0;
		rem_chunk_parts--;
	}

	// Add the message length if we have two spots left
	if (rem_chunk_parts >= 2)
	{
		chk = (uint32_t)(msg_length_in_bits >> 32);
        DBG_PRINTF("-# %08x\n", chk);
		*chunk++ = (uint32_t)(msg_length_in_bits >> 32);
		rem_chunk_parts--;
		chk = (uint32_t)(msg_length_in_bits & 0xffffffff);
        DBG_PRINTF("-# %08x\n", chk);
		*chunk++ = (uint32_t)(msg_length_in_bits & 0xffffffff);
		rem_chunk_parts--;
		DBG_PRINTF("  Chunk length: %llu\n", msg_length_in_bits);
	}

	// Zero out any spots remaining
	while (rem_chunk_parts)
	{
		DBG_PRINTF("-Z %08x\n", 0);
		*chunk++ = 0;
		rem_chunk_parts--;
	}

	return (bytes_used);
}

//! sha256_compare_hash - compare two hashes and return non-zero if they differ, zero otherwise
/**
 * Given two pointers to hashs, return non-zero if the hashs differ and zero otherwise
 *
 * @param h1 A pointer to the first hash
 *
 * @param h2 a poiter to the second hash
 *
 * @return non-zero if the hashs differ and zero if they are the same
 *
 */

unsigned int sha256_compare_hash(uint32_t *h1, uint32_t *h2)
{
	for (unsigned int k = 0; k < SHA256_HASH_SIZE; k++)
	{
		if (h1[k] != h2[k])
	    {
		    return(~0);
		}
	}

    return (0);
}

//! sha256_init_hash - initialize the hash
/**
 * Given two pointers to hashs, return non-zero if the hashs differ and zero otherwise
 *
 * @param h1 A pointer to the first hash
 *
 * @param h2 a poiter to the second hash
 *
 * @return non-zero if the hashs differ and zero if they are the same
 *
 */

void sha256_init_hash(uint32_t *hash)
{
	// Initialize hash values
	memcpy(hash, HASH_INI_VALUES, SHA256_HASH_SIZE * sizeof(uint32_t));
}


// Accepts a pointer to a message, the size of the message in bytes, and a place to store
// the 512 byte hash

//! sha256_uint8 - calculate the hash given a string of uint8
/**
 * Given a pointer to an array of uint8 and the size of the array, calculate the hash
 *
 * @param msg A pointer to message to be hashed
 *
 * @param num_bytes The length of the message
 *
 * @param hash A pointer to a hash
 *
 * @return nothing
 *
 */


void sha256_uint8(uint8_t *msg, size_t num_bytes, uint32_t *hash)
{
	uint32_t chunk[CHUNK_SIZE];
	uint64_t num_chunks;
	uint64_t ch;
	uint8_t *msg_ptr = msg;
	unsigned int rem_bytes = (unsigned int)num_bytes;
	unsigned int bytes_used = 0;
	
	// Initialize hash values
    sha256_init_hash(hash);

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

// Print a hash value

void sha256_print_hash(uint32_t *h)
{
	printf("0x ");
	for (unsigned int i = 0; i < SHA256_HASH_SIZE; i++)
	{
		printf("%08x", h[i]);
	}
	printf("\n");
}



