// SPDX-License-Identifier: MIT
// Jeff R. Stripling

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

#define SIZEOF_ARRAY(A) (sizeof(A) / sizeof(A[0]))

// -------------------------------------------------------

#define MAX_TEST_MSG_SIZE 256

typedef struct
{
	const uint8_t msg[MAX_TEST_MSG_SIZE];
    const uint32_t known_hash[SHA256_HASH_SIZE];
} message_test_case;

const message_test_case MessageArray[] =
{
	{
		"abc",
	    {0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad}
    },
	{
		"",
		{0xe3b0c442, 0x98fc1c14, 0x9afbf4c8, 0x996fb924, 0x27ae41e4, 0x649b934c, 0xa495991b, 0x7852b855}
    },
	{
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		{0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039, 0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1}
	},
	{
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		{0xcf5b16a7, 0x78af8380, 0x036ce59e, 0x7b049237, 0x0b249b11, 0xe8f07a51, 0xafac4503, 0x7afee9d1}
	}
};

// -------------------------------------------------------

unsigned int test_known_cases(void)
{
    const message_test_case *mtc = MessageArray;
	unsigned int size;
    uint32_t hash[SHA256_HASH_SIZE];
	unsigned int errors = 0;

    printf("-- Testing common known cases\n");

	for (unsigned int k = 0; k < SIZEOF_ARRAY(MessageArray); k++)
	{
		size = strnlen((const char *)mtc->msg, MAX_TEST_MSG_SIZE);

		printf("%s\n", mtc->msg);
		sha256_uint8((uint8_t *)mtc->msg, size, hash);
		sha256_print_hash(hash);
		
		if (sha256_compare_hash(hash, (uint32_t *)mtc->known_hash))
    	{
        	printf("Answer not correct\n");
			errors++;
    	}

        mtc++;
	}
	return (errors);
}

