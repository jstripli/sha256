// SPDX-License-Identifier: MIT
// Jeff R. Stripling

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"

const char Message[] = "Hello World";
//const char Message[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstufffffff01234567ab";
//const char Message[] = "";

uint32_t Hash[SHA256_HASH_SIZE];

static void print_sha256_hash(uint32_t *h)
{
	printf("0x ");
	for (unsigned int i = 0; i < SHA256_HASH_SIZE; i++)
	{
		printf("%08x", Hash[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	char *msg = (char *)Message;
	unsigned int size = strlen(Message);
	
	printf("%s\n", msg);
	sha256_char(msg, size, Hash);
	print_sha256_hash(Hash);
}

