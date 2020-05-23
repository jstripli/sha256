// SPDX-License-Identifier: MIT
// Jeff R. Stripling

#include <stdio.h>

#include "test_big_sha.h"
#include "test_known_cases.h"

int main(int argc, char *argv[])
{
	unsigned int errors = 0;
	
    errors += test_known_cases();
	
	errors += test_big_sha();

	if (errors)
	{
    	printf ("Failed casees: %u\n", errors);
		return (errors);
	}

    printf ("All passed\n");
	return (0);
}

