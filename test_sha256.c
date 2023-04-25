#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <assert.h>

#include <string.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#include "sha256.h"

static int test_single_round(void)
{
	__u8 buf[SHA256_CHUNK_SIZE_BYTES] = "abc";
	struct sha256_ctx sum;
	int ret;

	ret = sha256_pad(buf, 3, SHA256_CHUNK_SIZE_BYTES);
	if (ret)
		error(1, -1, "padding failed %d", ret);

	sha256_print_chunk(buf);

	sha256_init(&sum);
	sha256_round(&sum, (void *)buf);
	sha256_print(&sum);


	return sum.h[0] == 0xba7816bf &&
		sum.h[1] == 0x8f01cfea &&
		sum.h[2] == 0x414140de &&
		sum.h[3] == 0x5dae2223 &&
		sum.h[4] == 0xb00361a3 &&
		sum.h[5] == 0x96177a9c &&
		sum.h[6] == 0xb410ff61 &&
		sum.h[7] == 0xf20015ad;
}

static int test_two_rounds(void)
{
	__u8 buf[SHA256_CHUNK_SIZE_BYTES * 2] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	struct sha256_ctx sum;
	int ret;

	ret = sha256_pad(buf, 56, SHA256_CHUNK_SIZE_BYTES * 2);
	if (ret)
		error(1, -1, "padding failed %d", ret);

	sha256_print_chunk(buf);
	sha256_print_chunk(&buf[SHA256_CHUNK_SIZE_BYTES]);

	sha256_init(&sum);
	sha256_round(&sum, (void *)&buf[0]);
	sha256_print(&sum);
	sha256_round(&sum, (void *)&buf[SHA256_CHUNK_SIZE_BYTES]);
	sha256_print(&sum);

	return sum.h[0] == 0x248d6a61 &&
		sum.h[1] == 0xd20638b8 &&
		sum.h[2] == 0xe5c02693 &&
		sum.h[3] == 0x0c3e6039 &&
		sum.h[4] == 0xa33ce459 &&
		sum.h[5] == 0x64ff2167 &&
		sum.h[6] == 0xf6ecedd4 &&
		sum.h[7] == 0x19db06c1;
}

int main(int argc, char **argv)
{
	assert(test_single_round() == 1);
	assert(test_two_rounds() == 1);
	printf("ok\n");
	return 0;
}
