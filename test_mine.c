#include <stdio.h>
#include <stdlib.h>
#include <error.h>
#include <assert.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "mine.h"
#include "block_123.h"

static inline int mine(struct sha256_ctx *sum,
		       struct block_header *bh,
		       __u8 buf[BUF_SIZE_BYTES],
		       __u8 difficulty[32])
{
	int ret, i;

	for (i = 0; i < 65536; i++) {
		memcpy(buf, bh, sizeof(*bh));

		ret = hash_block(sum, buf);
		if (ret)
			return -1;

		if (meets_difficulty(sum, difficulty))
			return i;

		bh->nonce++;
	}
	return -1;
}

int main(int argc, char **argv)
{
	/* to fit sizeof(struct block_header) and padding */
	__u8 buf[BUF_SIZE_BYTES] = {};
	struct block_header bh;
	struct sha256_ctx sum;
	__u8 difficulty[32];
	int ret;

	block_123_init(&bh, difficulty);

	/* go back 15 nonces */
	bh.nonce -= 15;

	ret = mine(&sum, &bh, buf, difficulty);
	printf("mine() = %d\n", ret);

	if (ret >= 0)
		sha256_print(&sum);

	assert(sum.h[0] == 0x00000000 &&
	       sum.h[1] == 0xa3bbe4fd &&
	       sum.h[2] == 0x1da16a29 &&
	       sum.h[3] == 0xdbdaba01 &&
	       sum.h[4] == 0xcc35d6fc &&
	       sum.h[5] == 0x74ee17f7 &&
	       sum.h[6] == 0x94cf3aab &&
	       sum.h[7] == 0x94f7aaa0);

	printf("ok\n");

	return 0;
}
