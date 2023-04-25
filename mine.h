#pragma once

#include "sha256.h"

/* Bitcoin block definition that we'll be mining (nounce). */
struct block_header {
	__u32		version;
	__u32		prev_block[8];
	__u32		merkle_root[8];
	__u32		time;
	__u32		bits;
	__u32		nonce;
} __attribute__((packed));

/* The packet that the XDP program expects to receive (UDP).
 *
 * It will mine 15 nounces (starting from the one in the packet)
 * and will reply back if it found the nounce that satisfies
 * the provided difficulty.
 */
struct pkt {
	struct ethhdr eth;
	struct iphdr iph;
	struct udphdr udp;
	struct block_header bh;
	__u8 difficulty[32];
} __attribute__((packed));

/* to fit sizeof(struct block_header) and padding */
#define BUF_SIZE_BYTES	(SHA256_CHUNK_SIZE_BYTES * 2)

static inline int hash_block(struct sha256_ctx *sum,
			     __u8 buf[BUF_SIZE_BYTES])
{
	int ret;

	/* First round of sha256 over struct block_header.
	 */
	ret = sha256_pad(buf, sizeof(struct block_header), BUF_SIZE_BYTES);
	if (ret)
		return ret;

	sha256_print_chunk((void *)&buf[0]);
	sha256_print_chunk((void *)&buf[SHA256_CHUNK_SIZE_BYTES]);

	sha256_init(sum);
	sha256_round(sum, (void *)&buf[0]);
	sha256_round(sum, (void *)&buf[SHA256_CHUNK_SIZE_BYTES]);

	/* Copy resulting checksum back into the buffer with
	 * proper endian.
	 */
	{
		__u32 *x = (void *)buf;
		x[0] = __cpu_to_be32(sum->h[0]);
		x[1] = __cpu_to_be32(sum->h[1]);
		x[2] = __cpu_to_be32(sum->h[2]);
		x[3] = __cpu_to_be32(sum->h[3]);
		x[4] = __cpu_to_be32(sum->h[4]);
		x[5] = __cpu_to_be32(sum->h[5]);
		x[6] = __cpu_to_be32(sum->h[6]);
		x[7] = __cpu_to_be32(sum->h[7]);
	}

	/* Second round of sha256 over first checksum.
	 */
	ret = sha256_pad(buf, 32, SHA256_CHUNK_SIZE_BYTES);
	if (ret)
		return ret;

	sha256_print_chunk((void *)&buf[0]);

	sha256_init(sum);
	sha256_round(sum, (void *)&buf[0]);

	/* Transform back to big endian.
	 */
	sha256_to_be(sum);

	return 0;
}

static inline int meets_difficulty(struct sha256_ctx *sum, __u8 difficulty[32])
{
	int i;

	for (i = 0; i < 8; i++) {
		__u32 diff32 = difficulty[i + 0] << 24 |
			difficulty[i + 1] << 16 |
			difficulty[i + 2] << 8 |
			difficulty[i + 3] << 0;

		if (sum->h[i] == diff32)
			continue;
		return sum->h[i] < diff32;
	}

	return 0;
}
