#pragma once

#undef DEBUG

#define SHA256_CHUNK_SIZE_BYTES		64

struct sha256_ctx {
	__u32 h[8];
	__u32 w[64];

	/* Putting those on the stack leads to some clobbering issues
	 * in clang where shr returns incorrect result.
	 * I'm also (hopefully) forcing read/writes with 'volatile',
	 * otherwise they are cached on the stack and clobbered.
	 */
	volatile __u32 a, e;
};

static inline void sha256_to_be(struct sha256_ctx *ctx)
{
	__u32 tmp;

	tmp = ctx->h[0];
	ctx->h[0] = __cpu_to_be32(ctx->h[7]);
	ctx->h[7] = __cpu_to_be32(tmp);

	tmp = ctx->h[1];
	ctx->h[1] = __cpu_to_be32(ctx->h[6]);
	ctx->h[6] = __cpu_to_be32(tmp);

	tmp = ctx->h[2];
	ctx->h[2] = __cpu_to_be32(ctx->h[5]);
	ctx->h[5] = __cpu_to_be32(tmp);

	tmp = ctx->h[3];
	ctx->h[3] = __cpu_to_be32(ctx->h[4]);
	ctx->h[4] = __cpu_to_be32(tmp);
}

static inline void sha256_print(struct sha256_ctx *ctx)
{
	int i;

	for (i = 0; i < 8; i++)
		printf("%08x", ctx->h[i]);
	printf("\n");
}

static inline void sha256_print_chunk(__u8 buf[SHA256_CHUNK_SIZE_BYTES])
{
#ifdef DEBUG
	int i;
	for (i = 0; i < SHA256_CHUNK_SIZE_BYTES; i++)
		printf("buf[%d] = %x\n", i, buf[i]);
#endif
}

static inline void sha256_print_w(struct sha256_ctx *ctx)
{
#ifdef DEBUG
	int i;

	for (i = 0; i < 16; i++)
		printf("w[%d] = %x\n", i, ctx->w[i]);
#endif
}

static inline void sha256_print_h(struct sha256_ctx *ctx)
{
#ifdef DEBUG
	int i;

	for (i = 0; i < 8; i++)
		printf("h[%d] = %x\n", i, ctx->h[i]);
#endif
}

static inline __u32 lrot(__u32 x, __u32 shift)
{
	return (x << (shift & 31)) | (x >> ((-shift) & 31));
}

static inline __u32 rrot(__u32 x, __u32 shift)
{
	return (x >> (shift & 31)) | (x << ((-shift) & 31));
}

static __u32 k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline void sha256_init(struct sha256_ctx *ctx)
{
	ctx->h[0] = 0x6a09e667;
	ctx->h[1] = 0xbb67ae85;
	ctx->h[2] = 0x3c6ef372;
	ctx->h[3] = 0xa54ff53a;
	ctx->h[4] = 0x510e527f;
	ctx->h[5] = 0x9b05688c;
	ctx->h[6] = 0x1f83d9ab;
	ctx->h[7] = 0x5be0cd19;
}

static inline void sha256_round(struct sha256_ctx *ctx,
				__u32 chunk[16])
{
	__u32 ch, temp1, temp2, maj;
	__u32 b, c, d, f, g, h;
	__u32 s0, s1;
	int i;

	for (i = 0; i < 16; i++)
		ctx->w[i] = __cpu_to_be32(chunk[i]);

	sha256_print_h(ctx);
	sha256_print_w(ctx);

	for (i = 16; i < 64; i++) {
		s0 = rrot(ctx->w[i-15],  7) ^ rrot(ctx->w[i-15], 18) ^ (ctx->w[i-15] >>  3);
		s1 = rrot(ctx->w[i- 2], 17) ^ rrot(ctx->w[i- 2], 19) ^ (ctx->w[i- 2] >> 10);
		ctx->w[i] = ctx->w[i-16] + s0 + ctx->w[i-7] + s1;
	}

	ctx->a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	ctx->e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	for (i = 0; i < 64; i++) {
		s1 = rrot(ctx->e, 6) ^ rrot(ctx->e, 11) ^ rrot(ctx->e, 25);
		ch = (ctx->e & f) ^ ((~ctx->e) & g);
		temp1 = h + s1 + ch + k[i] + ctx->w[i];
		s0 = rrot(ctx->a, 2) ^ rrot(ctx->a, 13) ^ rrot(ctx->a, 22);
		maj = (ctx->a & b) ^ (ctx->a & c) ^ (b & c);
		temp2 = s0 + maj;

		h = g;
		g = f;
		f = ctx->e;
		ctx->e = d + temp1;
		d = c;
		c = b;
		b = ctx->a;
		ctx->a = temp1 + temp2;

#ifdef DEBUG
		printf("t = %d : s0=%x s1=%x\n", i, s0, s1);
		printf("t = %d : ch=%x maj=%x\n", i, ch, maj);
		printf("t = %d : temp1=%x temp2=%x\n", i, temp1, temp2);
		printf("t = %d : a=%x b=%x\n", i, ctx->a, b);
		printf("t = %d : c=%x d=%x\n", i, c, d);
		printf("t = %d : e=%x f=%x\n", i, ctx->e, f);
		printf("t = %d : g=%x h=%x\n", i, g, h);
#endif
	}

	ctx->h[0] += ctx->a;
	ctx->h[1] += b;
	ctx->h[2] += c;
	ctx->h[3] += d;
	ctx->h[4] += ctx->e;
	ctx->h[5] += f;
	ctx->h[6] += g;
	ctx->h[7] += h;
}

static inline int sha256_pad(void *buf, __u64 len, __u64 max_len)
{
	__u8 *p = buf;
	__u64 *l;

	/* buffer is not 512-bit aligned */
	if (max_len % SHA256_CHUNK_SIZE_BYTES)
		return -1;

	/* padding doesn't fit */
	if (max_len - len < 1 + sizeof(__u64))
		return -2;

	/* padding more than single chunk */
	if (max_len - len - 1 - sizeof(__u64) > SHA256_CHUNK_SIZE_BYTES)
		return -3;

	/*__builtin_memset(p + len, 0, max_len - len);*/
	for (int i = 0; i < max_len - len; i++)
		p[len + i] = 0;

	p[len] = 0x80;
	l = (void *)(p + max_len - sizeof(__u64));
	*l = __cpu_to_be64(len * 8);

	return 0;
}
