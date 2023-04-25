#pragma once

/* Payload of a fully-solved block #123.
 *
 * https://blockchain.info/block-height/123?format=json
 */

static inline void block_123_init(struct block_header *bh, __u8 difficulty[32])
{
	bh->version = 1;
	bh->time = 1231677823;
	bh->bits = 486604799;
	bh->nonce = 4094077204;

	/* prev_block is stored in little endian! */
	bh->prev_block[7] = 0x00000000;
	bh->prev_block[6] = 0x8d98d186;
	bh->prev_block[5] = 0x56544105;
	bh->prev_block[4] = 0x7e87cc03;
	bh->prev_block[3] = 0x251b95b9;
	bh->prev_block[2] = 0x042956c9;
	bh->prev_block[1] = 0xfb11325e;
	bh->prev_block[0] = 0x2d4a847a;

	/* merkle_root is stored in little endian! */
	bh->merkle_root[7] = 0xb944ef8c;
	bh->merkle_root[6] = 0x77f9b5f4;
	bh->merkle_root[5] = 0xa4276880;
	bh->merkle_root[4] = 0xf1725698;
	bh->merkle_root[3] = 0x8bba4d01;
	bh->merkle_root[2] = 0x25abc543;
	bh->merkle_root[1] = 0x91548061;
	bh->merkle_root[0] = 0xa688ae09;

	difficulty[0] = 0x00;
	difficulty[1] = 0x00;
	difficulty[2] = 0x00;
	difficulty[3] = 0x01;

	difficulty[4] = 0xff;
	difficulty[5] = 0xff;
	difficulty[6] = 0xff;
	difficulty[7] = 0xff;

	difficulty[8] = 0xff;
	difficulty[9] = 0xff;
	difficulty[10] = 0xff;
	difficulty[11] = 0xff;

	difficulty[12] = 0xff;
	difficulty[13] = 0xff;
	difficulty[14] = 0xff;
	difficulty[15] = 0xff;

	difficulty[16] = 0xff;
	difficulty[17] = 0xff;
	difficulty[18] = 0xff;
	difficulty[19] = 0xff;

	difficulty[20] = 0xff;
	difficulty[21] = 0xff;
	difficulty[22] = 0xff;
	difficulty[23] = 0xff;

	difficulty[24] = 0xff;
	difficulty[25] = 0xff;
	difficulty[26] = 0xff;
	difficulty[27] = 0xff;

	difficulty[28] = 0xff;
	difficulty[29] = 0xff;
	difficulty[30] = 0xff;
	difficulty[31] = 0xff;
}
