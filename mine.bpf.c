#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl:4, version:4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

#define NUM_LOOPS 16

#define __cpu_to_be32(x) bpf_htonl(x)
#define __cpu_to_be64(x) ({ \
	__u32 h = x >> 32; \
	__u32 l = x & ((1ULL << 32) - 1); \
	(((__u64)bpf_htonl(l)) << 32) | ((__u64)(bpf_htonl(h))); \
})

#define printf bpf_printk

#define swap(a, b) do { typeof(a) tmp = (a); (a) = (b); (b) = tmp; } while (0)

#include "sha256.h"
#include "mine.h"

char _license[] SEC("license") = "GPL";

struct scratch {
	struct sha256_ctx sum;
	__u8 buf[BUF_SIZE_BYTES];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct scratch));
} scratch_map SEC(".maps");

SEC("xdp")
int mine(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct scratch *s;
	struct pkt *p;
	int key = 0;
	int ret, i;

	s = bpf_map_lookup_elem(&scratch_map, &key);
	if (!s)
		return XDP_DROP;

	p = data;

	if (data + sizeof(*p) > data_end)
		return XDP_DROP;

	for (i = 0; i < NUM_LOOPS; i++) {
		__builtin_memcpy(s->buf, &p->bh, sizeof(p->bh));

		ret = hash_block(&s->sum, s->buf);
		if (ret)
			return XDP_DROP;

#ifdef DEBUG
		bpf_printk("h[0]=%x\n", s->sum.h[0]);
		bpf_printk("h[1]=%x\n", s->sum.h[1]);
		bpf_printk("h[2]=%x\n", s->sum.h[2]);
		bpf_printk("h[3]=%x\n", s->sum.h[3]);
		bpf_printk("h[4]=%x\n", s->sum.h[4]);
		bpf_printk("h[5]=%x\n", s->sum.h[5]);
		bpf_printk("h[6]=%x\n", s->sum.h[6]);
		bpf_printk("h[7]=%x\n", s->sum.h[7]);
#endif

		/* We do range check again because verifies loses track
		 * of the original one.
		 */
		if (data + sizeof(*p) <= data_end) {
			if (meets_difficulty(&s->sum, p->difficulty)) {
				bpf_printk("found on %dth iteration\n", i);

				/* nonce found, send it back! */
				swap(p->eth.h_dest[0], p->eth.h_source[0]);
				swap(p->eth.h_dest[1], p->eth.h_source[1]);
				swap(p->eth.h_dest[2], p->eth.h_source[2]);
				swap(p->eth.h_dest[3], p->eth.h_source[3]);
				swap(p->eth.h_dest[4], p->eth.h_source[4]);
				swap(p->eth.h_dest[5], p->eth.h_source[5]);
				swap(p->iph.saddr, p->iph.daddr);
				swap(p->udp.source, p->udp.dest);

				return XDP_TX;
			}
			p->bh.nonce++;
		}
	}

	bpf_printk("not found\n");
	return XDP_DROP;
}
