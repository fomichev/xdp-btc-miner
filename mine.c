#include <stdio.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <asm/byteorder.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "mine.h"
#include "block_123.h"

int main(int argc, char **argv)
{
	struct bpf_test_run_opts opts = {};
	struct bpf_program *prog;
	struct bpf_object *obj;
	__u32 correct_nonce;
	struct pkt p;
	int err;

	block_123_init(&p.bh, p.difficulty);

	/* go back 15 nonces, current loop limit in the xdp program */
	correct_nonce = p.bh.nonce;
	p.bh.nonce -= 15;

	obj = bpf_object__open("./mine.bpf.o");
	err = libbpf_get_error(obj);
	if (err < 0)
		error(1, err, "bpf_object__open");

	err = bpf_object__load(obj);
	if (err < 0)
		error(1, err, "bpf_object__load");

	prog = bpf_object__find_program_by_name(obj, "mine");
	err = libbpf_get_error(prog);
	if (err < 0)
		error(1, err, "bpf_object__find_program_by_name");

	opts.repeat = 1;
	opts.data_in = &p;
	opts.data_size_in = sizeof(p);
	opts.data_out = &p;
	opts.data_size_out = sizeof(p);
	opts.sz = sizeof(struct bpf_test_run_opts);

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (err)
		error(1, err, "bpf_prog_test_run_xattr");

	if (opts.retval != XDP_TX)
		error(1, -1, "unexpected retval %u != XDP_TX", opts.retval);

	if (p.bh.nonce != correct_nonce)
		error(1, -1, "unexpected nonce %u != %u", p.bh.nonce,
		      correct_nonce);

	printf("returned XDP_TX and correct %u nonce\n", correct_nonce);

	bpf_object__close(obj);

	return 0;
}
