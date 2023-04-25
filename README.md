# BPF XDP Bitcoin Miner

Thanks to the introduction of BPF loops and increased verifier complexity
limits we are now able to implement simple Bitcoin miner in XDP. The program
assumes hard-coded input format, runs main loop 16 times, and if the solution
is found, sends it back. Having more than 16 loop iterations is still
problematic; `bpf_loop` might be the way to go beyond this toy example.

# How to run?

```
make
./mine
```

The above will run a test around XDP program by feeding it a solved
block 123 with a `nounce` adjusted back by 15 iterations. That's
enough for the program to try them all and eventually find a
solution.

```
$ make -s check
cc test_sha256.c && ./a.out
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
85e655d6417a17953363376a624cde5c76e09589cac5f811cc4b32c1f20e533a
248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
ok
cc test_mine.c && ./a.out
mine() = 15
00000000a3bbe4fd1da16a29dbdaba01cc35d6fc74ee17f794cf3aab94f7aaa0
ok
rm a.out

$ make -s
$ ./mine
returned XDP_TX and correct 4094077204 nonce
$ cat /sys/kernel/debug/tracing/trace_maker
            ...
            mine-216     [001] b..11     6.270270: bpf_trace_printk: found on 15th iteration
```

# How Bitcoin mining works?

Block header is 80 bytes that contain the following:

```
+---------+-----------------+----------------+------+------------+-------+
| Version | Prev Block Hash | TX Merkle Root | Time | Difficulty | Nonce |
+---------+-----------------+----------------+------+------------+-------+
```

Mining works by iterating `nonce` by one, calling sha256 over 80 bytes
of block header, then calling sha256 again over previous result. (I'm
simplifying here a lot because `nonce` is only 32 bits and it's
possible to exhaust all nonces without finding the block)

The resulting checksum is treated as a big number and if this big number
is less then the predefined difficulty (e.g. has a lot of leading zeroes),
we've mined a new block.

# SHA256

SHA256 is very naive and unoptimized version from the [Wikipedia
page](https://en.wikipedia.org/wiki/SHA-2).

There is a userspace test program that runs a bunch of test vectors from
https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
