all:
	clang -g -O2 -target bpf -c mine.bpf.c -o mine.bpf.o
	$(CC) mine.c -lbpf -o mine

check:
	$(CC) test_sha256.c && ./a.out
	$(CC) test_mine.c && ./a.out
	rm a.out
