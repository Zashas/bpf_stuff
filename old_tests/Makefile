CC = ~/llvm/build/bin/clang
LLC = ~/llvm/build/bin/llc

main:
	$(CC) -O2 -emit-llvm -c class.c -o - | $(LLC) -march=bpf -filetype=obj -o class.o
