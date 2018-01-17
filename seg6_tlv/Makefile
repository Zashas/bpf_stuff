# Paths to clang 6.0svn
CC = ~/llvm/build/bin/clang
LLC = ~/llvm/build/bin/llc

all: bpf

bpf:
	$(CC) -O2 -emit-llvm -g -c tlv_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o tlv_bpf.o
