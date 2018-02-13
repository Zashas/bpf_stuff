# Paths to clang 6.0svn
CC = ~/llvm/build/bin/clang
LLC = ~/llvm/build/bin/llc

all: bpf tool

tool:
	clang classifier.c parser.c json.c -o classifier -lm


bpf:
	$(CC) -O2 -emit-llvm -g -c classifier_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o classifier_bpf.o
