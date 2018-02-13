# Paths to clang 6.0svn
CC = ~/llvm/build/bin/clang
LLC = ~/llvm/build/bin/llc

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c, %.o, $(SRCS))

.PHONY: bpf

all: $(OBJS)

clean:
	rm $(OBJS)

%.o: %.c
	$(CC) -O2 -emit-llvm -g -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@
