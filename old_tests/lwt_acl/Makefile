# Paths to clang 6.0svn
CC = clang
LLC = llc

all: tool bpf

tool:
	gcc acl_tool.c -o acl_drop

bpf:
	$(CC) -O2 -emit-llvm -g -c acl_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o acl_bpf.o
