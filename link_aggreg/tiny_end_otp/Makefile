CC = clang
LLC = llc

all: bpf tool

tool:
	clang end_otp_usr.c -o end_otp_usr


bpf:
	$(CC) -O2 -emit-llvm -g -c end_otp_bpf.c -o - | $(LLC) -march=bpf -filetype=obj -o end_otp_bpf.o

