all:
	gcc -fPIC -c nstime.c -o nstime.o
	gcc nstime.o -shared -o libnstime.so

clean:
	rm *.o *.so
