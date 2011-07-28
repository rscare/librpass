all: test

test: rpass.o test.o
	gcc -g rpass.o test.o `gpgme-config --libs --cflags` -o test

rpass.o: rpass.c rpass.h
	gcc -g -c rpass.c `gpgme-config --libs` -o rpass.o

test.o: test.c
	gcc -g -c test.c `gpgme-config --libs` -o test.o
