all:
	gcc `gpgme-config --libs` -g -c rpass.c -o rpass.o
	gcc `gpgme-config --libs` -g test.c rpass.o -o main
