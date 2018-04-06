CC = gcc

CFLAGS=-O3 -mcpu=cortex-a53 -mfloat-abi=hard -mfpu=neon-fp-armv8 -mneon-for-64bits -mtune=cortex-a53 -std=c99

all :
	$(CC) $(CFLAGS) -c Lizard.c main.c randombytes.c sha512.c 
	$(CC) $(CFLAGS) -o Lizard Lizard.o main.o randombytes.o sha512.o -lcrypto libkeccak.a
	
run : all
	./Lizard

clean :
	rm -f *.o
	rm -f Lizard

new :
	make clean
	make all
	./Lizard
