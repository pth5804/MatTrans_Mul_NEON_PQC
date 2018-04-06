#ifndef LIZARD_H
#define LIZARD_H

#include <stdint.h>
#include "params.h"
#include "api.h"

#define iter 1000		// iteration number for keygen & EncDec test
#define testnum 1000	// repeatetion number of Enc Dec procedure in a single iteration

#define sft (sizeof(size_t) * 4 - 1)

#define BLOCK_TRANSPOSE 8
#define LANES_SHORT_NUM 8
#define iter_k	LWE_N/LANES_SHORT_NUM
#define GAP		LANES_SHORT_NUM * LWE_L
#define mod4	LWE_N%LANES_SHORT_NUM
#define div_M	LWE_M/LANES_SHORT_NUM
#define idx_N	LWE_N-mod4
#define mod_N	LWE_N%BLOCK_TRANSPOSE
#define mod_L	LWE_L%BLOCK_TRANSPOSE
#define set_N	BLOCK_TRANSPOSE - mod_N
#define set_L	BLOCK_TRANSPOSE - mod_L

typedef unsigned char SecretKey[CRYPTO_SECRETKEYBYTES];
typedef unsigned char PublicKey[CRYPTO_PUBLICKEYBYTES];

clock_t start, finish, elapsed1, elapsed2, elapsed3;

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk);
int crypto_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, const unsigned long long mlen, const unsigned char *pk);
int crypto_encrypt_open(unsigned char *m, unsigned long long *mlen, const unsigned char *c, unsigned long long clen, const unsigned char *sk);

//Matrix Mul test

int matrixMul(unsigned char *pk, unsigned char *sk);

#endif
