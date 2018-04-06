#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "Lizard.h"
//#include "rng.h"

PublicKey pk;
SecretKey sk;
unsigned char sk_t[CRYPTO_SECRETKEYBYTES + CRYPTO_PUBLICKEYBYTES];

//FILE *fp;

void Keygen() {
	elapsed1 = clock();
	for (int l = 0; l < iter; ++l) {
		crypto_encrypt_keypair(pk, sk);
	}
	elapsed1 = clock() - elapsed1;

	printf("    Keygen Time: %f ms\n", elapsed1 * 1000. / CLOCKS_PER_SEC / iter);
}

/*
void EncDecTest_CCA() {
	// Set a messages
#if defined(CCA_CATEGORY1_N536) || defined(CCA_CATEGORY1_N663)
	unsigned char m3[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	unsigned char m4[32];

#endif
#if defined(CCA_CATEGORY3_N816) || defined(CCA_CATEGORY3_N952)
	unsigned char m3[48] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	unsigned char m4[48];
#endif
#if defined(CCA_CATEGORY5_N1088) || defined(CCA_CATEGORY5_N1300)
	unsigned char m3[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	unsigned char m4[64];
#endif
	unsigned long long mlen3 = sizeof(m3), clen, mlen4;
	unsigned char *c = (unsigned char*)calloc(CRYPTO_BYTES, sizeof(unsigned char));
	int i, res = 0;

	elapsed1 = 0;
	elapsed2 = 0;
	
	memcpy(sk_t, sk, sizeof(unsigned char) * CRYPTO_SECRETKEYBYTES);
	memcpy(sk_t + CRYPTO_SECRETKEYBYTES, pk, sizeof(unsigned char) * CRYPTO_PUBLICKEYBYTES);

	for (int l = 0; l < iter; ++l) {

		for (i = 0; i < testnum; i++){
			crypto_encrypt(c, &clen, m3, mlen3, pk);
			res = crypto_encrypt_open(m4, &mlen4, c, clen, sk_t);
		}

		if (res == 1) {
			printf("    Decryption Validity Error Type 1 : c3 components\n");
			break;
		}

		if (res == 2) {
			printf("    Decryption Validity Error Type 2 : a, b components\n");
			break;
		}

		// Correctness check
		for (i = 0; i < mlen3; ++i) {
			if (m3[i] != m4[i]) {
				printf("    Correctness Error\n");
				printf("    %d %d\n", m3[i], m4[i]);
				break;
			}
		}
		if (i < mlen3) break;
	}

	//printf("    Enc Time: %f ms\n", elapsed1 * 1000. / CLOCKS_PER_SEC / testnum / iter);
	//printf("    Dec Time: %f ms\n", elapsed2 * 1000. / CLOCKS_PER_SEC / testnum / iter);

	fprintf(fp, "    Enc Time:\t %f \tms\t", elapsed1 * 1000. / CLOCKS_PER_SEC / testnum / iter);
	fprintf(fp, "    Dec Time:\t %f \tms\n", elapsed2 * 1000. / CLOCKS_PER_SEC / testnum / iter);

	free(c);
}
*/

/*
void MatrixMulTest(){
	crypto_encrypt_keypair(pk, sk);

	printf("    C Time: %f ms\n", elapsed1 * 1000. / CLOCKS_PER_SEC / iter);
	printf("    NEON Time1: %f ms\n", elapsed2 * 1000. / CLOCKS_PER_SEC / iter);
};
*/

void main() {

	int i = 0;

	printf("\n  //////////////////////////////////////////////////////////////////\n\n");
	printf("\t\t"PARAMNAME" Parameter\n\n");
	printf("    LWE dimension: %d, \t\tLWR dimension: %d\n", LWE_N, LWE_M);
	printf("    Plaintext dimension: %d, \t\tPlaintext Modulus: %d bits\t\n", LWE_L, LOG_T);
	printf("    Public Key modulus: %d bits, \tCiphertext modulus: %d bits\t\n\n", LOG_Q, LOG_P);
	printf("  //////////////////////////////////////////////////////////////////\n\n");
	printf("\t\t\tPerformance Test\n\n");


	//char buf[100];

	//sprintf(buf, "%s.csv", PARAMNAME);

	//char *filename = buf;//"test1.csv";

	//fp=fopen(filename, "w+");

	//printf("FileName: %s\n", filename);

	//for(i=0; i<1000; i++){	
		// Key Generation
		KEYGEN();

		// Enc and Dec
		//ENCDECTEST();
	//}

	printf("Timing Calculation is done!\n\n");

	//fclose(fp);
}
