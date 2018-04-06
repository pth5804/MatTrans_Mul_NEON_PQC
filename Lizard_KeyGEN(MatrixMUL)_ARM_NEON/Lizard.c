#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <immintrin.h>
#include <arm_neon.h>

#include "Lizard.h"
#include "rng.h"
#include "sha512.h"
#include "./SP800-185/SP800-185.h"

uint16_t seed[LWE_M * LWE_L * 2];
int count = 0;

#ifdef NOISE_D1
#define SAMPLE_DG Sample_D1
const uint16_t CDF_TABLE[9] = { 78, 226, 334, 425, 473, 495, 506, 510, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 9;

uint16_t Sample_D1() {
	uint16_t rnd = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D2
#define SAMPLE_DG Sample_D2
const uint16_t CDF_TABLE[4] = { 458, 946, 1020, 1023 }; // out of [0, 1023]
const size_t TABLE_LENGTH = 4;

uint16_t Sample_D2() {
	uint16_t rnd = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x03ff;
	uint16_t sign = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D3
#define SAMPLE_DG Sample_D3
const uint16_t CDF_TABLE[5] = { 151, 382, 482, 507, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 5;

uint16_t Sample_D3() {
	uint16_t rnd = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D4
#define SAMPLE_DG Sample_D4
const uint16_t CDF_TABLE[6] = { 121, 325, 445, 494, 508, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 6;

uint16_t Sample_D4() {
	uint16_t rnd = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D5
#define SAMPLE_DG Sample_D5
const uint16_t CDF_TABLE[12] = { 262, 761, 1188, 1518, 1748, 1892, 1974, 2016, 2035, 2043, 2046, 2047 }; // out of [0, 2047]
const size_t TABLE_LENGTH = 12;

uint16_t Sample_D5() {
	uint16_t rnd = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x07ff;
	uint16_t sign = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D6
#define SAMPLE_DG Sample_D6
const uint16_t CDF_TABLE[4] = { 380, 874, 1008, 1023 }; // out of [0, 1023]
const size_t TABLE_LENGTH = 4;

uint16_t Sample_D6() {
	uint16_t rnd = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x03ff;
	uint16_t sign = seed[count == LWE_M * LWE_L * 2 ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif


/**
  * @param	pk		[in] public key for encryption. pk = (A, B)
  * @param	sk		[in] private key for decryption
  */

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk) {
	int i, j, k;

	uint8_t sk_t[LWE_N * LWE_L];
	uint16_t *pk_A = (uint16_t*)malloc(sizeof(uint16_t) * (LWE_M * LWE_N));
	uint16_t *pk_B = (uint16_t*)malloc(sizeof(uint16_t) * (LWE_M * LWE_L));

	// Matrix Multiplication (NEON)
	uint16_t S[LWE_N*LWE_L] = {0, };
   	uint16x8_t sum_vect;
	uint16x8_t a_vec;
	uint16x8_t b_vec;

	uint16x8_t a_vec1,a_vec2,a_vec3,a_vec4, a_vec5, a_vec6, a_vec7;
	uint16x8_t b_vec1,b_vec2,b_vec3,b_vec4, b_vec5, b_vec6, b_vec7;
	// Matrix Transpose (NEON)
	uint16x8_t vec1_l;
	uint16x8_t vec1_h;
	uint16x8_t vec2_l;
	uint16x8_t vec2_h;

	uint16x8x2_t t0;
	uint16x8x2_t t1;
	uint16x8x2_t t2;
	uint16x8x2_t t3;
	uint16x8x2_t t4;
	uint16x8x2_t t5;
	uint16x8x2_t t6;
	uint16x8x2_t t7;

	uint16x8x2_t m0;
	uint16x8x2_t m1;
	uint16x8x2_t m2;
	uint16x8x2_t m3;
	uint16x8x2_t m4;
	uint16x8x2_t m5;
	uint16x8x2_t m6;
	uint16x8x2_t m7;

	uint16_t sum = 0;
	uint16_t sum_array[8]={0, };

	// Generate a random matrix A
	randombytes((unsigned char*)pk_A, PublicKey_A);
	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_N; ++j) {
			pk_A[i * LWE_N + j] <<= _16_LOG_Q;
			pk[(i * LWE_N * 2) + (j * 2)] = pk_A[i * LWE_N + j] >> 8;
			pk[(i * LWE_N * 2) + (j * 2 + 1)] = pk_A[i * LWE_N + j] & 0xff;
		}
	}

	// Generate a secret matrix S
	randombytes(sk_t, LWE_L * LWE_N);
	// Secret distribution ZO(1/2)
#if defined(CCA_CATEGORY1_N536) || defined(CCA_CATEGORY3_N816) || defined(CCA_CATEGORY5_N1088)
	for (i = 0; i < LWE_L * LWE_N; ++i) {
		if ((sk_t[i] & 0x03) == 0x00){
			sk[i] = -1;
		}else if ((sk_t[i] & 0x03) == 0x01){
			sk[i] = 1;
		}else{
			sk[i] = 0;
		}
		S[i] = (uint16_t)sk[i];
	}
#endif
	// Secret distribution ZO(1/4)
#if defined(CCA_CATEGORY1_N663) || defined(CCA_CATEGORY3_N952) || defined(CCA_CATEGORY5_N1300)
	for (i = 0; i < LWE_L * LWE_N; ++i) {
		if ((sk_t[i] & 0x07) == 0x00){
			sk[i] = -1;
		}else if ((sk_t[i] & 0x07) == 0x01){
			sk[i] = 1;
		}else{
			sk[i] = 0;
		}
		S[i] = (uint16_t)sk[i];
	}
#endif

	// Initialize B as an error matrix E
	randombytes((unsigned char*)seed, LWE_M * LWE_L * 4);
	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_L; ++j) {
			pk_B[i * LWE_L + j] = SAMPLE_DG() << _16_LOG_Q;
		}
	}

	// Add -AS to B. Resulting B = -AS + E (Original)
/*
	for (i = 0; i < LWE_M; ++i) {
		uint16_t* A_i = pk_A + LWE_N * i;
		uint16_t* B_i = pk_B + LWE_L * i;
		for (k = 0; k < LWE_N; ++k) {
			uint8_t* sk_k = sk + LWE_L * k;
			uint16_t A_ik = A_i[k];
			for (j = 0; j < LWE_L; j += 2) {
				B_i[j] -= A_ik * (char)sk_k[j];
				B_i[j + 1] -= A_ik * (char)sk_k[j + 1];
			}
		}
	}
*/

	
	// Add -AS to B. Resulting B = -AS + E (NEON)
///*
	for (i = 0; i < LWE_N; i += BLOCK_TRANSPOSE) {
        
			if (i + BLOCK_TRANSPOSE > LWE_N) {
			    i -= set_N;
			}

			for (j = 0; j < LWE_L; j += BLOCK_TRANSPOSE) {
			    
			    if (j + BLOCK_TRANSPOSE > LWE_L) {
				j -= set_L;
			    }
			    
			    vec1_l = vld1q_u16(S + i * LWE_L + j);
			    vec1_h = vld1q_u16(S + i * LWE_L + j + 8);
			    vec2_l = vld1q_u16(S + (i + 8) * LWE_L + j);
			    vec2_h = vld1q_u16(S + (i + 8) * LWE_L + j + 8);

			    
			    t0 = vzipq_u16(vec1_l, vec2_l);
			    t1 = vzipq_u16(vec1_h, vec2_h);


			    vec1_l = vld1q_u16(S + (i + 1) * LWE_L + j);
			    vec1_h = vld1q_u16(S + (i + 1) * LWE_L + j + 8);

			    vec2_l = vld1q_u16(S + (i + 9) * LWE_L + j);
			    vec2_h = vld1q_u16(S + (i + 9) * LWE_L + j + 8);


			    t2 = vzipq_u16(vec1_l, vec2_l);
			    t3 = vzipq_u16(vec1_h, vec2_h);


			    vec1_l = vld1q_u16(S + (i + 2) * LWE_L + j);
			    vec1_h = vld1q_u16(S + (i + 2) * LWE_L + j + 8);

			    vec2_l = vld1q_u16(S + (i + 10) * LWE_L + j);
			    vec2_h = vld1q_u16(S + (i + 10) * LWE_L + j + 8);


			    t4 = vzipq_u16(vec1_l, vec2_l);
			    t5 = vzipq_u16(vec1_h, vec2_h);



			    vec1_l = vld1q_u16(S + (i + 3) * LWE_L + j);
			    vec1_h = vld1q_u16(S + (i + 3) * LWE_L + j + 8);

			    vec2_l = vld1q_u16(S + (i + 11) * LWE_L + j);
			    vec2_h = vld1q_u16(S + (i + 11) * LWE_L + j + 8);


			    t6 = vzipq_u16(vec1_l, vec2_l);
			    t7 = vzipq_u16(vec1_h, vec2_h);


			    m0 = vzipq_u16(t0.val[0], t4.val[0]);
			    m1 = vzipq_u16(t0.val[1], t4.val[1]);
			    m2 = vzipq_u16(t1.val[0], t5.val[0]);
			    m3 = vzipq_u16(t1.val[1], t5.val[1]);
			    m4 = vzipq_u16(t2.val[0], t6.val[0]);
			    m5 = vzipq_u16(t2.val[1], t6.val[1]);
			    m6 = vzipq_u16(t3.val[0], t7.val[0]);
			    m7 = vzipq_u16(t3.val[1], t7.val[1]);
			    t0 = vzipq_u16(m0.val[0], m4.val[0]);
			    t1 = vzipq_u16(m0.val[1], m4.val[1]);
			    t2 = vzipq_u16(m1.val[0], m5.val[0]);
			    t3 = vzipq_u16(m1.val[1], m5.val[1]);
			    t4 = vzipq_u16(m2.val[0], m6.val[0]);
			    t5 = vzipq_u16(m2.val[1], m6.val[1]);
			    t6 = vzipq_u16(m3.val[0], m7.val[0]);
			    t7 = vzipq_u16(m3.val[1], m7.val[1]);

			    vst1q_u16(S + j * LWE_N + i,  t0.val[0]);
			    vst1q_u16(S + j * LWE_N + i + 8,  t0.val[1]);
			    vst1q_u16(S + (j + 1) * LWE_N + i,  t1.val[0]);
			    vst1q_u16(S + (j + 1) * LWE_N + i + 8, t1.val[1]);
			    vst1q_u16(S + (j + 2) * LWE_N + i, t2.val[0]);
			    vst1q_u16(S + (j + 2) * LWE_N + i + 8, t2.val[1]);
			    vst1q_u16(S + (j + 3) * LWE_N + i, t3.val[0]);
			    vst1q_u16(S + (j + 3) * LWE_N + i + 8, t3.val[1]);
			    vst1q_u16(S + (j + 4) * LWE_N + i, t4.val[0]);
			    vst1q_u16(S + (j + 4) * LWE_N + i + 8, t4.val[1]);
			    vst1q_u16(S + (j + 5) * LWE_N + i, t5.val[0]);
			    vst1q_u16(S + (j + 5) * LWE_N + i + 8, t5.val[1]);
			    vst1q_u16(S + (j + 6) * LWE_N + i, t6.val[0]);
			    vst1q_u16(S + (j + 6) * LWE_N + i + 8, t6.val[1]);
			    vst1q_u16(S + (j + 7) * LWE_N + i, t7.val[0]);
			    vst1q_u16(S + (j + 7) * LWE_N + i + 8, t7.val[1]);
			}
		    }

		// Matrix Multiplication (NEON)
		for (i = 0; i < LWE_M; i++) {
			for (j = 0; j < LWE_L; j++) {
			    sum_vect = vdupq_n_u16(0);
			    

			    for (k = 0; k < iter_k; k+=12) {
				a_vec1 = vld1q_u16(pk_A + i * LWE_N + k * LANES_SHORT_NUM);
				b_vec1 = vld1q_u16(S + j * LWE_N + k * LANES_SHORT_NUM);

				a_vec2 = vld1q_u16(pk_A + i * LWE_N + (k+1) * LANES_SHORT_NUM);
				b_vec2 = vld1q_u16(S + j * LWE_N + (k+1) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec1, b_vec1);

				a_vec3 = vld1q_u16(pk_A + i * LWE_N + (k+2) * LANES_SHORT_NUM);
				b_vec3 = vld1q_u16(S + j * LWE_N + (k+2) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec2, b_vec2);

				a_vec4 = vld1q_u16(pk_A + i * LWE_N + (k+3) * LANES_SHORT_NUM);
				b_vec4 = vld1q_u16(S + j * LWE_N + (k+3) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec3, b_vec3);

				a_vec5 = vld1q_u16(pk_A + i * LWE_N + (k+4) * LANES_SHORT_NUM);
				b_vec5 = vld1q_u16(S + j * LWE_N + (k+4) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec4, b_vec4);

				a_vec6 = vld1q_u16(pk_A + i * LWE_N + (k+5) * LANES_SHORT_NUM);
				b_vec6 = vld1q_u16(S + j * LWE_N + (k+5) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec5, b_vec5);

				a_vec7 = vld1q_u16(pk_A + i * LWE_N + (k+6) * LANES_SHORT_NUM); //
				b_vec7 = vld1q_u16(S + j * LWE_N + (k+6) * LANES_SHORT_NUM); //
				sum_vect = vmlaq_u16(sum_vect, a_vec6, b_vec6);

				a_vec2 = vld1q_u16(pk_A + i * LWE_N + (k+7) * LANES_SHORT_NUM);
				b_vec2 = vld1q_u16(S + j * LWE_N + (k+7) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec7, b_vec7); // 8

				a_vec3 = vld1q_u16(pk_A + i * LWE_N + (k+8) * LANES_SHORT_NUM);
				b_vec3 = vld1q_u16(S + j * LWE_N + (k+8) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec2, b_vec2); // 9

				a_vec4 = vld1q_u16(pk_A + i * LWE_N + (k+9) * LANES_SHORT_NUM);
				b_vec4 = vld1q_u16(S + j * LWE_N + (k+9) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec3, b_vec3); // 10

				a_vec5 = vld1q_u16(pk_A + i * LWE_N + (k+10) * LANES_SHORT_NUM);
				b_vec5 = vld1q_u16(S + j * LWE_N + (k+10) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec4, b_vec4); //11

				a_vec6 = vld1q_u16(pk_A + i * LWE_N + (k+11) * LANES_SHORT_NUM);
				b_vec6 = vld1q_u16(S + j * LWE_N + (k+11) * LANES_SHORT_NUM);
				sum_vect = vmlaq_u16(sum_vect, a_vec5, b_vec5); //12

				sum_vect = vmlaq_u16(sum_vect, a_vec6, b_vec6); 

				

			    }

			vst1q_u16(sum_array, sum_vect);
			pk_B[i * LWE_L + j] = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] + sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];


#if defined(CCA_CATEGORY1_N663)
			    if (k == iter_k && mod4 != 0) {
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N] * S[idx_N * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+1] * S[(idx_N+1) * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+2] * S[(idx_N+2) * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+3] * S[(idx_N+3) * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+4] * S[(idx_N+4) * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+5] * S[(idx_N+5) * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+6] * S[(idx_N+6) * LWE_L + j];
			    }
			    pk_B[i * LWE_L + j] = sum;
#endif

#if defined(CCA_CATEGORY1_N1300)
			    if (k == iter_k && mod4 != 0) {
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N] * S[idx_N * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+1] * S[(idx_N+1) * LWE_L + j];
				    pk_B[i * LWE_L + j] += pk_A[i * LWE_N + idx_N+2] * S[(idx_N+2) * LWE_L + j];
				    pk_B[i * LLWE_ + j] += pk_A[i * LWE_N + idx_N+3] * S[(idx_N+3) * LWE_L + j];
			    }
			    pk_B[i * LWE_L + j] = sum;
#endif


			}
		}
//*/

	for (i = 0; i < LWE_M; ++i) {
		for (j = 0; j < LWE_L; ++j) {
			pk[PublicKey_A + (i * LWE_L * 2) + (j * 2)] = pk_B[i * LWE_L + j] >> 8;
			pk[PublicKey_A + (i * LWE_L * 2) + (j * 2 + 1)] = pk_B[i * LWE_L + j] & 0xff;
		}
	}

	free(pk_A);
	free(pk_B);

	return 0;
}