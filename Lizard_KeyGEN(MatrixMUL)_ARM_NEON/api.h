#ifndef API_H
#define API_H

#include "params.h"

#define PublicKey_A (LWE_M * LWE_N * 2)
#define PublicKey_B (LWE_M * LWE_L * 2)

#define CRYPTO_SECRETKEYBYTES (LWE_N * LWE_L)
#define CRYPTO_PUBLICKEYBYTES (PublicKey_A + PublicKey_B)

#ifdef CCA_CATEGORY1_N663
#define CRYPTO_BYTES (LWE_L / 8) + LWE_N + LWE_L + (LAMBDA / 4)
#endif
#if defined(CCA_CATEGORY1_N536) || defined(CCA_CATEGORY3_N816) || defined(CCA_CATEGORY3_N952) || defined(CCA_CATEGORY5_N1088) || defined(CCA_CATEGORY5_N1300)
#define CRYPTO_BYTES (LWE_L / 8) + (LWE_N * 2) + (LWE_L * 2) + (LAMBDA / 4)
#endif

#define CRYPTO_ALGNAME PARAMNAME

#endif