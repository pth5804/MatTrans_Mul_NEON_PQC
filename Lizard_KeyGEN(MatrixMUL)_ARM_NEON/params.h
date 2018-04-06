#ifndef PARAMS_H
#define PARAMS_H

//#define CCA_CATEGORY1_N536
//#define CCA_CATEGORY1_N663
//#define CCA_CATEGORY3_N816
//#define CCA_CATEGORY3_N952
#define CCA_CATEGORY5_N1088
//#define CCA_CATEGORY5_N1300

#ifdef CCA_CATEGORY1_N536
#define PARAMNAME "Lizard.CCA_CATEGORY1_N536"
#define LWE_N 536		// LWE dim
#define LWE_M 1024		// LWR dim (Number of LWE samples in pk)
#define LWE_L 256
#define LOG_Q 11
#define _16_LOG_Q 5
#define LOG_P 9
#define RD_ADD 0x40 	// 2^(15 - LOG_P)
#define RD_AND 0xff80
#define HR 140			// Hamming weight of coefficient vector r
#define LOG_T 1
#define _16_LOG_T 15
#define T 2
#define DEC_ADD 0x4000	// 2^(15 - LOG_T)
#define LAMBDA 128
#define NOISE_D1		// standard deviation for discrete gaussian distribution
#endif

#ifdef CCA_CATEGORY1_N663
#define PARAMNAME "Lizard.CCA_CATEGORY1_N663"
#define LWE_N 663		// LWE dim
#define LWE_M 1024		// LWR dim (Number of LWE samples in pk)
#define LWE_L 256
#define LOG_Q 10
#define _16_LOG_Q 6
#define LOG_P 8
#define RD_ADD 0x80 	// 2^(15 - LOG_P)
#define RD_AND 0xff00
#define HR 128			// Hamming weight of coefficient vector r
#define LOG_T 1
#define _16_LOG_T 15
#define T 2
#define DEC_ADD 0x4000	// 2^(15 - LOG_T)
#define LAMBDA 128
#define NOISE_D2		// standard deviation for discrete gaussian distribution
#endif

#ifdef CCA_CATEGORY3_N816
#define PARAMNAME "Lizard.CCA_CATEGORY3_N816"
#define LWE_N 816		// LWE dim
#define LWE_M 1024		// LWR dim (Number of LWE samples in pk)
#define LWE_L 384
#define LOG_Q 11
#define _16_LOG_Q 5
#define LOG_P 9
#define RD_ADD 0x40 	// 2^(15 - LOG_P)
#define RD_AND 0xff80
#define HR 200			// Hamming weight of coefficient vector r
#define LOG_T 1
#define _16_LOG_T 15
#define T 2
#define DEC_ADD 0x4000	// 2^(15 - LOG_T)
#define LAMBDA 192
#define NOISE_D3		// standard deviation for discrete gaussian distribution
#endif

#ifdef CCA_CATEGORY3_N952
#define PARAMNAME "Lizard.CCA_CATEGORY3_N952"
#define LWE_N 952		// LWE dim
#define LWE_M 1024		// LWR dim (Number of LWE samples in pk)
#define LWE_L 384
#define LOG_Q 11
#define _16_LOG_Q 5
#define LOG_P 9
#define RD_ADD 0x40 	// 2^(15 - LOG_P)
#define RD_AND 0xff80
#define HR 200			// Hamming weight of coefficient vector r
#define LOG_T 1
#define _16_LOG_T 15
#define T 2
#define DEC_ADD 0x4000	// 2^(15 - LOG_T)
#define LAMBDA 192
#define NOISE_D4		// standard deviation for discrete gaussian distribution
#endif

#ifdef CCA_CATEGORY5_N1088
#define PARAMNAME "Lizard.CCA_CATEGORY5_N1088"
#define LWE_N 1088		// LWE dim
#define LWE_M 2048		// LWR dim (Number of LWE samples in pk)
#define LWE_L 512
#define LOG_Q 12
#define _16_LOG_Q 4
#define LOG_P 10
#define RD_ADD 0x20 	// 2^(15 - LOG_P)
#define RD_AND 0xffC0
#define HR 200			// Hamming weight of coefficient vector r
#define LOG_T 1
#define _16_LOG_T 15
#define T 2
#define DEC_ADD 0x4000	// 2^(15 - LOG_T)
#define LAMBDA 256
#define NOISE_D5		// standard deviation for discrete gaussian distribution
#endif

#ifdef CCA_CATEGORY5_N1300
#define PARAMNAME "Lizard.CCA_CATEGORY5_N1300"
#define LWE_N 1300		// LWE dim
#define LWE_M 1024		// LWR dim (Number of LWE samples in pk)
#define LWE_L 512
#define LOG_Q 11
#define _16_LOG_Q 5
#define LOG_P 9
#define RD_ADD 0x40 	// 2^(15 - LOG_P)
#define RD_AND 0xff80
#define HR 200			// Hamming weight of coefficient vector r
#define LOG_T 1
#define _16_LOG_T 15
#define T 2
#define DEC_ADD 0x4000	// 2^(15 - LOG_T)
#define LAMBDA 256
#define NOISE_D6		// standard deviation for discrete gaussian distribution
#endif

#define KEYGEN Keygen
#define ENCDECTEST EncDecTest_CCA

#endif
