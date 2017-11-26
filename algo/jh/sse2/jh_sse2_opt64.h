/*This program gives the optimized SSE2 bitslice implementation of JH for 64-bit platform (with 16 128-bit XMM registers).

   --------------------------------
   Performance

   Microprocessor: Intel CORE 2 processor (Core 2 Duo Mobile T6600 2.2GHz)
   Operating System: 64-bit Ubuntu 10.04 (Linux kernel 2.6.32-22-generic)
   Speed for long message:
   1) 19.9 cycles/byte   compiler: Intel C++ Compiler 11.1   compilation option: icc -O3
   2) 20.9 cycles/byte   compiler: gcc 4.4.3                 compilation option: gcc -msse2 -O3

   --------------------------------
   Compare with the original JH sse2 code (October 2008) for 64-bit platform, we made the modifications:
   a) The Sbox implementation follows exactly the description given in the document
   b) Data alignment definition is improved so that the code can be compiled by GCC, Intel C++ compiler and Microsoft Visual C compiler
   c) Using y0,y1,..,y7 variables in Function F8 for performance improvement (local variable in function F8 so that compiler can optimize the code easily)
   d) Removed a number of intermediate variables from the program (so as to given compiler more freedom to optimize the code)
   e) Using "for" loop to implement 42 rounds (with 7 rounds in each loop), so as to reduce the code size.

   --------------------------------
   Last Modified: January 16, 2011
*/


#include <emmintrin.h>
#include <stdint.h>
#include <string.h>
#include "algo/sha/sha3-defs.h"

typedef __m128i  word128;   /*word128 defines a 128-bit SSE2 word*/
typedef enum {jhSUCCESS = 0, jhFAIL = 1, jhBAD_HASHLEN = 2} jhReturn;

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

typedef struct {
      DataLength jhbitlen;	                /*the message digest size*/
      DataLength databitlen;    /*the message size in bits*/
      DataLength datasize_in_buffer;           /*the size of the message remained in buffer; assumed to be multiple of 8bits except for the last partial block at the end of the message*/
      word128  x0,x1,x2,x3,x4,x5,x6,x7; /*1024-bit state;*/
      unsigned char buffer[64];         /*512-bit message block;*/
} jhState;

#define DECL_JH \
    word128 jhSx0,jhSx1,jhSx2,jhSx3,jhSx4,jhSx5,jhSx6,jhSx7; \
    unsigned char jhSbuffer[64];


/*The initial hash value H(0)*/
static DATA_ALIGN16(const unsigned char JH512_H0[128])={0x6f,0xd1,0x4b,0x96,0x3e,0x0,0xaa,0x17,0x63,0x6a,0x2e,0x5,0x7a,0x15,0xd5,0x43,0x8a,0x22,0x5e,0x8d,0xc,0x97,0xef,0xb,0xe9,0x34,0x12,0x59,0xf2,0xb3,0xc3,0x61,0x89,0x1d,0xa0,0xc1,0x53,0x6f,0x80,0x1e,0x2a,0xa9,0x5,0x6b,0xea,0x2b,0x6d,0x80,0x58,0x8e,0xcc,0xdb,0x20,0x75,0xba,0xa6,0xa9,0xf,0x3a,0x76,0xba,0xf8,0x3b,0xf7,0x1,0x69,0xe6,0x5,0x41,0xe3,0x4a,0x69,0x46,0xb5,0x8a,0x8e,0x2e,0x6f,0xe6,0x5a,0x10,0x47,0xa7,0xd0,0xc1,0x84,0x3c,0x24,0x3b,0x6e,0x71,0xb1,0x2d,0x5a,0xc1,0x99,0xcf,0x57,0xf6,0xec,0x9d,0xb1,0xf8,0x56,0xa7,0x6,0x88,0x7c,0x57,0x16,0xb1,0x56,0xe3,0xc2,0xfc,0xdf,0xe6,0x85,0x17,0xfb,0x54,0x5a,0x46,0x78,0xcc,0x8c,0xdd,0x4b};

/*42 round constants, each round constant is 32-byte (256-bit)*/
static DATA_ALIGN16(const unsigned char jhE8_bitslice_roundconstant[42][32])={
{0x72,0xd5,0xde,0xa2,0xdf,0x15,0xf8,0x67,0x7b,0x84,0x15,0xa,0xb7,0x23,0x15,0x57,0x81,0xab,0xd6,0x90,0x4d,0x5a,0x87,0xf6,0x4e,0x9f,0x4f,0xc5,0xc3,0xd1,0x2b,0x40},
{0xea,0x98,0x3a,0xe0,0x5c,0x45,0xfa,0x9c,0x3,0xc5,0xd2,0x99,0x66,0xb2,0x99,0x9a,0x66,0x2,0x96,0xb4,0xf2,0xbb,0x53,0x8a,0xb5,0x56,0x14,0x1a,0x88,0xdb,0xa2,0x31},
{0x3,0xa3,0x5a,0x5c,0x9a,0x19,0xe,0xdb,0x40,0x3f,0xb2,0xa,0x87,0xc1,0x44,0x10,0x1c,0x5,0x19,0x80,0x84,0x9e,0x95,0x1d,0x6f,0x33,0xeb,0xad,0x5e,0xe7,0xcd,0xdc},
{0x10,0xba,0x13,0x92,0x2,0xbf,0x6b,0x41,0xdc,0x78,0x65,0x15,0xf7,0xbb,0x27,0xd0,0xa,0x2c,0x81,0x39,0x37,0xaa,0x78,0x50,0x3f,0x1a,0xbf,0xd2,0x41,0x0,0x91,0xd3},
{0x42,0x2d,0x5a,0xd,0xf6,0xcc,0x7e,0x90,0xdd,0x62,0x9f,0x9c,0x92,0xc0,0x97,0xce,0x18,0x5c,0xa7,0xb,0xc7,0x2b,0x44,0xac,0xd1,0xdf,0x65,0xd6,0x63,0xc6,0xfc,0x23},
{0x97,0x6e,0x6c,0x3,0x9e,0xe0,0xb8,0x1a,0x21,0x5,0x45,0x7e,0x44,0x6c,0xec,0xa8,0xee,0xf1,0x3,0xbb,0x5d,0x8e,0x61,0xfa,0xfd,0x96,0x97,0xb2,0x94,0x83,0x81,0x97},
{0x4a,0x8e,0x85,0x37,0xdb,0x3,0x30,0x2f,0x2a,0x67,0x8d,0x2d,0xfb,0x9f,0x6a,0x95,0x8a,0xfe,0x73,0x81,0xf8,0xb8,0x69,0x6c,0x8a,0xc7,0x72,0x46,0xc0,0x7f,0x42,0x14},
{0xc5,0xf4,0x15,0x8f,0xbd,0xc7,0x5e,0xc4,0x75,0x44,0x6f,0xa7,0x8f,0x11,0xbb,0x80,0x52,0xde,0x75,0xb7,0xae,0xe4,0x88,0xbc,0x82,0xb8,0x0,0x1e,0x98,0xa6,0xa3,0xf4},
{0x8e,0xf4,0x8f,0x33,0xa9,0xa3,0x63,0x15,0xaa,0x5f,0x56,0x24,0xd5,0xb7,0xf9,0x89,0xb6,0xf1,0xed,0x20,0x7c,0x5a,0xe0,0xfd,0x36,0xca,0xe9,0x5a,0x6,0x42,0x2c,0x36},
{0xce,0x29,0x35,0x43,0x4e,0xfe,0x98,0x3d,0x53,0x3a,0xf9,0x74,0x73,0x9a,0x4b,0xa7,0xd0,0xf5,0x1f,0x59,0x6f,0x4e,0x81,0x86,0xe,0x9d,0xad,0x81,0xaf,0xd8,0x5a,0x9f},
{0xa7,0x5,0x6,0x67,0xee,0x34,0x62,0x6a,0x8b,0xb,0x28,0xbe,0x6e,0xb9,0x17,0x27,0x47,0x74,0x7,0x26,0xc6,0x80,0x10,0x3f,0xe0,0xa0,0x7e,0x6f,0xc6,0x7e,0x48,0x7b},
{0xd,0x55,0xa,0xa5,0x4a,0xf8,0xa4,0xc0,0x91,0xe3,0xe7,0x9f,0x97,0x8e,0xf1,0x9e,0x86,0x76,0x72,0x81,0x50,0x60,0x8d,0xd4,0x7e,0x9e,0x5a,0x41,0xf3,0xe5,0xb0,0x62},
{0xfc,0x9f,0x1f,0xec,0x40,0x54,0x20,0x7a,0xe3,0xe4,0x1a,0x0,0xce,0xf4,0xc9,0x84,0x4f,0xd7,0x94,0xf5,0x9d,0xfa,0x95,0xd8,0x55,0x2e,0x7e,0x11,0x24,0xc3,0x54,0xa5},
{0x5b,0xdf,0x72,0x28,0xbd,0xfe,0x6e,0x28,0x78,0xf5,0x7f,0xe2,0xf,0xa5,0xc4,0xb2,0x5,0x89,0x7c,0xef,0xee,0x49,0xd3,0x2e,0x44,0x7e,0x93,0x85,0xeb,0x28,0x59,0x7f},
{0x70,0x5f,0x69,0x37,0xb3,0x24,0x31,0x4a,0x5e,0x86,0x28,0xf1,0x1d,0xd6,0xe4,0x65,0xc7,0x1b,0x77,0x4,0x51,0xb9,0x20,0xe7,0x74,0xfe,0x43,0xe8,0x23,0xd4,0x87,0x8a},
{0x7d,0x29,0xe8,0xa3,0x92,0x76,0x94,0xf2,0xdd,0xcb,0x7a,0x9,0x9b,0x30,0xd9,0xc1,0x1d,0x1b,0x30,0xfb,0x5b,0xdc,0x1b,0xe0,0xda,0x24,0x49,0x4f,0xf2,0x9c,0x82,0xbf},
{0xa4,0xe7,0xba,0x31,0xb4,0x70,0xbf,0xff,0xd,0x32,0x44,0x5,0xde,0xf8,0xbc,0x48,0x3b,0xae,0xfc,0x32,0x53,0xbb,0xd3,0x39,0x45,0x9f,0xc3,0xc1,0xe0,0x29,0x8b,0xa0},
{0xe5,0xc9,0x5,0xfd,0xf7,0xae,0x9,0xf,0x94,0x70,0x34,0x12,0x42,0x90,0xf1,0x34,0xa2,0x71,0xb7,0x1,0xe3,0x44,0xed,0x95,0xe9,0x3b,0x8e,0x36,0x4f,0x2f,0x98,0x4a},
{0x88,0x40,0x1d,0x63,0xa0,0x6c,0xf6,0x15,0x47,0xc1,0x44,0x4b,0x87,0x52,0xaf,0xff,0x7e,0xbb,0x4a,0xf1,0xe2,0xa,0xc6,0x30,0x46,0x70,0xb6,0xc5,0xcc,0x6e,0x8c,0xe6},
{0xa4,0xd5,0xa4,0x56,0xbd,0x4f,0xca,0x0,0xda,0x9d,0x84,0x4b,0xc8,0x3e,0x18,0xae,0x73,0x57,0xce,0x45,0x30,0x64,0xd1,0xad,0xe8,0xa6,0xce,0x68,0x14,0x5c,0x25,0x67},
{0xa3,0xda,0x8c,0xf2,0xcb,0xe,0xe1,0x16,0x33,0xe9,0x6,0x58,0x9a,0x94,0x99,0x9a,0x1f,0x60,0xb2,0x20,0xc2,0x6f,0x84,0x7b,0xd1,0xce,0xac,0x7f,0xa0,0xd1,0x85,0x18},
{0x32,0x59,0x5b,0xa1,0x8d,0xdd,0x19,0xd3,0x50,0x9a,0x1c,0xc0,0xaa,0xa5,0xb4,0x46,0x9f,0x3d,0x63,0x67,0xe4,0x4,0x6b,0xba,0xf6,0xca,0x19,0xab,0xb,0x56,0xee,0x7e},
{0x1f,0xb1,0x79,0xea,0xa9,0x28,0x21,0x74,0xe9,0xbd,0xf7,0x35,0x3b,0x36,0x51,0xee,0x1d,0x57,0xac,0x5a,0x75,0x50,0xd3,0x76,0x3a,0x46,0xc2,0xfe,0xa3,0x7d,0x70,0x1},
{0xf7,0x35,0xc1,0xaf,0x98,0xa4,0xd8,0x42,0x78,0xed,0xec,0x20,0x9e,0x6b,0x67,0x79,0x41,0x83,0x63,0x15,0xea,0x3a,0xdb,0xa8,0xfa,0xc3,0x3b,0x4d,0x32,0x83,0x2c,0x83},
{0xa7,0x40,0x3b,0x1f,0x1c,0x27,0x47,0xf3,0x59,0x40,0xf0,0x34,0xb7,0x2d,0x76,0x9a,0xe7,0x3e,0x4e,0x6c,0xd2,0x21,0x4f,0xfd,0xb8,0xfd,0x8d,0x39,0xdc,0x57,0x59,0xef},
{0x8d,0x9b,0xc,0x49,0x2b,0x49,0xeb,0xda,0x5b,0xa2,0xd7,0x49,0x68,0xf3,0x70,0xd,0x7d,0x3b,0xae,0xd0,0x7a,0x8d,0x55,0x84,0xf5,0xa5,0xe9,0xf0,0xe4,0xf8,0x8e,0x65},
{0xa0,0xb8,0xa2,0xf4,0x36,0x10,0x3b,0x53,0xc,0xa8,0x7,0x9e,0x75,0x3e,0xec,0x5a,0x91,0x68,0x94,0x92,0x56,0xe8,0x88,0x4f,0x5b,0xb0,0x5c,0x55,0xf8,0xba,0xbc,0x4c},
{0xe3,0xbb,0x3b,0x99,0xf3,0x87,0x94,0x7b,0x75,0xda,0xf4,0xd6,0x72,0x6b,0x1c,0x5d,0x64,0xae,0xac,0x28,0xdc,0x34,0xb3,0x6d,0x6c,0x34,0xa5,0x50,0xb8,0x28,0xdb,0x71},
{0xf8,0x61,0xe2,0xf2,0x10,0x8d,0x51,0x2a,0xe3,0xdb,0x64,0x33,0x59,0xdd,0x75,0xfc,0x1c,0xac,0xbc,0xf1,0x43,0xce,0x3f,0xa2,0x67,0xbb,0xd1,0x3c,0x2,0xe8,0x43,0xb0},
{0x33,0xa,0x5b,0xca,0x88,0x29,0xa1,0x75,0x7f,0x34,0x19,0x4d,0xb4,0x16,0x53,0x5c,0x92,0x3b,0x94,0xc3,0xe,0x79,0x4d,0x1e,0x79,0x74,0x75,0xd7,0xb6,0xee,0xaf,0x3f},
{0xea,0xa8,0xd4,0xf7,0xbe,0x1a,0x39,0x21,0x5c,0xf4,0x7e,0x9,0x4c,0x23,0x27,0x51,0x26,0xa3,0x24,0x53,0xba,0x32,0x3c,0xd2,0x44,0xa3,0x17,0x4a,0x6d,0xa6,0xd5,0xad},
{0xb5,0x1d,0x3e,0xa6,0xaf,0xf2,0xc9,0x8,0x83,0x59,0x3d,0x98,0x91,0x6b,0x3c,0x56,0x4c,0xf8,0x7c,0xa1,0x72,0x86,0x60,0x4d,0x46,0xe2,0x3e,0xcc,0x8,0x6e,0xc7,0xf6},
{0x2f,0x98,0x33,0xb3,0xb1,0xbc,0x76,0x5e,0x2b,0xd6,0x66,0xa5,0xef,0xc4,0xe6,0x2a,0x6,0xf4,0xb6,0xe8,0xbe,0xc1,0xd4,0x36,0x74,0xee,0x82,0x15,0xbc,0xef,0x21,0x63},
{0xfd,0xc1,0x4e,0xd,0xf4,0x53,0xc9,0x69,0xa7,0x7d,0x5a,0xc4,0x6,0x58,0x58,0x26,0x7e,0xc1,0x14,0x16,0x6,0xe0,0xfa,0x16,0x7e,0x90,0xaf,0x3d,0x28,0x63,0x9d,0x3f},
{0xd2,0xc9,0xf2,0xe3,0x0,0x9b,0xd2,0xc,0x5f,0xaa,0xce,0x30,0xb7,0xd4,0xc,0x30,0x74,0x2a,0x51,0x16,0xf2,0xe0,0x32,0x98,0xd,0xeb,0x30,0xd8,0xe3,0xce,0xf8,0x9a},
{0x4b,0xc5,0x9e,0x7b,0xb5,0xf1,0x79,0x92,0xff,0x51,0xe6,0x6e,0x4,0x86,0x68,0xd3,0x9b,0x23,0x4d,0x57,0xe6,0x96,0x67,0x31,0xcc,0xe6,0xa6,0xf3,0x17,0xa,0x75,0x5},
{0xb1,0x76,0x81,0xd9,0x13,0x32,0x6c,0xce,0x3c,0x17,0x52,0x84,0xf8,0x5,0xa2,0x62,0xf4,0x2b,0xcb,0xb3,0x78,0x47,0x15,0x47,0xff,0x46,0x54,0x82,0x23,0x93,0x6a,0x48},
{0x38,0xdf,0x58,0x7,0x4e,0x5e,0x65,0x65,0xf2,0xfc,0x7c,0x89,0xfc,0x86,0x50,0x8e,0x31,0x70,0x2e,0x44,0xd0,0xb,0xca,0x86,0xf0,0x40,0x9,0xa2,0x30,0x78,0x47,0x4e},
{0x65,0xa0,0xee,0x39,0xd1,0xf7,0x38,0x83,0xf7,0x5e,0xe9,0x37,0xe4,0x2c,0x3a,0xbd,0x21,0x97,0xb2,0x26,0x1,0x13,0xf8,0x6f,0xa3,0x44,0xed,0xd1,0xef,0x9f,0xde,0xe7},
{0x8b,0xa0,0xdf,0x15,0x76,0x25,0x92,0xd9,0x3c,0x85,0xf7,0xf6,0x12,0xdc,0x42,0xbe,0xd8,0xa7,0xec,0x7c,0xab,0x27,0xb0,0x7e,0x53,0x8d,0x7d,0xda,0xaa,0x3e,0xa8,0xde},
{0xaa,0x25,0xce,0x93,0xbd,0x2,0x69,0xd8,0x5a,0xf6,0x43,0xfd,0x1a,0x73,0x8,0xf9,0xc0,0x5f,0xef,0xda,0x17,0x4a,0x19,0xa5,0x97,0x4d,0x66,0x33,0x4c,0xfd,0x21,0x6a},
{0x35,0xb4,0x98,0x31,0xdb,0x41,0x15,0x70,0xea,0x1e,0xf,0xbb,0xed,0xcd,0x54,0x9b,0x9a,0xd0,0x63,0xa1,0x51,0x97,0x40,0x72,0xf6,0x75,0x9d,0xbf,0x91,0x47,0x6f,0xe2}};


//static void jhF8(jhState *state);    /* the compression function F8 */

/*The API functions*/

/*The following defines operations on 128-bit word(s)*/
#define jhCONSTANT(b)   _mm_set1_epi8((b))          /*set each byte in a 128-bit register to be "b"*/

#define jhXOR(x,y)      _mm_xor_si128((x),(y))      /*jhXOR(x,y) = x ^ y, where x and y are two 128-bit word*/
#define jhAND(x,y)      _mm_and_si128((x),(y))      /*jhAND(x,y) = x & y, where x and y are two 128-bit word*/
#define jhANDNOT(x,y)   _mm_andnot_si128((x),(y))   /*jhANDNOT(x,y) = (!x) & y, where x and y are two 128-bit word*/
#define jhOR(x,y)       _mm_or_si128((x),(y))       /*jhOR(x,y)  = x | y, where x and y are two 128-bit word*/

#define jhSHR1(x)       _mm_srli_epi16((x), 1)      /*jhSHR1(x)  = x >> 1, where x is a 128 bit word*/
#define jhSHR2(x)       _mm_srli_epi16((x), 2)      /*jhSHR2(x)  = x >> 2, where x is a 128 bit word*/
#define jhSHR4(x)       _mm_srli_epi16((x), 4)      /*jhSHR4(x)  = x >> 4, where x is a 128 bit word*/
#define jhSHR8(x)       _mm_slli_epi16((x), 8)      /*jhSHR8(x)  = x >> 8, where x is a 128 bit word*/
#define jhSHR16(x)      _mm_slli_epi32((x), 16)     /*jhSHR16(x) = x >> 16, where x is a 128 bit word*/
#define jhSHR32(x)      _mm_slli_epi64((x), 32)     /*jhSHR32(x) = x >> 32, where x is a 128 bit word*/
#define jhSHR64(x)      _mm_slli_si128((x), 8)      /*jhSHR64(x) = x >> 64, where x is a 128 bit word*/

#define jhSHL1(x)       _mm_slli_epi16((x), 1)      /*jhSHL1(x)  = x << 1, where x is a 128 bit word*/
#define jhSHL2(x)       _mm_slli_epi16((x), 2)	  /*jhSHL2(x)  = x << 2, where x is a 128 bit word*/
#define jhSHL4(x)       _mm_slli_epi16((x), 4)	  /*jhSHL4(x)  = x << 4, where x is a 128 bit word*/
#define jhSHL8(x)       _mm_srli_epi16((x), 8)	  /*jhSHL8(x)  = x << 8, where x is a 128 bit word*/
#define jhSHL16(x)      _mm_srli_epi32((x), 16)	  /*jhSHL16(x) = x << 16, where x is a 128 bit word*/
#define jhSHL32(x)      _mm_srli_epi64((x), 32)	  /*jhSHL32(x) = x << 32, where x is a 128 bit word*/
#define jhSHL64(x)      _mm_srli_si128((x), 8)	  /*jhSHL64(x) = x << 64, where x is a 128 bit word*/

#define jhSWAP1(x)      jhOR(jhSHR1(jhAND((x),jhCONSTANT(0xaa))),jhSHL1(jhAND((x),jhCONSTANT(0x55))))  /*swapping bit 2i with bit 2i+1 of the 128-bit x */
#define jhSWAP2(x)      jhOR(jhSHR2(jhAND((x),jhCONSTANT(0xcc))),jhSHL2(jhAND((x),jhCONSTANT(0x33))))  /*swapping bit 4i||4i+1 with bit 4i+2||4i+3 of the 128-bit x */
#define jhSWAP4(x)      jhOR(jhSHR4(jhAND((x),jhCONSTANT(0xf0))),jhSHL4(jhAND((x),jhCONSTANT(0xf))))   /*swapping bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 of the 128-bit x */
#define jhSWAP8(x)      jhOR(jhSHR8(x),jhSHL8(x))                          /*swapping bits 16i||16i+1||...||16i+7 with bits 16i+8||16i+9||...||16i+15 of the 128-bit x */
#define jhSWAP16(x)     jhOR(jhSHR16(x),jhSHL16(x))                        /*swapping bits 32i||32i+1||...||32i+15 with bits 32i+16||32i+17||...||32i+31 of the 128-bit x */
#define jhSWAP32(x)     _mm_shuffle_epi32((x),_MM_SHUFFLE(2,3,0,1))  /*swapping bits 64i||64i+1||...||64i+31 with bits 64i+32||64i+33||...||64i+63 of the 128-bit x*/
#define jhSWAP64(x)     _mm_shuffle_epi32((x),_MM_SHUFFLE(1,0,3,2))  /*swapping bits 128i||128i+1||...||128i+63 with bits 128i+64||128i+65||...||128i+127 of the 128-bit x*/
#define jhSTORE(x,p)    _mm_store_si128((__m128i *)(p), (x))         /*store the 128-bit word x into memeory address p, where p is the multile of 16 bytes*/
#define jhLOAD(p)       _mm_load_si128((__m128i *)(p))               /*load 16 bytes from the memory address p, return a 128-bit word, where p is the multile of 16 bytes*/

/*The MDS code*/
#define jhL(m0,m1,m2,m3,m4,m5,m6,m7)     \
      (m4) = jhXOR((m4),(m1));           \
      (m5) = jhXOR((m5),(m2));           \
      (m6) = jhXOR(jhXOR((m6),(m3)),(m0)); \
      (m7) = jhXOR((m7),(m0));           \
      (m0) = jhXOR((m0),(m5));           \
      (m1) = jhXOR((m1),(m6));           \
      (m2) = jhXOR(jhXOR((m2),(m7)),(m4)); \
      (m3) = jhXOR((m3),(m4));

/*Two Sboxes computed in parallel, each Sbox implements S0 and S1, selected by a constant bit*/
/*The reason to compute two Sboxes in parallel is to try to fully utilize the parallel processing power of SSE2 instructions*/
#define jhSS(m0,m1,m2,m3,m4,m5,m6,m7,constant0,constant1)  \
      m3 = jhXOR(m3,jhCONSTANT(0xff));       \
      m7 = jhXOR(m7,jhCONSTANT(0xff));       \
      m0 = jhXOR(m0,jhANDNOT(m2,constant0)); \
      m4 = jhXOR(m4,jhANDNOT(m6,constant1)); \
      a0 = jhXOR(constant0,jhAND(m0,m1));    \
      a1 = jhXOR(constant1,jhAND(m4,m5));    \
      m0 = jhXOR(m0,jhAND(m3,m2));           \
      m4 = jhXOR(m4,jhAND(m7,m6));           \
      m3 = jhXOR(m3,jhANDNOT(m1,m2));        \
      m7 = jhXOR(m7,jhANDNOT(m5,m6));        \
      m1 = jhXOR(m1,jhAND(m0,m2));           \
      m5 = jhXOR(m5,jhAND(m4,m6));           \
      m2 = jhXOR(m2,jhANDNOT(m3,m0));        \
      m6 = jhXOR(m6,jhANDNOT(m7,m4));        \
      m0 = jhXOR(m0,jhOR(m1,m3));            \
      m4 = jhXOR(m4,jhOR(m5,m7));            \
      m3 = jhXOR(m3,jhAND(m1,m2));           \
      m7 = jhXOR(m7,jhAND(m5,m6));           \
      m2 = jhXOR(m2,a0);                   \
      m6 = jhXOR(m6,a1);                   \
      m1 = jhXOR(m1,jhAND(a0,m0));           \
      m5 = jhXOR(m5,jhAND(a1,m4));

/* The linear transform of the (7*i+0)th round*/
#define jhlineartransform_R00(m0,m1,m2,m3,m4,m5,m6,m7)         \
      /*MDS layer*/                                          \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                            \
      /*swapping bit 2i with bit 2i+1 for m4,m5,m6 and m7 */ \
      m4 = jhSWAP1(m4); m5 = jhSWAP1(m5); m6 = jhSWAP1(m6); m7 = jhSWAP1(m7);

/* The linear transform of the (7*i+1)th round*/
#define jhlineartransform_R01(m0,m1,m2,m3,m4,m5,m6,m7)         \
      /*MDS layer*/                                          \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                            \
      /*swapping bit 4i||4i+1 with bit 4i+2||4i+3 for m4,m5,m6 and m7 */  \
      m4 = jhSWAP2(m4); m5 = jhSWAP2(m5); m6 = jhSWAP2(m6); m7 = jhSWAP2(m7);

/* The linear transform of the (7*i+2)th round*/
#define jhlineartransform_R02(m0,m1,m2,m3,m4,m5,m6,m7)         \
      /*MDS layer*/                                          \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                            \
      /*swapping bits 8i||8i+1||8i+2||8i+3 with bits 8i+4||8i+5||8i+6||8i+7 for m4,m5,m6 and m7*/      \
      m4 = jhSWAP4(m4); m5 = jhSWAP4(m5); m6 = jhSWAP4(m6); m7 = jhSWAP4(m7);

/* The linear transform of the (7*i+3)th round*/
#define jhlineartransform_R03(m0,m1,m2,m3,m4,m5,m6,m7)         \
      /*MDS layer*/                                          \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                            \
      /*swapping bits 16i||16i+1||...||16i+7 with bits 16i+8||16i+9||...||16i+15 for m4,m5,m6 and m7*/  \
      m4 = jhSWAP8(m4); m5 = jhSWAP8(m5); m6 = jhSWAP8(m6); m7 = jhSWAP8(m7);

/* The linear transform of the (7*i+4)th round*/
#define jhlineartransform_R04(m0,m1,m2,m3,m4,m5,m6,m7)  \
      /*MDS layer*/                                   \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                     \
      /*swapping bits 32i||32i+1||...||32i+15 with bits 32i+16||32i+17||...||32i+31 for m0,m1,m2 and m3*/  \
      m4 = jhSWAP16(m4); m5 = jhSWAP16(m5); m6 = jhSWAP16(m6); m7 = jhSWAP16(m7);

/* The linear transform of the (7*i+5)th round -- faster*/
#define jhlineartransform_R05(m0,m1,m2,m3,m4,m5,m6,m7)  \
      /*MDS layer*/                                   \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                     \
      /*swapping bits 64i||64i+1||...||64i+31 with bits 64i+32||64i+33||...||64i+63 for m0,m1,m2 and m3*/  \
      m4 = jhSWAP32(m4); m5 = jhSWAP32(m5); m6 = jhSWAP32(m6); m7 = jhSWAP32(m7);

/* The linear transform of the (7*i+6)th round -- faster*/
#define jhlineartransform_R06(m0,m1,m2,m3,m4,m5,m6,m7)  \
      /*MDS layer*/                                   \
      jhL(m0,m1,m2,m3,m4,m5,m6,m7);                     \
      /*swapping bits 128i||128i+1||...||128i+63 with bits 128i+64||128i+65||...||128i+127 for m0,m1,m2 and m3*/  \
      m4 = jhSWAP64(m4); m5 = jhSWAP64(m5); m6 = jhSWAP64(m6); m7 = jhSWAP64(m7);

/*the round function of E8 */
#define jhround_function(nn,r)                                                              \
      jhSS(y0,y2,y4,y6,y1,y3,y5,y7, jhLOAD(jhE8_bitslice_roundconstant[r]), jhLOAD(jhE8_bitslice_roundconstant[r]+16) ); \
      jhlineartransform_R##nn(y0,y2,y4,y6,y1,y3,y5,y7);

/*the round function of E8 */
#define jhround_functionI(nn,r)                                                              \
      jhSS(jhSx0,jhSx2,jhSx4,jhSx6,jhSx1,jhSx3,jhSx5,jhSx7, jhLOAD(jhE8_bitslice_roundconstant[r]), jhLOAD(jhE8_bitslice_roundconstant[r]+16) ); \
      jhlineartransform_R##nn(jhSx0,jhSx2,jhSx4,jhSx6,jhSx1,jhSx3,jhSx5,jhSx7);

/*
//the compression function F8
static void jhF8(jhState *state)
{
    return;
      uint64_t i;
      word128  y0,y1,y2,y3,y4,y5,y6,y7;
      word128  a0,a1;

      y0 = state->x0,
      y0 = jhXOR(y0, jhLOAD(state->buffer));
      y1 = state->x1,
      y1 = jhXOR(y1, jhLOAD(state->buffer+16));
      y2 = state->x2,
      y2 = jhXOR(y2, jhLOAD(state->buffer+32));
      y3 = state->x3,
      y3 = jhXOR(y3, jhLOAD(state->buffer+48));
      y4 = state->x4;
      y5 = state->x5;
      y6 = state->x6;
      y7 = state->x7;

      //xor the 512-bit message with the fist half of the 1024-bit hash state

      //perform 42 rounds
      for (i = 0; i < 42; i = i+7) {
            jhround_function(00,i);
            jhround_function(01,i+1);
            jhround_function(02,i+2);
            jhround_function(03,i+3);
            jhround_function(04,i+4);
            jhround_function(05,i+5);
            jhround_function(06,i+6);
      }

      //xor the 512-bit message with the second half of the 1024-bit hash state

      state->x0 = y0;
      state->x1 = y1;
      state->x2 = y2;
      state->x3 = y3;
      y4 = jhXOR(y4, jhLOAD(state->buffer)),
      state->x4 = y4;
      y5 = jhXOR(y5, jhLOAD(state->buffer+16)),
      state->x5 = y5;
      y6 = jhXOR(y6, jhLOAD(state->buffer+32)),
      state->x6 = y6;
      y7 = jhXOR(y7, jhLOAD(state->buffer+48)),
      state->x7 = y7;
}
*/

#define jhF8I \
do { \
      uint64_t i; \
      word128  a0,a1; \
      jhSx0 = jhXOR(jhSx0, jhLOAD(jhSbuffer)); \
      jhSx1 = jhXOR(jhSx1, jhLOAD(jhSbuffer+16)); \
      jhSx2 = jhXOR(jhSx2, jhLOAD(jhSbuffer+32)); \
      jhSx3 = jhXOR(jhSx3, jhLOAD(jhSbuffer+48)); \
      for (i = 0; i < 42; i = i+7) { \
            jhround_functionI(00,i); \
            jhround_functionI(01,i+1); \
            jhround_functionI(02,i+2); \
            jhround_functionI(03,i+3); \
            jhround_functionI(04,i+4); \
            jhround_functionI(05,i+5); \
            jhround_functionI(06,i+6); \
      } \
      jhSx4 = jhXOR(jhSx4, jhLOAD(jhSbuffer)); \
      jhSx5 = jhXOR(jhSx5, jhLOAD(jhSbuffer+16)); \
      jhSx6 = jhXOR(jhSx6, jhLOAD(jhSbuffer+32)); \
      jhSx7 = jhXOR(jhSx7, jhLOAD(jhSbuffer+48)); \
} while (0)

/* the whole thing 
 * load from hash 
 * hash = JH512(loaded)
 */
#define JH_H \
do { \
    jhSx0 = jhLOAD(JH512_H0); \
    jhSx1 = jhLOAD(JH512_H0+16); \
    jhSx2 = jhLOAD(JH512_H0+32); \
    jhSx3 = jhLOAD(JH512_H0+48); \
    jhSx4 = jhLOAD(JH512_H0+64); \
    jhSx5 = jhLOAD(JH512_H0+80); \
    jhSx6 = jhLOAD(JH512_H0+96); \
    jhSx7 = jhLOAD(JH512_H0+112); \
    /* for break loop */ \
    /* one inlined copy of JHF8i */ \
    int b = false; \
    memcpy(jhSbuffer, hash, 64); \
    for(;;) { \
        jhF8I; \
        if (b) break; \
        memset(jhSbuffer,0,48); \
        jhSbuffer[0] = 0x80; \
        jhSbuffer[48] = 0x00, \
        jhSbuffer[49] = 0x00, \
        jhSbuffer[50] = 0x00, \
        jhSbuffer[51] = 0x00, \
        jhSbuffer[52] = 0x00, \
        jhSbuffer[53] = 0x00, \
        jhSbuffer[54] = 0x00, \
        jhSbuffer[55] = 0x00; \
        jhSbuffer[56] = ((64*8) >> 56) & 0xff, \
        jhSbuffer[57] = ((64*8) >> 48) & 0xff, \
        jhSbuffer[58] = ((64*8) >> 40) & 0xff, \
        jhSbuffer[59] = ((64*8) >> 32) & 0xff, \
        jhSbuffer[60] = ((64*8) >> 24) & 0xff, \
        jhSbuffer[61] = ((64*8) >> 16) & 0xff, \
        jhSbuffer[62] = ((64*8) >> 8) & 0xff, \
        jhSbuffer[63] = (64*8) & 0xff; \
        b = true; \
    } \
jhSTORE(jhSx4,(char *)(hash)); \
jhSTORE(jhSx5,(char *)(hash)+16); \
jhSTORE(jhSx6,(char *)(hash)+32); \
jhSTORE(jhSx7,(char *)(hash)+48); \
} while (0) 
