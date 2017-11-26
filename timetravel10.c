#include "timetravel10.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "algo/luffa/sse2/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "sha3/sph_shavite.h"
#include "algo/simd/sse2/nist.h"
#include "sha3/sph_groestl.h"

#define HASH_FUNC_BASE_TIMESTAMP 1492973331U // BitCore: Genesis Timestamp
#define HASH_FUNC_COUNT 10
#define HASH_FUNC_COUNT_PERMUTATIONS 40320

#define _ALIGN(x) __attribute__ ((aligned(x)))

// helpers
inline void swap(int *a, int *b) {
	int c = *a;
	*a = *b;
	*b = c;
}

static void reverse(int *pbegin, int *pend) {
	while ((pbegin != pend) && (pbegin != --pend))
		swap(pbegin, pend);
	    pbegin++;
}

static void next_permutation(int *pbegin, int *pend) 
{
	if (pbegin == pend)
		return;

	int *i = pbegin;
	++i;
	if (i == pend)
		return;

	i = pend;
	--i;

	while (1)
	{
		int *j = i;
		--i;

		if (*i < *j)
		{
			int *k = pend;

			while (!(*i < *--k)) /* do nothing */;

			swap(i, k);
			reverse(j, pend);
			return; // true
		}

		if (i == pbegin)
		{
			reverse(pbegin, pend);
			return; // false
		}
		// else?
	}
}
// helpers

void timetravel10_hash(const char* input, char* output, uint32_t len)
{
	uint32_t hash[16 * HASH_FUNC_COUNT] __attribute__((aligned(64)));
	uint32_t *hashA, *hashB;
	uint32_t dataLen = 64;
	uint32_t *work_data = (uint32_t *)input;
	uint32_t timestamp = work_data[17];
	int i;
	const int midlen = 64;          // bytes
	const int tail = 80 - midlen;   // 16

	sph_blake512_context    ctx_blake;
	sph_bmw512_context      ctx_bmw;
	sph_skein512_context    ctx_skein;
	sph_jh512_context       ctx_jh;
	sph_keccak512_context   ctx_keccak;
	hashState_luffa         ctx_luffa;
	cubehashParam           ctx_cubehash;
	sph_shavite512_context  ctx_shavite;
	hashState_sd            ctx_simd;
	sph_groestl512_context  ctx_groestl;

	// We want to permute algorithms. To get started we
	// initialize an array with a sorted sequence of unique
	// integers where every integer represents its own algorithm.
	uint32_t permutation[HASH_FUNC_COUNT];
	for (uint32_t i = 0; i < HASH_FUNC_COUNT; i++) {
		permutation[i] = i;
	}

	// Compute the next permuation
	uint32_t steps = (timestamp - HASH_FUNC_BASE_TIMESTAMP) % HASH_FUNC_COUNT_PERMUTATIONS;
	for (uint32_t i = 0; i < steps; i++) {
		next_permutation(permutation, permutation + HASH_FUNC_COUNT);
	}

	for (uint32_t i = 0; i < HASH_FUNC_COUNT; i++) {
		if (i == 0) {
			dataLen = 80;
			hashA = work_data;
		}
		else {
			dataLen = 64;
			hashA = &hash[16 * (i - 1)];
		}
		hashB = &hash[16 * i];

		switch (permutation[i]) {
		case 0:
			if (i == 0)
			{
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, input + midlen, tail);
				sph_blake512_close(&ctx_blake, hashB);
			}
			else
			{
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, hashA, dataLen);
				sph_blake512_close(&ctx_blake, hashB);
			}
			break;
		case 1:
			if (i == 0)
			{
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512(&ctx_bmw, input + midlen, tail);
				sph_bmw512_close(&ctx_bmw, hashB);
			}
			else
			{
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512(&ctx_bmw, hashA, dataLen);
				sph_bmw512_close(&ctx_bmw, hashB);
			}
			break;
		case 2:
			if (i == 0)
			{
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, input + midlen, tail);
				sph_groestl512_close(&ctx_groestl, hashB);
			}
			else
			{
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, hashA, dataLen);
				sph_groestl512_close(&ctx_groestl, hashB);
			}
			break;
		case 3:
			if (i == 0)
			{
				sph_skein512_init(&ctx_skein);
				sph_skein512(&ctx_skein, input + midlen, tail);
				sph_skein512_close(&ctx_skein, hashB);
			}
			else
			{
				sph_skein512_init(&ctx_skein);
				sph_skein512(&ctx_skein, hashA, dataLen);
				sph_skein512_close(&ctx_skein, hashB);
			}
			break;
		case 4:
			if (i == 0)
			{
				sph_jh512_init(&ctx_jh);
				sph_jh512(&ctx_jh, input + midlen, tail);
				sph_jh512_close(&ctx_jh, hashB);
			}
			else
			{
				sph_jh512_init(&ctx_jh);
				sph_jh512(&ctx_jh, hashA, dataLen);
				sph_jh512_close(&ctx_jh, hashB);
			}
			break;
		case 5:
			if (i == 0)
			{
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512(&ctx_keccak, input + midlen, tail);
				sph_keccak512_close(&ctx_keccak, hashB);
			}
			else
			{
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512(&ctx_keccak, hashA, dataLen);
				sph_keccak512_close(&ctx_keccak, hashB);
			}
			break;
		case 6:
			if (i == 0)
			{
				init_luffa(&ctx_luffa, 512);
				update_and_final_luffa(&ctx_luffa, (BitSequence*)hashB,
					(const BitSequence *)input + 64, 16);
			}
			else
			{
				init_luffa(&ctx_luffa, 512);
				update_and_final_luffa(&ctx_luffa, (BitSequence*)hashB,
					(const BitSequence *)hashA, dataLen);
			}
			break;
		case 7:
			if (i == 0)
			{
				cubehashInit(&ctx_cubehash, 512, 16, 32);
				cubehashUpdateDigest(&ctx_cubehash, (byte*)hashB,
					(const byte*)input + midlen, tail);
			}
			else
			{
				cubehashInit(&ctx_cubehash, 512, 16, 32);
				cubehashUpdateDigest(&ctx_cubehash, (byte*)hashB, (const byte*)hashA,
					dataLen);
			}
			break;
		case 8:
			if (i == 0)
			{
				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, input + midlen, tail * 8);
				sph_shavite512_close(&ctx_shavite, hashB);
			}
			else
			{
				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, hashA, dataLen);
				sph_shavite512_close(&ctx_shavite, hashB);
			}
			break;
		case 9:
			if (i == 0)
			{
				init_sd(&ctx_simd, 512);
				update_final_sd(&ctx_simd, (BitSequence *)hashB,
					(const BitSequence *)input + midlen, tail * 8);
			}
			else
			{
				init_sd(&ctx_simd, 512);
				update_final_sd(&ctx_simd, (BitSequence *)hashB,
					(const BitSequence *)hashA, dataLen * 8);
			}
			break;
		default:
			break;
		}
	}

	memcpy(output, &hash[16 * (HASH_FUNC_COUNT - 1)], 32);
}