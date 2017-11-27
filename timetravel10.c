#include "timetravel10.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

#define HASH_FUNC_BASE_TIMESTAMP 1492973331 // BitCore: Genesis Timestamp
#define HASH_FUNC_COUNT 10                  // BitCore: HASH_FUNC_COUNT of 11
#define HASH_FUNC_COUNT_PERMUTATIONS 40320 // BitCore: HASH_FUNC_COUNT! 

extern uint32_t permutations[];

void timetravel10_hash(const char* input, char* output, uint32_t len)
{
	uint32_t hash[16], i;
	uint32_t time = ((uint32_t *)input)[17];
	uint32_t permutation = permutations[(time - HASH_FUNC_BASE_TIMESTAMP) % HASH_FUNC_COUNT_PERMUTATIONS];

	sph_blake512_context	ctx_blake;
	sph_bmw512_context		ctx_bmw;
	sph_groestl512_context	ctx_groestl;
	sph_skein512_context	ctx_skein;
	sph_jh512_context		ctx_jh;
	sph_keccak512_context	ctx_keccak;
	sph_luffa512_context	ctx_luffa;
	sph_cubehash512_context	ctx_cubehash;
	sph_shavite512_context	ctx_shavite;
	sph_simd512_context		ctx_simd;

	memset(hash, 0, 16 * sizeof(uint32_t));

	sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, input, 80);
	sph_blake512_close(&ctx_blake, hash);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512(&ctx_bmw, hash, 64);
	sph_bmw512_close(&ctx_bmw, hash);

	for (i = 0; i < (4 * (HASH_FUNC_COUNT - 2)); i += 4) {
		switch ((permutation >> i) & 0xf) {

		case 0:
			sph_groestl512_init(&ctx_groestl);
			sph_groestl512(&ctx_groestl, hash, 64);
			sph_groestl512_close(&ctx_groestl, hash);
			break;
		case 1:
			sph_skein512_init(&ctx_skein);
			sph_skein512(&ctx_skein, hash, 64);
			sph_skein512_close(&ctx_skein, hash);
			break;
		case 2:
			sph_jh512_init(&ctx_jh);
			sph_jh512(&ctx_jh, hash, 64);
			sph_jh512_close(&ctx_jh, hash);
			break;
		case 3:
			sph_keccak512_init(&ctx_keccak);
			sph_keccak512(&ctx_keccak, hash, 64);
			sph_keccak512_close(&ctx_keccak, hash);
			break;
		case 4:
			sph_luffa512_init(&ctx_luffa);
			sph_luffa512(&ctx_luffa, hash, 64);
			sph_luffa512_close(&ctx_luffa, hash);
			break;
		case 5:
			sph_cubehash512_init(&ctx_cubehash);
			sph_cubehash512(&ctx_cubehash, hash, 64);
			sph_cubehash512_close(&ctx_cubehash, hash);
			break;
		case 6:
			sph_shavite512_init(&ctx_shavite);
			sph_shavite512(&ctx_shavite, hash, 64);
			sph_shavite512_close(&ctx_shavite, hash);
			break;
		case 7:
			sph_simd512_init(&ctx_simd);
			sph_simd512(&ctx_simd, hash, 64);
			sph_simd512_close(&ctx_simd, hash);
			break;
		}
	}

	memcpy(output, hash, 32);
}