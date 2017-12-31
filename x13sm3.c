#include "x13sm3.h"
#include "uint256.h"
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
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_sm3.h"


void x13sm3_hash(const char* input, char* output, uint32_t len)
{
	uint256 hash[34];	

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_skein512_context     ctx_skein;
	sm3_ctx_t				ctx_sm3;
	sph_cubehash512_context  ctx_cubehash;
	sph_shavite512_context   ctx_shavite;
	sph_simd512_context      ctx_simd;
	sph_echo512_context      ctx_echo;
	sph_hamsi512_context     ctx_hamsi;
	sph_fugue512_context     ctx_fugue;

	sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, input, len);
	sph_blake512_close(&ctx_blake, hash[0]);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512(&ctx_bmw, hash[0], 64);
	sph_bmw512_close(&ctx_bmw, hash[2]);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512(&ctx_groestl, hash[2], 64);
	sph_groestl512_close(&ctx_groestl, hash[4]);

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, hash[4], 64);
	sph_skein512_close(&ctx_skein, hash[6]);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, hash[6], 64);
	sph_jh512_close(&ctx_jh, hash[8]);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, hash[8], 64);
	sph_keccak512_close(&ctx_keccak, hash[10]);

	hash[12].SetNull();	//sm3 is 256bit, just in case
	hash[13].SetNull();
	sm3_init(&ctx_sm3);
	sph_sm3(&ctx_sm3, hash[10], 64);
	sph_sm3_close(&ctx_sm3, hash[12]);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, hash[12], 64);
	sph_cubehash512_close(&ctx_cubehash, hash[14]);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, hash[14], 64);
	sph_shavite512_close(&ctx_shavite, hash[16]);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, hash[16], 64);
	sph_simd512_close(&ctx_simd, hash[18]);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hash[18], 64);
	sph_echo512_close(&ctx_echo, hash[20]);

	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512(&ctx_hamsi, hash[20], 64);
	sph_hamsi512_close(&ctx_hamsi, hash[22]);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hash[22], 64);
	sph_fugue512_close(&ctx_fugue, hash[24]);

	memcpy(output, hash, 24);

}
