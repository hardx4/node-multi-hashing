#include "polytimos.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_skein.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_shabal.h"
#include "sha3/gost_streebog.h"

void polytimos_hash(const char *input, char* output, uint32_t len)
{
	uint32_t hashA[16];

	sph_skein512_context ctx_skein;
	sph_shabal512_context ctx_shabal;
	sph_echo512_context ctx_echo;
	sph_luffa512_context ctx_luffa;
	sph_fugue512_context ctx_fugue;
	sph_gost512_context ctx_gost;

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, hashA);

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hashA, 64);
	sph_shabal512_close(&ctx_shabal, hashA);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, hashA, 64);
	sph_echo512_close(&ctx_echo, hashA);

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, hashA, 64);
	sph_luffa512_close(&ctx_luffa, hashA);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, hashA, 64);
	sph_fugue512_close(&ctx_fugue, hashA);

	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx_gost, hashA, 64);
	sph_gost512_close(&ctx_gost, hashA);

	memcpy(output, hashA, 32);
}

