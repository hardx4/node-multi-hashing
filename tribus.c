#include "tribus.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_echo.h"


void tribus_hash(const char* input, char* output, uint32_t len)
{    
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;   
    sph_echo512_context     ctx_echo1;    

    //these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t hash[64];

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, input, 80);
    sph_jh512_close(&ctx_jh, hash);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hash, 64);
    sph_keccak512_close(&ctx_keccak, hash);    

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, hash, 64);
    sph_echo512_close(&ctx_echo1, hash);

    memcpy(output, hash, 32);

}
