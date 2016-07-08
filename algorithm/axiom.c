#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_shabal.h"

/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_shabal256_context	shabal;
} axiomhash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL axiomhash_context_holder ctx;

void init_axiom_contexts(void *dummy)
{
	sph_shabal256_init(&ctx.shabal);
}

static void axiomhash(void *output, const void *input)
{
	uint32_t hash[65536][8];
	int R = 2;
	int N = 65536;
	int i;

	memset(hash, 0, 65536 * 8 * sizeof(uint32_t));

	sph_shabal256(&ctx.shabal, input, 80);
	sph_shabal256_close(&ctx.shabal, hash[0]);

	for(int i = 1; i < N; i++)
	{
//		sph_shabal256_init(&ctx.shabal);
		sph_shabal256 (&ctx.shabal, hash[i - 1], 8 * sizeof(uint32_t));
		sph_shabal256_close(&ctx.shabal, hash[i]);
	}

	for(int r = 1; r < R; r ++)
	{
		for(int b = 0; b < N; b++)
		{
			int p = b > 0 ? b - 1 : N - 1;
			int q = hash[p][0] % (N - 1);
			int j = (b + q) % N;

//			sph_shabal256_init(&ctx.shabal);
			sph_shabal256 (&ctx.shabal, hash[p], 8 * sizeof(uint32_t));
			sph_shabal256 (&ctx.shabal, hash[j], 8 * sizeof(uint32_t));
			sph_shabal256_close(&ctx.shabal, hash[b]);
		}
	}
	memcpy(output, hash[N - 1], 32);
}

int scanhash_axiom(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));
	uint32_t endiandata[32];

	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0xFFFFF,
		0xFFFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0xFFF00000,
		0xFF000000,
		0
	};

	// we need bigendian data...
	for (int kk=0; kk < 32; kk++) {
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};
	

#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				be32enc(&endiandata[19], n);
				axiomhash(hash64, &endiandata);
#ifndef DEBUG_ALGO
				if ((!(hash64[7] & mask)) && fulltest(hash64, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return true;
				}
#else
				if (!(n % 0x1000) && !thr_id) printf(".");
				if (!(hash64[7] & mask)) {
					printf("[%d]",thr_id);
					if (fulltest(hash64, ptarget)) {
						*hashes_done = n - first_nonce + 1;
						return true;
					}
				}
#endif
			} while (n < max_nonce && !work_restart[thr_id].restart);
			// see blake.c if else to understand the loop on htmax => mask
			break;
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
