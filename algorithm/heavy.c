#include <string.h>
#include <openssl/sha.h>
#include <stdint.h>

#include "miner.h"
#include "sha3/sph_hefty1.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_blake.h"
#include "sha3/sph_groestl.h"


/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_keccak512_context	keccak;
	sph_groestl512_context	groestl;
	sph_blake512_context	blake;
} heavyhash_context_holder;

/* no need to copy, because close reinit the context */
static THREADLOCAL heavyhash_context_holder ctx;

void init_heavy_contexts(void *dummy)
{
	sph_keccak512_init(&ctx.keccak);
	sph_groestl512_init(&ctx.groestl);
	sph_blake512_init(&ctx.blake);
}

/* Combines top 64-bits from each hash into a single hash */
static void combine_hashes(uint32_t *out, uint32_t *hash1, uint32_t *hash2, uint32_t *hash3, uint32_t *hash4)
{
	uint32_t *hash[4] = { hash1, hash2, hash3, hash4 };

	/* Transpose first 64 bits of each hash into out */
	memset(out, 0, 32);
	int bits = 0;
	for (unsigned int i = 7; i >= 6; i--) {
		for (uint32_t mask = 0x80000000; mask; mask >>= 1) {
			for (unsigned int k = 0; k < 4; k++) {
				out[(255 - bits)/32] <<= 1;
				if ((hash[k][i] & mask) != 0)
					out[(255 - bits)/32] |= 1;
				bits++;
			}
		}
	}
}

void heavyhash(void* output, const void* input)
{
	uint32_t hash1[16], hash2[16], hash3[16], hash4[16], hash5[16];

	HEFTY1(input, 80, (unsigned char *)hash1);

	/* HEFTY1 is new, so take an extra security measure to eliminate
	 * the possiblity of collisions:
	 *
	 *	 Hash(x) = SHA256(x + HEFTY1(x))
	 *
	 * N.B. '+' is concatenation.
	 */
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, input, 80);
	SHA256_Update(&sha256, hash1, sizeof(hash1));
	SHA256_Final((unsigned char*)hash2, &sha256);

	/* Additional security: Do not rely on a single cryptographic hash
	 * function.  Instead, combine the outputs of 4 of the most secure
	 * cryptographic hash functions-- SHA256, KECCAK512, GROESTL512
	 * and BLAKE512.
	 */

	sph_keccak512(&ctx.keccak, input, 80);
	sph_keccak512(&ctx.keccak, hash1, sizeof(hash1));
	sph_keccak512_close(&ctx.keccak, hash3);

	sph_groestl512(&ctx.groestl, input, 80);
	sph_groestl512(&ctx.groestl, hash1, sizeof(hash1));
	sph_groestl512_close(&ctx.groestl, hash4);

	sph_blake512(&ctx.blake, input, 80);
	sph_blake512(&ctx.blake, hash1, sizeof(hash1));
	sph_blake512_close(&ctx.blake, hash5);

	combine_hashes((uint32_t *)output, hash2, hash3, hash4, hash5);
}

int scanhash_heavy(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
			uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t hash64[8] __attribute__((aligned(32)));

	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000
	};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0
	};

#ifdef DEBUG_ALGO
	printf("[%d] Htarg=%X\n", thr_id, Htarg);
#endif
	for (int m=0; m < sizeof(masks); m++) {
		if (Htarg <= htmax[m]) {
			uint32_t mask = masks[m];
			do {
				pdata[19] = ++n;
				heavyhash(hash64, &pdata);
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
