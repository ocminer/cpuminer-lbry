
#include "algorithm.h"
#include "miner.h"

#include <inttypes.h>
#include <string.h>

#define SCANHASH(name) \
extern int scanhash_ ## name(int thr_id, uint32_t *pdata, const uint32_t *ptarget, \
                            uint32_t max_nonce, uint64_t *hashes_done); \
extern void init_ ## name ## _contexts();


SCANHASH(sha256d)
SCANHASH(scrypt);
SCANHASH(keccak);
SCANHASH(heavy);
SCANHASH(quark);
SCANHASH(skein);
SCANHASH(ink);
SCANHASH(blake);
SCANHASH(fresh);
SCANHASH(lbry);
SCANHASH(x11);
SCANHASH(x13);
SCANHASH(x14);
SCANHASH(x15);
SCANHASH(groestl);
SCANHASH(myriadcoin_groestl);
SCANHASH(pentablake);
SCANHASH(axiom);
SCANHASH(cryptonight);

algorithm_t algos[] = {
    { "scrypt",      ALGO_SCRYPT,     "scrypt(1024, 1, 1)", sha256d, scanhash_scrypt, NULL },
    { "sha256d",     ALGO_SHA256D,    "SHA-256d", sha256d, scanhash_sha256d, NULL },
    { "blake",       ALGO_BLAKE,      "Blake", sha256d, scanhash_blake, init_blake_contexts },
    { "fresh",       ALGO_FRESH,      "Fresh", sha256d, scanhash_fresh, init_fresh_contexts },
    { "lbry",        ALGO_LBRY,       "Lbry", sha256d, scanhash_lbry, init_lbry_contexts },
    { "heavy",       ALGO_HEAVY,      "Heavy", sha256d, scanhash_heavy, init_heavy_contexts },
    { "keccak",      ALGO_KECCAK,     "Keccak", sha256, scanhash_keccak, init_keccak_contexts },
    { "shavite3",    ALGO_SHAVITE3,   "Shavite3", sha256d, scanhash_ink, init_ink_contexts },
    { "skein",       ALGO_SKEIN,      "Skein", sha256d, scanhash_skein, init_skein_contexts },
    { "quark",       ALGO_QUARK,      "Quark", sha256d, scanhash_quark, init_quark_contexts },
    { "pentablake",  ALGO_PENTABLAKE, "pentablake", sha256d, scanhash_pentablake, init_pentablake_contexts },
    { "axiom",       ALGO_AXIOM,      "AxiomHash", sha256d, scanhash_axiom, init_axiom_contexts },
    { "x11",         ALGO_X11,        "X11", sha256d, scanhash_x11, init_x11_contexts },
    { "x13",         ALGO_X13,        "X13", sha256d, scanhash_x13, init_x13_contexts },
    { "x14",         ALGO_X14,        "X14", sha256d, scanhash_x14, init_x14_contexts },
    { "x15",         ALGO_X15,        "X15", sha256d, scanhash_x15, init_x15_contexts },
    { "groestl",     ALGO_GROESTL,    "Groestl", sha256, scanhash_groestl, init_groestl_contexts },
    { "myr-groestl", ALGO_MYRGROESTL,    "Myriadcoin-groestl", sha256, scanhash_myriadcoin_groestl, init_myriadcoin_groestl_contexts },

    { "cryptonight", ALGO_CRYPTONIGHT, "cryptonight", sha256d, scanhash_cryptonight, NULL },

    // Terminator (do not remove)
    { NULL, ALGO_UNK, NULL, NULL, NULL }
};

