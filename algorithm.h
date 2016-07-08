#ifndef ALGORITHM_H
#define ALGORITHM_H

#include <inttypes.h>
#include <stdbool.h>

typedef enum {
    ALGO_UNK,
    ALGO_SCRYPT,      /* scrypt(1024,1,1) */
    ALGO_SHA256D,     /* SHA-256d */
    ALGO_KECCAK,      /* Keccak */
    ALGO_HEAVY,       /* Heavy */
    ALGO_QUARK,       /* Quark */
    ALGO_GROESTL,     /* Groestl */
    ALGO_MYRGROESTL,  /* Myriadcoin-groestl */
    ALGO_SKEIN,       /* Skein */
    ALGO_SHAVITE3,    /* Shavite3 */
    ALGO_BLAKE,       /* Blake */
    ALGO_FRESH,       /* Fresh */
    ALGO_LBRY,        /* lbrycr */
    ALGO_X11,         /* X11 */
    ALGO_X13,         /* X13 */
    ALGO_X14,         /* X14 */
    ALGO_X15,         /* X15 Whirlpool */
    ALGO_PENTABLAKE,  /* Pentablake */
    ALGO_AXIOM,       /* AxiomHash */
    ALGO_CRYPTONIGHT, /* CryptoNight */
} algorithm_type_t;

typedef struct _algorithm_t {
    const char* name; /* Human-readable identifier */
    algorithm_type_t type; //algorithm type
    char *displayname;
//    int64_t max;
    void (*gen_hash)(unsigned char *hash, const unsigned char *data, int len);
    int (*scanhash)(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                    uint32_t max_nonce, uint64_t *hashes_done);
    void (*init_contexts)(void *params);
} algorithm_t;

#endif /* ALGORITHM_H */

