#include <l4/crypto/random.h>

#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "crypto/rand_pool.h"
#include "prov/seeding.h"


size_t ossl_prov_acquire_entropy(RAND_POOL * pool) {
    size_t bytes_needed = ossl_rand_pool_bytes_needed(pool, 1);
    unsigned char *buf = malloc(bytes_needed);

    if (bytes_needed <= 0) {
        free(buf);
        return ossl_rand_pool_entropy_available(pool);
    }
    if (buf == NULL) {
        free(buf);
        ossl_rand_pool_add_end(pool, 0, 0);
    } else {

    crypto_randomize_buf(buf, bytes_needed);

    ossl_rand_pool_add_end(pool, bytes_needed, sizeof(unsigned char) * bytes_needed);
    free(buf);
    }
    return ossl_rand_pool_entropy_available(pool);
}
