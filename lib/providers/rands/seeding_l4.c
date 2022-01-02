#include "internal/cryptlib.h"
#include <openssl/opensslconf.h>
#include "crypto/rand_pool.h"
#include "prov/seeding.h"

void crypto_randomize_buf(char* buf, size_t size) {
    while(size) {
        buf[size] = rand();
        size--;
    }
}

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

size_t ossl_pool_acquire_entropy(RAND_POOL *pool) {
    return ossl_prov_acquire_entropy(pool);
}

void ossl_rand_pool_cleanup(void)
{
}

void ossl_rand_pool_keep_random_devices_open(int keep)
{
    (int)keep;
}

static int wait_random_seeded(void)
{
    return 1;
}

int ossl_rand_pool_init(void) {
    return 1;
}

int ossl_pool_add_nonce_data(RAND_POOL *pool)
{
    unsigned char* data[128];

    crypto_randomize_buf(data, sizeof(data));

    return ossl_rand_pool_add(pool, &data, sizeof(data), 0);
}
