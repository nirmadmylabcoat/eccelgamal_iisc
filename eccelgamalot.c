#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#include <string.h>

// Helper to print EC point
void print_point(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx, const char *label) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
    printf("%s: (", label);
    BN_print_fp(stdout, x);
    printf(", ");
    BN_print_fp(stdout, y);
    printf(")\n");
    BN_free(x);
    BN_free(y);
}

// Hash to point: Hash input to x, try finding y such that (x, y) lies on curve
EC_POINT *hash_to_point(const EC_GROUP *group, const char *input, BN_CTX *ctx) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *p = BN_new();
    EC_POINT *point = EC_POINT_new(group);

    EC_GROUP_get_curve_GFp(group, p, a, b, ctx);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, x);
    BN_mod(x, x, p, ctx);

    while (1) {
        // y^2 = x^3 + ax + b mod p
        BIGNUM *rhs = BN_new();
        BIGNUM *x3 = BN_new();
        BN_mod_sqr(rhs, x, p, ctx); // x^2
        BN_mod_mul(x3, rhs, x, p, ctx); // x^3
        BN_mod_mul(rhs, a, x, p, ctx); // ax
        BN_mod_add(rhs, rhs, x3, p, ctx);
        BN_mod_add(rhs, rhs, b, p, ctx);

        // Euler's criterion to check if rhs is a square mod p
        BIGNUM *exp = BN_new();
        BN_copy(exp, p);
        BN_sub_word(exp, 1);
        BN_rshift1(exp, exp);
        BN_mod_exp(y, rhs, exp, p, ctx);

        if (BN_is_one(y)) {
            // valid point exists
            BN_mod_sqrt(y, rhs, p, ctx);
            EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx);
            if (EC_POINT_is_on_curve(group, point, ctx)) {
                BN_free(rhs); BN_free(x3); BN_free(exp);
                BN_free(x); BN_free(y); BN_free(a); BN_free(b); BN_free(p);
                return point;
            }
        }
        BN_add_word(x, 1); // try next x
        BN_free(rhs); BN_free(x3); BN_free(exp);
    }
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    EC_KEY *key_sender = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key_sender);

    const EC_GROUP *group = EC_KEY_get0_group(key_sender);
    const EC_POINT *public_sender = EC_KEY_get0_public_key(key_sender);

    // Receiver creates 2 choices: real and fake
    const char *fake_input = "fake_key_secret";
    EC_POINT *fake_pubkey = hash_to_point(group, fake_input, ctx);

    // Validate point
    if (EC_POINT_is_on_curve(group, fake_pubkey, ctx)) {
        print_point(group, fake_pubkey, ctx, "[Receiver] Fake Public Key");
    } else {
        printf("Generated point is not on the curve\n");
        return 1;
    }

    // Sender encrypts message 0 with receiver's public key
    BIGNUM *k = BN_new();
    BN_rand_range(k, EC_GROUP_get0_order(group));
    EC_POINT *C1 = EC_POINT_new(group);
    EC_POINT *shared = EC_POINT_new(group);

    EC_POINT_mul(group, C1, NULL, EC_GROUP_get0_generator(group), k, ctx);
    EC_POINT_mul(group, shared, NULL, fake_pubkey, k, ctx);

    print_point(group, C1, ctx, "[Sender] C1 (ephemeral)");
    print_point(group, shared, ctx, "[Sender] Shared secret with fake key");

    // The receiver can't decrypt this as it doesn't know k or sender's private key
    // In a full OT, the receiver picks one real and one fake key and only learns one message.

    BN_free(k);
    EC_POINT_free(C1);
    EC_POINT_free(shared);
    EC_POINT_free(fake_pubkey);
    EC_KEY_free(key_sender);
    BN_CTX_free(ctx);

    return 0;
}
