#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

void commit_and_verify(int value) {
    // Initialization
    EC_GROUP *group;
    EC_POINT *G, *H_prime, *C, *mG, *recomputed_C;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *m = BN_new();

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    G = EC_GROUP_get0_generator(group);
    BIGNUM *x = BN_new();
    unsigned char hash[32];
    int success = 0;

    // Step 1: Generate a random r in [1, order-1]
    H_prime = EC_POINT_new(group);
    BIGNUM *r = BN_new();
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    do {
        BN_rand_range(r, order);
    } while (BN_is_zero(r)); // ensure r ≠ 0

    // Step 2: Hash r
    unsigned char r_bytes[32];
    int r_len = BN_num_bytes(r);
    BN_bn2binpad(r, r_bytes, 32);  // pad to 32 bytes
    SHA256(r_bytes, 32, hash);
    x = BN_bin2bn(hash, 32, NULL);

    // Step 3: Try to convert hash to EC point, or increment until successful
    while (!success) {
        for (int y_bit = 0; y_bit <= 1; y_bit++) {
            if (EC_POINT_set_compressed_coordinates_GFp(group, H_prime, x, y_bit, ctx)) {
                if (EC_POINT_is_on_curve(group, H_prime, ctx)) {
                    success = 1;
                    break;
                }
            }
        }
        if (!success) {
            BN_add_word(x, 1); // increment x and try again
        }
    }

    // Set message
    BN_set_word(m, value);

    // Commit: C = mG + H'
    mG = EC_POINT_new(group);
    C = EC_POINT_new(group);
    EC_POINT_mul(group, mG, NULL, G, m, ctx);
    EC_POINT_add(group, C, mG, H_prime, ctx);

    BIGNUM *Cx = BN_new(), *Cy = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, C, Cx, Cy, ctx);
    printf("Commitment C:\n  x = "); BN_print_fp(stdout, Cx);
    printf("\n  y = "); BN_print_fp(stdout, Cy); printf("\n");

    // Reveal value
    printf("\nRevealed value:\n  m = "); BN_print_fp(stdout, m); printf("\n");

    // Recompute C for verification
    recomputed_C = EC_POINT_new(group);
    EC_POINT_mul(group, mG, NULL, G, m, ctx);
    EC_POINT_add(group, recomputed_C, mG, H_prime, ctx);

    BIGNUM *re_x = BN_new(), *re_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, recomputed_C, re_x, re_y, ctx);

    if (BN_cmp(Cx, re_x) == 0 && BN_cmp(Cy, re_y) == 0) {
        printf("\nVerification successful: Commitment is valid.\n");
    } else {
        printf("\nVerification failed: Commitment does not match.\n");
    }

    // Free all
    BN_free(m); BN_free(x); BN_free(Cx); BN_free(Cy);
    BN_free(re_x); BN_free(re_y);
    EC_POINT_free(H_prime); EC_POINT_free(mG);
    EC_POINT_free(C); EC_POINT_free(recomputed_C);
    EC_GROUP_free(group); BN_CTX_free(ctx);
}

int main() {
    int value;
    printf("Enter value to commit: ");
    scanf("%d", &value);
    commit_and_verify(value);
    return 0;
}
