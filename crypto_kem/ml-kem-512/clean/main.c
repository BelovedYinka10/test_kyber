#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "api.h"

void print_bytes(const char *label, const unsigned char *data, size_t len) {
    printf("\n%s\n", label);
    printf("Index | Hex  | Dec  | ASCII\n");
    printf("------+-------+------+-------\n");
    for (size_t i = 0; i < len; i++) {
        unsigned char byte = data[i];
        printf("%4zu  |  %02X   | %3u  |  %c\n",
               i, byte, byte, isprint(byte) ? byte : '.');
    }
    printf("\n");
}

int main() {
    unsigned char pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
    unsigned char ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
    unsigned char ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

    clock_t start, end;

    // --- Keypair Generation ---
    start = clock();
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    end = clock();
    printf("\n[Clock Ticks] Key Generation: %ld\n", (long)(end - start));

    // --- Encapsulation ---
    start = clock();
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, pk);
    end = clock();
    printf("[Clock Ticks] Encapsulation:  %ld\n", (long)(end - start));

    // --- Decapsulation ---
    start = clock();
    PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);
    end = clock();
    printf("[Clock Ticks] Decapsulation:  %ld\n", (long)(end - start));

    // Optional: Print values
    print_bytes("Public Key (pk):", pk, 32);  // First 32 bytes for brevity
    print_bytes("Shared Secret (ss1):", ss1, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);
    print_bytes("Shared Secret (ss2):", ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);

    printf("Shared secret match: %s\n",
           memcmp(ss1, ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES) == 0 ? "YES" : "NO");

    return 0;
}
