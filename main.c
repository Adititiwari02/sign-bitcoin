#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip39.h"

void callback(uint32_t current, uint32_t total) {}

void getSeedAsString(char seedAsString[500], uint8_t *seed, int size) {
    unsigned char *pin = seed;
    const char *hex = "0123456789abcdef";
    char *pout = seedAsString;
    int i = 0;
    for (; i < size - 1; ++i) {
        *pout++ = hex[(*pin >> 4) & 0xF];
        *pout++ = hex[(*pin++) & 0xF];
    }
    *pout++ = hex[(*pin >> 4) & 0xF];
    *pout++ = hex[(*pin) & 0xF];
    *pout = 0;
}

int main() {
    const char *mnemonic =
        "crew squeeze kid test vault razor era rotate employ remove rare fat "
        "peasant celery stable certain whale clump flush cash goat jacket wear "
        "rally";
    const char *originalSeed =
        "c0db23b48bb1e776aa47b0a6002f4bd456183f2a6b124cb02ffef330447e4ea38d6ca0"
        "41c85f939579875aa59dd45ce9a1f99335d806dd72fbee1b7a5a1466f8";

    const char *passphrase = "";
    uint8_t seed[512 / 8];
    void (*ptr)(uint32_t, uint32_t) = &callback;
    mnemonic_to_seed(mnemonic, passphrase, seed, ptr);

    char seedAsString[500];
    getSeedAsString(seedAsString, seed, 512 / 8);
    printf("Seed original: %s\n", originalSeed);
    printf("Seed    found: %s\n", seedAsString);

    return 0;
}
