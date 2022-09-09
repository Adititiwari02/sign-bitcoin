#include <stdio.h>
#include "bip39.h"

int main() {
    const char *mnemonics = "crew squeeze kid test vault razor era rotate employ remove rare fat peasant celery stable certain whale clump flush cash goat jacket wear rally";
    int x = mnemonic_check(mnemonics);
    printf("%d", x);
    return 0;
}
