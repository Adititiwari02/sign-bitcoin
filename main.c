#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "ripemd160.h"
#include "sha2.h"

typedef uint8_t sha2_byte;

void callback(uint32_t current, uint32_t total) {}

void initialize_Xprv_Xpub(uint8_t *extendedPrivateKey,
                          uint8_t *extendedPublicKey, uint8_t depth,
                          uint8_t child_num, HDNode *parentNode) {
    /**
     *
     * 4 bytes Version (mainnet: 0488B21E public, 0488ADE4 private; testnet:
     * 043587CF public, 04358394 private)
     * 1 bytes Depth (0x00 for master nodes, 0x01 for level-1 derived keys, etc)
     * 4 byte Fingerprint (first 32 bits of hash160 of parent public key)
     * 4 byte Child Index
     * 32 byte Chain Code
     * 33 byte Private or Public Key byte
     */

    // version
    extendedPrivateKey[0] = 4;
    extendedPrivateKey[1] = 136;
    extendedPrivateKey[2] = 178;
    extendedPrivateKey[3] = 30;
    extendedPublicKey[0] = extendedPrivateKey[0];
    extendedPublicKey[1] = extendedPrivateKey[1];
    extendedPublicKey[2] = extendedPrivateKey[2];
    extendedPublicKey[3] = extendedPrivateKey[3];

    // depth
    extendedPrivateKey[4] = depth;
    extendedPublicKey[4] = depth;

    // fingerprint
    uint32_t finger_print = hdnode_fingerprint(parentNode);
    extendedPrivateKey[5] = (finger_print >> 24) & 0xFF;
    extendedPrivateKey[6] = (finger_print >> 16) & 0xFF;
    extendedPrivateKey[7] = (finger_print >> 8) & 0xFF;
    extendedPrivateKey[8] = (finger_print >> 0) & 0xFF;
    extendedPublicKey[5] = (finger_print >> 24) & 0xFF;
    extendedPublicKey[6] = (finger_print >> 16) & 0xFF;
    extendedPublicKey[7] = (finger_print >> 8) & 0xFF;
    extendedPublicKey[8] = (finger_print >> 0) & 0xFF;

    // child index
    extendedPrivateKey[9] = (child_num >> 24) & 0xFF;
    extendedPrivateKey[10] = (child_num >> 16) & 0xFF;
    extendedPrivateKey[11] = (child_num >> 8) & 0xFF;
    extendedPrivateKey[12] = (child_num >> 0) & 0xFF;
    extendedPublicKey[9] = (child_num >> 24) & 0xFF;
    extendedPublicKey[10] = (child_num >> 16) & 0xFF;
    extendedPublicKey[11] = (child_num >> 8) & 0xFF;
    extendedPublicKey[12] = (child_num >> 0) & 0xFF;

    // chain code
    for (int i = 0; i < 32; i++) {
        extendedPrivateKey[13 + i] = parentNode->chain_code[i];
    }
    for (int i = 0; i < 32; i++) {
        extendedPublicKey[13 + i] = parentNode->chain_code[i];
    }

    // private key / public key
    extendedPrivateKey[45] = 0;
    for (int i = 0; i < 32; i++) {
        extendedPrivateKey[46 + i] = parentNode->private_key[i];
    }
    for (int i = 0; i < 33; i++) {
        extendedPublicKey[45 + i] = parentNode->public_key[i];
    }
}

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

void displayInfo(HDNode *node, char *name) {
    printf("\n\n%s", name);
    printf("\nPrivate Key: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", node->private_key[i]);
    }
    printf("\nPublic Key: \n");
    for (int i = 0; i < 33; i++) {
        printf("%02x", node->public_key[i]);
    }
    printf("\nChain Code: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x", node->chain_code[i]);
    }
}
int main() {
    // const char hexstring[] = "0488ADE4", *pos = hexstring;
    // unsigned char val[4];
    // for (size_t count = 0; count < sizeof val / sizeof *val; count++) {
    //     sscanf(pos, "%2hhx", &val[count]);
    //     pos += 2;
    // }
    // printf("0x");
    // for (size_t count = 0; count < sizeof val / sizeof *val; count++)
    //     printf("%d ", val[count]);
    // printf("\n");

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
    printf("\n\nSeed original: %s\n", originalSeed);
    printf("\n\nSeed    found: %s\n", seedAsString);

    HDNode masterNode;
    HDNode *out = &masterNode;
    int x = hdnode_from_seed(seed, 64, SECP256K1_NAME, out);
    hdnode_fill_public_key(out);
    displayInfo(out, "MASTER NODE");

    // Process Node
    uint32_t child_num = (1 << 31) + 44;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    displayInfo(out, "PROCESS NODE");

    // Coin Node
    child_num = (1 << 31) + 1;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    displayInfo(out, "COIN NODE");

    // Account Node
    child_num = 1 << 31;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    displayInfo(out, "ACCOUNT NODE");

    // Change Node
    child_num = 0;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    displayInfo(out, "CHANGE NODE");

    // Address Node
    child_num = 0;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    displayInfo(out, "ADDRESS NODE");

    printf("\n\n");
    return 0;
}

// address: mg2doB74cqV9qKbSpPNbk5jtBHrst9WseY

/**
 * // DERIVE PRIVATE & PUBLIC KEY
 *
 * 1. Master Node
 * 2. Master Node to Purpose Node: 44' hardened
 * 3. Purpose Node to Coin Node: 1' hardened
 * 4. Coin Node to Account Node: 0' hardened
 * 5. Account Node to Change Node: 0 non hardened
 * 6. Change Node to Address Index Node: 0 non hardened
 *
 *
 *  // GETTING THE XPUB
 *
 * 1. SHA-256 on public key
 * 2. RIPEMD-160 on result of SHA-256
 * 3. Add version byte
 * 4. Perform SHA-256 on extended RIPEMD-160
 * 5. Perform SHA-256 on previous
 * 6. Take the first 4 bytes
 * 7. 4 checksum bytes added to RIPEMD-160 from stage 4. This is the 25-byte
 * 8. binary Bitcoin Address. convert to base58 encoding
 *
 * // GENERATE UNSIGNED TRANSACTION FROM CLI TOOL.
 *
 * // PARSE THE UNSIGNED TRANSACTION TO BITCOIN UNSIGNED TRANSACTION STRUCTURE.
 *
 * // DOUBLE HASH THE UNSIGNED TRANSACTION BYTE ARRAY USING SHA256.
 *
 * // SIGN DIGEST USING PRIVATE KEY CORRESPONDING TO THE INPUT OF UNSIGNED TXN.
 *
 * // CONVERT THE SIGNATURE INTO DER FORMAT AND THEN INTO SCRIPT SIG.
 *
 * // ADD THE SCRIPT SIG INSIDE THE INPUT OF THE TRANSACTION.
 **/

// uint8_t digest[64];
// for (int i = 0; i < 32; i++) {
//     digest[i] = masterPrivateKey[i];
// }
// for (int i = 0; i < 32; i++) {
//     digest[i + 32] = masterPublicKey[i];
// }
// printf("\n\nDigest is:\n");
// for (int i = 0; i < 64; i++) {
//     printf("%x", digest[i]);
// }
// printf("\n\nStep 1:\n");
// uint8_t shaDigest[64];
// sha256_Raw(masterPublicKey, 33, shaDigest);
// for (int i = 0; i < 64; i++) {
//     printf("%x", shaDigest[i]);
// }

// printf("\n\nStep 2:\n");
// uint8_t ripemd160Hash[20];
// ripemd160(shaDigest, 8, ripemd160Hash);
// for (int i = 0; i < 20; i++) {
//     printf("%x", ripemd160Hash[i]);
// }

// printf("\n\nStep 3:\n");
// uint8_t extendedRipemd160Hash[21];
// extendedRipemd160Hash[0] = 0;
// for (int i = 0; i < 21; i++) {
//     extendedRipemd160Hash[i + 1] = ripemd160Hash[i];
// }
// for (int i = 0; i < 22; i++) {
//     printf("%x", extendedRipemd160Hash[i]);
// }

// printf("\n\nStep 4:\n");
// uint8_t len = 22;
// uint8_t shaDigest2[64];
// sha256_Raw(extendedRipemd160Hash, 24, shaDigest2);
// for (int i = 0; i < 64; i++) {
//     printf("%x", shaDigest2[i]);
// }

// printf("\n\nStep 5:\n");
// len = 64;
// uint8_t shaDigest3[64];
// sha256_Raw(shaDigest2, 24, shaDigest3);
// for (int i = 0; i < 64; i++) {
//     printf("%x", shaDigest3[i]);
// }

// printf("\n\nStep 6:\n");
// uint8_t addressCheckSum[4];
// for (int i = 0; i < 4; i++) {
//     addressCheckSum[i] = shaDigest3[i];
// }
// for (int i = 0; i < 4; i++) {
//     printf("%x", addressCheckSum[i]);
// }

// printf("\n\nStep 7:\n");
// uint8_t binaryAdd25Bytes[25];
// for (int i = 0; i < 21; i++) {
//     binaryAdd25Bytes[i] = extendedRipemd160Hash[i];
// }
// for (int i = 0; i < 4; i++) {
//     binaryAdd25Bytes[i + 21] = addressCheckSum[i];
// }
// for (int i = 0; i < 25; i++) {
//     printf("%d", binaryAdd25Bytes[i]);
// }

// printf("\n\nStep 8:\n");
