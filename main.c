/**
 * // GET SEED FROM MNEMONIC
 *
 * // DERIVE PRIVATE & PUBLIC KEY
 *
 *      1. Master Node
 *      2. Master Node to Purpose Node: 44' hardened
 *      3. Purpose Node to Coin Node: 1' hardened
 *      4. Coin Node to Account Node: 0' hardened
 *      5. Account Node to Change Node: 0 non hardened
 *      6. Change Node to Address Index Node: 0 non hardened
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "ripemd160.h"
#include "secp256k1.h"
#include "sha2.h"

struct txn_struct {
    uint8_t version[4];
    uint8_t num_inputs;
    uint8_t prev_txn_hash[32];
    uint8_t prev_output_idx[4];
    uint8_t script_len;
    uint8_t script_sig[106];
    uint8_t sequence[4];
    uint8_t num_outputs;
    uint8_t value[8];
    uint8_t script_len2;
    uint8_t script_pubkey[25];
    uint8_t lock_time[4];
};

void callback(uint32_t current, uint32_t total) {}

int callback2(uint8_t by, uint8_t sig[64]) { return 0; }

void get_seed_as_string(char seedAsString[500], uint8_t *seed, int size) {
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

void display_node_info(HDNode *node, char *name) {
    printf("\n\n\n\n%s", name);
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

void fill_txn_struct(struct txn_struct *txn, uint8_t *unsigned_txn_byte_array) {
    int idx = 0;
    for (int i = 0; i < 4; i++) {
        txn->version[i] = unsigned_txn_byte_array[idx++];
    }
    txn->num_inputs = unsigned_txn_byte_array[idx++];
    for (int i = 0; i < 32; i++) {
        txn->prev_txn_hash[i] = unsigned_txn_byte_array[idx++];
    }
    for (int i = 0; i < 4; i++) {
        txn->prev_output_idx[i] = unsigned_txn_byte_array[idx++];
    }
    txn->script_len = unsigned_txn_byte_array[idx++];
    for (int i = 0; i < 25; i++) {
        txn->script_sig[i] = unsigned_txn_byte_array[idx++];
    }
    for (int i = 0; i < 4; i++) {
        txn->sequence[i] = unsigned_txn_byte_array[idx++];
    }
    txn->num_outputs = unsigned_txn_byte_array[idx++];
    for (int i = 0; i < 8; i++) {
        txn->value[i] = unsigned_txn_byte_array[idx++];
    }
    txn->script_len2 = unsigned_txn_byte_array[idx++];
    for (int i = 0; i < 25; i++) {
        txn->script_pubkey[i] = unsigned_txn_byte_array[idx++];
    }
    for (int i = 0; i < 4; i++) {
        txn->lock_time[i] = unsigned_txn_byte_array[idx++];
    }
}

void print_txn_info(struct txn_struct *txn, int sz) {
    printf("\n\n\n\nTRANSACTION STRUCT: ");
    printf("\nVersion: \n");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", txn->version[i]);
    }

    printf("\nNumber of inputs: \n%02x", txn->num_inputs);

    printf("\nPrevious txn hash: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", txn->prev_txn_hash[i]);
    }

    printf("\nPrevious output idx: \n");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", txn->prev_output_idx[i]);
    }

    printf("\nScript len: \n%02x", txn->script_len);

    printf("\nScript signature \n");
    if (sz == 25) {
        printf("(only a placeholder for now)\n");
    }
    for (int i = 0; i < sz; i++) {
        printf("%02x ", txn->script_sig[i]);
    }

    printf("\nSequence: \n");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", txn->sequence[i]);
    }

    printf("\nNumber of outputs: \n%02x", txn->num_outputs);

    printf("\nValue: \n");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", txn->value[i]);
    }

    printf("\nScript len: \n%02x", txn->script_len2);

    printf("\nScript pub key: \n");
    for (int i = 0; i < 25; i++) {
        printf("%02x ", txn->script_pubkey[i]);
    }

    printf("\nLocktime: \n");
    for (int i = 0; i < 4; i++) {
        printf("%02x ", txn->lock_time[i]);
    }
}

void fill_script_sig(uint8_t *script_sig, uint8_t *der, uint8_t *public_key) {
    int idx = 0;
    script_sig[idx++] = 47;
    for (int i = 0; i < 70; i++) {
        script_sig[idx++] = der[i];
    }
    script_sig[idx++] = 1;
    script_sig[idx++] = 21;
    for (int i = 0; i < 33; i++) {
        script_sig[idx++] = public_key[i];
    }
}

void print_script_sig_info(u_int8_t *script_sig) {
    printf("\n\n\n\nSCRIPT SIG: ");
    int idx = 0;
    printf("\nPushdata opcode: \n%02x", script_sig[idx++]);
    printf("\nHeader: \n%02x", script_sig[idx++]);
    printf("\nSig len: \n%02x", script_sig[idx++]);
    printf("\nInteger: \n%02x", script_sig[idx++]);
    printf("\nR len: \n%02x", script_sig[idx++]);
    printf("\nR: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", script_sig[idx++]);
    }
    printf("\nInteger: \n%02x", script_sig[idx++]);
    printf("\nS len: \n%02x", script_sig[idx++]);
    printf("\nS: \n");
    for (int i = 0; i < 32; i++) {
        printf("%02x ", script_sig[idx++]);
    }
    printf("\nSighash code: \n%02x", script_sig[idx++]);
    printf("\nPushdata opcode: \n%02x", script_sig[idx++]);
    printf("\nPub key: \n");
    for (int i = 0; i < 33; i++) {
        printf("%02x ", script_sig[idx++]);
    }
}

void print_array(uint8_t *arr, int sz, char *name) {
    printf("\n\n\n\n%s\n", name);
    for (int i = 0; i < sz; i++) {
        printf("%02x ", arr[i]);
    }
}

int main() {
    const char *mnemonic =
        "crew squeeze kid test vault razor era rotate employ remove rare fat "
        "peasant celery stable certain whale clump flush cash goat jacket wear "
        "rally";
    const char *original_seed =
        "c0db23b48bb1e776aa47b0a6002f4bd456183f2a6b124cb02ffef330447e4ea38d6ca0"
        "41c85f939579875aa59dd45ce9a1f99335d806dd72fbee1b7a5a1466f8";

    const char *passphrase = "";
    uint8_t seed[512 / 8];
    void (*ptr)(uint32_t, uint32_t) = &callback;
    mnemonic_to_seed(mnemonic, passphrase, seed, ptr);

    char seed_as_string[500];
    get_seed_as_string(seed_as_string, seed, 512 / 8);
    printf("\nSeed original: %s\n", original_seed);
    printf("\n\n\n\nSeed    found: %s\n", seed_as_string);

    HDNode master_node;
    HDNode *out = &master_node;
    int x = hdnode_from_seed(seed, 64, SECP256K1_NAME, out);
    hdnode_fill_public_key(out);
    display_node_info(out, "MASTER NODE");

    // Process Node
    uint32_t child_num = (1 << 31) + 44;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    display_node_info(out, "PROCESS NODE");

    // Coin Node
    child_num = (1 << 31) + 1;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    display_node_info(out, "COIN NODE");

    // Account Node
    child_num = 1 << 31;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    display_node_info(out, "ACCOUNT NODE");

    // Change Node
    child_num = 0;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    display_node_info(out, "CHANGE NODE");

    // Address Node
    child_num = 0;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    display_node_info(out, "ADDRESS NODE");

    uint8_t *private_key = out->private_key;
    uint8_t *public_key = out->public_key;

    const char unsigned_txn[] =
        "0200000001c70de0473c83943c722823b9ead64745dff1b179a6c00120281d2f7bad3c"
        "cebe010000001976a914059d099e62cbd89abaa71a3fd49a81982f97e8aa88acffffff"
        "ff0160ea0000000000001976a914833e8b18093be487999c70da47abf1ad294e182788"
        "ac00000000";

    const char *pos = unsigned_txn;
    uint8_t unsigned_txn_byte_array[110];
    for (size_t count = 0; count < sizeof unsigned_txn_byte_array /
                                       sizeof *unsigned_txn_byte_array;
         count++) {
        sscanf(pos, "%2hhx", &unsigned_txn_byte_array[count]);
        pos += 2;
    }
    print_array(unsigned_txn_byte_array, 110, "UNSIGNED TXN AS BYTE ARRAY:");

    struct txn_struct txn;
    struct txn_struct *txn_ptr = &txn;
    fill_txn_struct(txn_ptr, unsigned_txn_byte_array);
    print_txn_info(txn_ptr, 25);

    uint8_t sha_digest_1[64], sha_digest_2[64];
    sha256_Raw(unsigned_txn_byte_array, 110, sha_digest_1);
    sha256_Raw(sha_digest_1, 64, sha_digest_2);
    print_array(sha_digest_2, 64, "AFTER DOUBLE HASHING USING SHA256:");

    uint8_t sig[64];
    int (*ptr2)(uint8_t, uint8_t[64]) = &callback2;
    const ecdsa_curve *curve = &secp256k1;
    x = ecdsa_sign_digest(curve, private_key, sha_digest_2, sig, public_key,
                          ptr2);
    print_array(sig, 64, "SIGNATURE:");

    uint8_t der[70];
    x = ecdsa_sig_to_der(sig, der);
    print_array(der, 70, "DER FORMAT:");

    uint8_t script_sig[106];
    fill_script_sig(script_sig, der, public_key);
    print_script_sig_info(script_sig);

    memcpy(txn.script_sig, script_sig, sizeof(script_sig));
    print_txn_info(txn_ptr, 106);
    return 0;
}
