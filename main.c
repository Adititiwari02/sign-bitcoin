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

int digest_size = 32;
int sig_size = 64;
int der_size = 70;
int script_sig_size = 107;  // is changed later based on der

struct input_struct {
    uint8_t prev_txn_hash[32];
    uint8_t prev_output_idx[4];
    uint8_t script_len;
    uint8_t *script_sig;
    uint8_t sequence[4];
};

struct output_struct {
    uint8_t value[8];
    uint8_t script_len;
    uint8_t *script_pubkey;
};

struct txn_struct {
    uint8_t version[4];
    uint8_t num_inputs;
    struct input_struct *inputs;
    uint8_t num_outputs;
    struct output_struct *outputs;
    uint8_t lock_time[4];
};

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

    // version
    for (int i = 0; i < 4; i++) {
        txn->version[i] = unsigned_txn_byte_array[idx++];
    }

    // number of inputs
    txn->num_inputs = unsigned_txn_byte_array[idx++];

    // input details
    txn->inputs = (struct input_struct *)malloc(txn->num_inputs *
                                                sizeof(struct input_struct));
    for (int i = 0; i < txn->num_inputs; i++) {
        int idx1 = 0;
        for (int j = 0; j < 32; j++) {
            txn->inputs[i].prev_txn_hash[j] = unsigned_txn_byte_array[idx++];
        }
        for (int j = 0; j < 4; j++) {
            txn->inputs[i].prev_output_idx[j] = unsigned_txn_byte_array[idx++];
        }
        txn->inputs[i].script_len = unsigned_txn_byte_array[idx++];
        txn->inputs[i].script_sig =
            (uint8_t *)malloc(txn->inputs[i].script_len * sizeof(uint8_t));
        for (int j = 0; j < txn->inputs[i].script_len; j++) {
            txn->inputs[i].script_sig[j] = unsigned_txn_byte_array[idx++];
        }
        for (int j = 0; j < 4; j++) {
            txn->inputs[i].sequence[j] = unsigned_txn_byte_array[idx++];
        }
    }

    // number of outputs
    txn->num_outputs = unsigned_txn_byte_array[idx++];

    // outputs details
    txn->outputs = (struct output_struct *)malloc(txn->num_outputs *
                                                  sizeof(struct output_struct));
    for (int i = 0; i < txn->num_outputs; i++) {
        for (int j = 0; j < 8; j++) {
            txn->outputs[i].value[j] = unsigned_txn_byte_array[idx++];
        }
        txn->outputs[i].script_len = unsigned_txn_byte_array[idx++];
        txn->outputs[i].script_pubkey =
            (uint8_t *)malloc(txn->outputs[i].script_len * sizeof(uint8_t));
        for (int j = 0; j < txn->outputs[i].script_len; j++) {
            txn->outputs[i].script_pubkey[j] = unsigned_txn_byte_array[idx++];
        }
    }

    // locktime
    for (int i = 0; i < 4; i++) {
        txn->lock_time[i] = unsigned_txn_byte_array[idx++];
    }
}

void fill_script_sig(uint8_t *script_sig, uint8_t *der, uint8_t *public_key) {
    int idx = 0, num;
    if (der[1] == 68)
        num = 71;
    else if (der[1] == 69)
        num = 72;
    else if (der[1] == 70)
        num = 73;
    else {
        printf("\n\nUnhandled case!!! TERMINATING!!\n\n");
        return;
    }
    script_sig[idx++] = num;
    for (int i = 0; i < der_size; i++) {
        script_sig[idx++] = der[i];
    }
    script_sig[idx++] = 1;
    script_sig[idx++] = 33;
    for (int i = 0; i < 33; i++) {
        script_sig[idx++] = public_key[i];
    }
}

void print_array(uint8_t *arr, int sz, char *name) {
    printf("\n\n\n\n%s\n", name);
    for (int i = 0; i < sz; i++) {
        printf("%02x", arr[i]);
    }
}

void display_txn(struct txn_struct *txn, int input_number) {
    printf("\n\nSIGNED TRANSACTION INPUT NUMBER: %d\n", input_number);
    int idx = 0;

    // version
    for (int i = 0; i < 4; i++) {
        printf("%02x", txn->version[i]);
    }

    // number of inputs
    printf("%02x", txn->num_inputs);

    // input details
    for (int i = 0; i < txn->num_inputs; i++) {
        int idx1 = 0;
        for (int j = 0; j < 32; j++) {
            printf("%02x", txn->inputs[i].prev_txn_hash[j]);
        }
        for (int j = 0; j < 4; j++) {
            printf("%02x", txn->inputs[i].prev_output_idx[j]);
        }
        printf("%02x", txn->inputs[i].script_len);
        for (int j = 0; j < txn->inputs[i].script_len; j++) {
            printf("%02x", txn->inputs[i].script_sig[j]);
        }
        for (int j = 0; j < 4; j++) {
            printf("%02x", txn->inputs[i].sequence[j]);
        }
    }

    // number of outputs
    printf("%02x", txn->num_outputs);

    // outputs details
    for (int i = 0; i < txn->num_outputs; i++) {
        for (int j = 0; j < 8; j++) {
            printf("%02x", txn->outputs[i].value[j]);
        }
        printf("%02x", txn->outputs[i].script_len);

        for (int j = 0; j < txn->outputs[i].script_len; j++) {
            printf("%02x", txn->outputs[i].script_pubkey[j]);
        }
    }

    // locktime
    for (int i = 0; i < 4; i++) {
        printf("%02x", txn->lock_time[i]);
    }
}

int main() {
    const char *mnemonic =
        "thing lift table helmet company income lottery cook benefit rule "
        "erupt lava drive universe sniff repeat doll truth pepper warrior "
        "dilemma reject state lock";
    const char *original_seed =
        "30b8e95cd08a8eb02ebe916becbf468b274c61410196f1b300fc6f7e5698c042aa0cfd"
        "69d4b478b488316e71a26f648df6262c359b4e372b464ba2e8bdee771d";

    const char *passphrase = "";
    int sizeOfSeed = 512 / 8;
    uint8_t seed[sizeOfSeed];
    mnemonic_to_seed(mnemonic, passphrase, seed, NULL);

    printf("\nSeed original: \n%s", original_seed);
    printf("\n\nSeed    found: \n");
    for (int i = 0; i < sizeOfSeed; i++) {
        printf("%02x", seed[i]);
    }

    HDNode master_node;
    HDNode *out = &master_node;
    int x = hdnode_from_seed(seed, sizeOfSeed, SECP256K1_NAME, out);
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

    HDNode *out2 = out;
    // Address Node
    child_num = 0;
    x = hdnode_private_ckd(out, child_num);
    hdnode_fill_public_key(out);
    display_node_info(out, "ADDRESS NODE");

    const char unsigned_txn[] =
        "02000000012a4bd05329a127c63a62b0813b58d7cfe37ea28742f7d73ec968bc601b6c"
        "ec6c010000001976a914ac625f3cf806a057ecf458cb39db7a7cd3b5cd0f88acffffff"
        "ff0210270000000000001976a914ac625f3cf806a057ecf458cb39db7a7cd3b5cd0f88"
        "ac9a9c0000000000001976a914df61b5ce3c121b3f6253ef1953a017117cb716ac88ac"
        "0000000001000000";

    const char *pos = unsigned_txn;
    size_t size_unsigned_byte_array = strlen(unsigned_txn) / 2;
    uint8_t *unsigned_txn_byte_array = malloc(size_unsigned_byte_array);
    memset(unsigned_txn_byte_array, 0, size_unsigned_byte_array);
    for (size_t count = 0; count < size_unsigned_byte_array; count++) {
        sscanf(pos, "%2hhx", &unsigned_txn_byte_array[count]);
        pos += 2;
    }
    print_array(unsigned_txn_byte_array, size_unsigned_byte_array,
                "UNSIGNED TXN AS BYTE ARRAY:");

    struct txn_struct txn;
    struct txn_struct *txn_ptr = &txn;
    fill_txn_struct(txn_ptr, unsigned_txn_byte_array);

    uint8_t sha_digest_1[digest_size], sha_digest_2[digest_size];
    sha256_Raw(unsigned_txn_byte_array, size_unsigned_byte_array, sha_digest_1);
    sha256_Raw(sha_digest_1, digest_size, sha_digest_2);
    print_array(sha_digest_2, digest_size,
                "AFTER DOUBLE HASHING USING SHA256:");

    uint8_t sig[sig_size];
    const ecdsa_curve *curve = &secp256k1;
    x = ecdsa_sign_digest(curve, out->private_key, sha_digest_2, sig, NULL,
                          NULL);
    print_array(sig, sig_size, "SIGNATURE:");

    uint8_t der[der_size];
    x = ecdsa_sig_to_der(sig, der);
    print_array(der, der_size, "DER FORMAT:");
    if (der[1] == 68)
        script_sig_size = 106;
    else if (der[1] == 69)
        script_sig_size = 107;
    else if (der[1] == 70)
        script_sig_size = 108;

    uint8_t script_sig[script_sig_size];
    fill_script_sig(script_sig, der, out->public_key);
    print_array(script_sig, script_sig_size, "SCRIPT SIG: ");

    // for multi input txns, sign each of them individually and keep the others
    // script sig empty
    for (int i = 0; i < txn.num_inputs; i++) {
        txn.inputs[i].script_len = script_sig_size;
        txn.inputs[i].script_sig =
            (uint8_t *)malloc(txn.inputs[i].script_len * sizeof(uint8_t));
        memcpy(txn.inputs[i].script_sig, script_sig, script_sig_size);
        for (int j = 0; j < txn.num_inputs; j++) {
            if (i != j) {
                txn.inputs[i].script_len = 0;
                txn.inputs[i].script_sig =
                    (uint8_t *)malloc(0 * sizeof(uint8_t));
            }
        }
        // displaying the signed transaction for the ith input
        display_txn(txn_ptr, i + 1);
    }
    return 0;
}
