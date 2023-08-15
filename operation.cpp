#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <iostream>
using namespace std;

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    bootsCONSTANT(&tmps[0], 0, bk);
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }

    for (int i=0; i<nb_bits; i++) {
            bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps);
}

void maximum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);

    bootsCONSTANT(&tmps[0], 0, bk);
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }

    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &a[i], &b[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps);
}

void additionCarryGen(LweSample* carryGen, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk){
    bootsAND(carryGen, a, b, bk);
}

void additionCarryResult(LweSample* carryResult, LweSample* carryProp, LweSample* cINBit, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk){
    bootsXOR(carryProp, a, b, bk);
    bootsXOR(carryResult, carryProp, cINBit, bk);
}

void additionCarryBit(LweSample* cinBit, LweSample* carryGen, LweSample* carryBit, LweSample* prevcinBit, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk){
    bootsXOR(carryBit, a, b, bk);
    bootsAND(carryBit, carryBit, prevcinBit, bk);
    bootsOR(cinBit, carryBit, carryGen, bk);
}

void addition(LweSample *result, const LweSample *a, const LweSample *b, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk) {
    LweSample* cINBit = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params);
    LweSample* carryGen = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* carryProp = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* carryBit = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* carryResult = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    bootsCONSTANT(&cINBit[0], 0, bk);

    for (int i=1; i<nb_bits+1; i++) {
        additionCarryGen(&carryGen[i-1], &a[i-1], &b[i-1], bk);
        additionCarryResult(&result[i-1], &carryProp[i-1], &cINBit[i-1], &a[i-1], &b[i-1], bk);
        additionCarryBit(&cINBit[i], &carryGen[i-1], &carryBit[i-1], &cINBit[i-1], &a[i-1], &b[i-1], bk);
    }


    delete_gate_bootstrapping_ciphertext_array(nb_bits, carryResult);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, carryBit);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, carryProp);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, carryGen);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, cINBit);
}

void subtraction(LweSample *result, const LweSample *a, const LweSample *b, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk){
    LweSample* cINBit = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params);
    LweSample* invert = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* temp2 = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* carry_bit = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    bootsCONSTANT(&cINBit[0], 0, bk);
    bootsCONSTANT(&carry_bit[0], 1, bk);
    for(int i=1; i<nb_bits; i++){
        bootsCONSTANT(&carry_bit[i], 0, bk);
    }

    bootsNOT(temp, &b[0], bk);
    bootsAND(temp2, temp, &carry_bit[0], bk);
    bootsXOR(temp, temp, &carry_bit[0], bk);
    bootsXOR(&invert[0], temp, &cINBit[0], bk);
    bootsAND(temp, temp, &cINBit[0], bk);
    bootsXOR(&cINBit[1], temp, temp2, bk);

    for(int i=1; i<nb_bits; i++){
        bootsNOT(temp, &b[i], bk);
        bootsAND(temp2, temp, &carry_bit[i], bk);
        bootsXOR(temp, temp, &carry_bit[i], bk);
        bootsXOR(&invert[i], temp, &cINBit[i], bk);
        bootsAND(temp, temp, &cINBit[i], bk);
        bootsXOR(&cINBit[i+1], temp, temp2, bk);
    }

    addition(result, invert, a, nb_bits, bk);

    delete_gate_bootstrapping_ciphertext(temp);
    delete_gate_bootstrapping_ciphertext(temp2);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, carry_bit);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, invert);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, cINBit);

}

void equality(LweSample *result, const LweSample *a, const LweSample *b, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk){
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    for (int i = 0; i < nb_bits; i++) {
        bootsXNOR(&tmps[i], &a[i], &b[i], bk);
    }

    bootsCONSTANT(result, 1, bk);

    for (int i = 0; i < nb_bits; i++) {
        bootsAND(result, result, &tmps[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, tmps);
}

void select(LweSample* result, const LweSample* s, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    for (int i = 0; i < nb_bits; i++) {
        bootsMUX(&result[i], s, &b[i], &a[i], bk);
    }
}

void operation(int choice){
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);

    const TFheGateBootstrappingParameterSet* params = bk->params;

    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(16, params);

    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);

    LweSample* result = new_gate_bootstrapping_ciphertext_array(16, params);

    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);

    switch (choice) {
        case 1:
            addition(result, ciphertext1, ciphertext2, 16, bk);
            break;
        case 2:
            subtraction(result, ciphertext1, ciphertext2, 16, bk);
            break;
        case 3:
            minimum(result, ciphertext1, ciphertext2, 16, bk);
            break;
        case 4:
            maximum(result, ciphertext1, ciphertext2, 16, bk);
            break;
        case 5:
            equality(result, ciphertext1, ciphertext2, 16, bk);
            break;
        case 6:
            int input;
            cout << "Choose which item to select: (0 for a), (1 for b)" << endl;
            cin >> input;
            bootsCONSTANT(temp, input, bk);
            select(result, temp, ciphertext1, ciphertext2, 16, bk);
            break;
        default:
            break;
    }

    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<16; i++) export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
    fclose(answer_data);

    delete_gate_bootstrapping_ciphertext_array(16, result);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1);
    delete_gate_bootstrapping_cloud_keyset(bk);
}