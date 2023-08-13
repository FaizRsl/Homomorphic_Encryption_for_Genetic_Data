#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <iostream>
#include <memory>
using namespace std;
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk);
void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);
void addition(LweSample *result, const LweSample *a, const LweSample *b, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk);
void additionCarryGen(LweSample* carryGen, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk);
void additionCarryResult(LweSample* carryResult, LweSample* carryProp, LweSample* cINBit, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk);
void subtraction(LweSample *result, const LweSample *a, const LweSample *b, const int nb_bits, const TFheGateBootstrappingCloudKeySet *bk);
void cloud();

void cloud(){
    
    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //read the 2x16 ciphertexts
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(16, params);

    //reads the 2x16 ciphertexts from the cloud file
    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<16; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);

    // cout << ciphertext1 << endl;
    // cout << ciphertext1->a << endl;
    // cout << ciphertext1->b << endl;
    // cout << ciphertext1->current_variance << endl;

    //do some operations on the ciphertexts: here, we will compute the
    //minimum of the two
    LweSample* result = new_gate_bootstrapping_ciphertext_array(16, params);
    //addition(result, ciphertext1, ciphertext2, 16, bk);
    //minimum(result, ciphertext1, ciphertext2, 16, bk);
    subtraction(result, ciphertext1, ciphertext2, 16, bk);

    //export the 32 ciphertexts to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    for (int i=0; i<16; i++) export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
    fclose(answer_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, result);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1);
    delete_gate_bootstrapping_cloud_keyset(bk);

}

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return b 
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    //cout << "si/tmp1: ";
    //cout << tmp->b << endl;
    bootsMUX(result, tmp, lsb_carry, a, bk);
    //cout << "ci/tmp0: ";
    //cout << result->b << endl;
}

// this function compares two multibit words, and puts the max in result
void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        //cout << i << endl;
        //cout << &tmps[0] << endl;
        //cout << "a: ";
        //cout << &a[i]<< endl;
        //cout << "b: ";
        //cout << &b[i] << endl;
        //cout << &tmps[0] << endl;
        //cout << &tmps[1] << endl;
        //cout << endl;
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        cout << i << ":";
        cout << &tmps[i] << endl;
        cout << "result:";
        cout << &result[i] << endl;
        cout << "a:";
        cout << &a[i] << endl;
        cout << "b:";
        cout << &b[i] << endl;
        bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);
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
    //FILE* secret_key = fopen("secret.key","rb");
    //TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);

    bootsCONSTANT(&cINBit[0], 0, bk);

    for (int i=1; i<nb_bits+1; i++) {
        additionCarryGen(&carryGen[i-1], &a[i-1], &b[i-1], bk);
        additionCarryResult(&result[i-1], &carryProp[i-1], &cINBit[i-1], &a[i-1], &b[i-1], bk);
        //cout << "a[" << i-1 << "]: " << bootsSymDecrypt(&a[i-1], key) << endl;
        //cout << "b[" << i-1 << "]: " << bootsSymDecrypt(&b[i-1], key) << endl;
        //cout << "c[" << i-1 << "]: " << bootsSymDecrypt(&cINBit[i-1], key) << endl;
        //bootsXOR(&carryProp[i-1], &a[i-1], &b[i-1], bk);
        //cout << "carryProp[" << i-1 << "]: " << bootsSymDecrypt(&carryProp[i-1], key) << endl;
        //bootsXOR(&carryResult[i-1], &carryProp[i-1], &cINBit[i-1], bk);
        //cout << "carryGen[" << i-1 << "]: " << bootsSymDecrypt(&carryGen[i-1], key) << endl;
        additionCarryBit(&cINBit[i], &carryGen[i-1], &carryBit[i-1], &cINBit[i-1], &a[i-1], &b[i-1], bk);
        //bootsXOR(&carryBit[i-1], &a[i-1], &b[i-1], bk);
        //cout << "result " << bootsSymDecrypt(&carryBit[i-1], key) << endl;
        //bootsAND(&carryBit[i-1], &carryBit[i-1], &cINBit[i-1], bk);
        //cout << "result " << bootsSymDecrypt(&carryBit[i-1], key) << endl;
        //bootsOR(&cINBit[i], &carryBit[i-1], &carryGen[i-1], bk);
        //cout << "carryBit[" << i << "]: " << bootsSymDecrypt(&cINBit[i], key) << endl;
        //cout << "carryResult[" << i-1 << "]: " << bootsSymDecrypt(&carryResult[i-1], key) << endl;
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
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);

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

    /*cout << "invert: ";
    for(int i=0; i<nb_bits; i++){
        cout << bootsSymDecrypt(&invert[i], key);
    }
    cout << endl;*/

    addition(result, invert, a, nb_bits, bk);


    delete_gate_bootstrapping_ciphertext(temp);
    delete_gate_bootstrapping_ciphertext(temp2);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, carry_bit);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, invert);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, cINBit);

}
