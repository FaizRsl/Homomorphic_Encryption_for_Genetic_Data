#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <iostream>
#include "operation.cpp"
#include "result.cpp"
using namespace std;

int operatorOptions(){
    int choice;
    cout << "1) addition " << endl;
    cout << "2) subtraction " << endl;
    cout << "3) min " << endl;
    cout << "4) max " << endl;
    cout << "5) equal " << endl;
    cout << "6) selection " << endl;
    cout << "Enter the operation that you want to apply a and b to:" << endl;
    cin >> choice;
    operation(choice);
    return choice;
}

int main() {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    int inputa;
    int inputb;

    cout << "Please key in the two number that are between -32,768 and 32767." << endl;
    cout << "a: ";
    cin >> inputa;
    cout << "b: ";
    cin >> inputb;


    //generate encrypt the 16 bits of 51
    int16_t plaintext1 = inputa;
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext1[i], (plaintext1>>i)&1, key);
    }

    //generate encrypt the 16 bits of 49
    int16_t plaintext2 = inputb;
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i=0; i<16; i++) {
        bootsSymEncrypt(&ciphertext2[i], (plaintext2>>i)&1, key);
    }

    //export the 2x16 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<16; i++)
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(16, ciphertext1);

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    int choice = operatorOptions();
    result(choice);
}

