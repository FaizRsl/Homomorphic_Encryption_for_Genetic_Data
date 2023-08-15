#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
using namespace std;

void result(int choice){

    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);

    const TFheGateBootstrappingParameterSet* params = key->params;

    LweSample* answer = new_gate_bootstrapping_ciphertext_array(16, params);

    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<16; i++)
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i], params);
    fclose(answer_data);

    int16_t int_answer = 0;
    for (int i=0; i<16; i++) {
        int ai = bootsSymDecrypt(&answer[i], key);
        int_answer |= (ai<<i);
    }
    if(choice != 5)
        printf("And the result is: %d\n",int_answer);
    else{
        if(int_answer)
            printf("The equal test results is TRUE");
        else
            printf("The equal test results is FALSE");
    }

    delete_gate_bootstrapping_ciphertext_array(16, answer);
    delete_gate_bootstrapping_secret_keyset(key);
}