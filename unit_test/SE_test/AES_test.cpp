#include <SE/AES.h>

mpz_t key;
mpz_t plaintext;
mpz_t ciphertext;
mpz_t decrypted_plaintext;

void test_init(){
    mpz_inits(key, plaintext, ciphertext, decrypted_plaintext, NULL);
}

void test_clear(){
    mpz_clears(key, plaintext, ciphertext, decrypted_plaintext, NULL);
}

int test(){
    AES *aes = new AES();

    aes->KGen(256, &key);

    GenerateRandomWithLength(plaintext, 128);
    gmp_printf("plaintext (mpz_t): %Zd\n", plaintext);

    aes->Enc(&key, &plaintext, &ciphertext);
    // print ciphertext
    // gmp_printf("Ciphertext (mpz_t): %Zd\n ",ciphertext);

    aes->Dec(&key, &ciphertext, &decrypted_plaintext);
    gmp_printf("Decrypted plaintext (mpz_t): %Zd\n", decrypted_plaintext);

    if (mpz_cmp(plaintext, decrypted_plaintext) == 0) {
        printf("Decryption successful!\n");
        return 0;
    } else {
        printf("Decryption failed.\n");
        return 1;
    }
}

int main(){
    test_init();

    int result = test();

    if(result == 0){
        test_clear();
        return 0;
    }else{
        test_clear();
        return 1;
    }
    
}