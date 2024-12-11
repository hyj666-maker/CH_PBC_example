#ifndef AES_H
#define AES_H

#include <utils/func.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdexcept> 


class AES{
    private:
        int k;

    public:
        AES();

        void KGen(mpz_t *key);
        void KGen(int k, mpz_t *key);

        void Enc(mpz_t *key, mpz_t *plaintext, mpz_t *ciphertext);

        void Dec(mpz_t *key, mpz_t *ciphertext, mpz_t *decrypted_plaintext);

        ~AES();
};


#endif  // AES_H