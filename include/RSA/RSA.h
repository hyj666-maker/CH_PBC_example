#ifndef RSA_H
#define RSA_H

#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <time.h>

class RSA{
    private:
    mpz_t *n; // 模数
    mpz_t *e; // 公钥指数
    mpz_t *d; // 私钥指数
    
    public:
    RSA(mpz_t *n, mpz_t *e, mpz_t *d);

    void rsa_clear();

    void rsa_generate_keys(unsigned long bit_size);

    void rsa_generate_keys_2(unsigned long bit_size, unsigned long int k);
    void rsa_generate_keys_2(unsigned long bit_size, unsigned long int k, mpz_t *phi);

    void rsa_generate_keys_pqn(unsigned long bit_size, mpz_t *p, mpz_t *q, mpz_t *n);

    void rsa_encrypt(mpz_t *ciphertext, const mpz_t *plaintext);

    void rsa_decrypt(mpz_t *plaintext, const mpz_t *ciphertext);

};

#endif  //RSA_H