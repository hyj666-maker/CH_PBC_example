#include <RSA/RSA.h>

MyRSA::MyRSA(mpz_t *n, mpz_t *e, mpz_t *d) {
    this->n = n;
    this->e = e;
    this->d = d;

    // 初始化
    mpz_init(*this->n);
    mpz_init(*this->e);
    mpz_init(*this->d);
}

// 释放密钥对
void MyRSA::rsa_clear() {
    mpz_clear(*this->n);
    mpz_clear(*this->e);
    mpz_clear(*this->d);
}

// 生成大素数 p 和 q，计算 n, φ(n) 等
void MyRSA::rsa_generate_keys(unsigned long bit_size) {
    mpz_t p, q, phi, gcd;
    mpz_inits(p, q, phi, gcd, NULL);

    // 设置随机数种子
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // 生成两个大素数 p 和 q
    mpz_urandomb(p, state, bit_size / 2);   // 生成随机数
    mpz_nextprime(p, p);    // 找到大于 p 的下一个素数
    mpz_urandomb(q, state, bit_size / 2);
    mpz_nextprime(q, q);

    // 输出p，q的大小(bytes)
    size_t bits = mpz_sizeinbase(p, 2);
    size_t bytes = (bits + 7) / 8;
    printf("sizeof(p): %zu bytes\n", bytes);
    bits = mpz_sizeinbase(q, 2);
    bytes = (bits + 7) / 8;
    printf("sizeof(q): %zu bytes\n", bytes);
    
    // 计算 n = p * q
    mpz_mul(*this->n, p, q);

    // 计算 φ(n) = (p-1)*(q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);

    // 设置公钥指数 e，通常取 65537
    mpz_set_ui(*this->e, 65537);

    // 计算私钥 d，使得 e * d ≡ 1 (mod φ(n))
    mpz_invert(*this->d, *this->e, phi);    // 计算 d = e^(-1) mod φ(n)

    // 清理中间变量
    mpz_clears(p, q, phi, gcd, NULL);
}

// 加密：c = m^e mod n
void MyRSA::rsa_encrypt(mpz_t *ciphertext, const mpz_t *plaintext) {
    mpz_powm(*ciphertext, *plaintext, *this->e, *this->n);
}

// 解密：m = c^d mod n
void MyRSA::rsa_decrypt(mpz_t *plaintext, const mpz_t *ciphertext) {
    mpz_powm(*plaintext, *ciphertext, *this->d, *this->n);
}

/**
 * RSA密钥生成函数 
 * e > n^k
 */
void MyRSA::rsa_generate_keys_2(unsigned long bit_size, unsigned long int k) {
    mpz_t p, q, phi, gcd, nk;
    mpz_inits(p, q, phi, gcd, nk, NULL);

    // 设置随机数种子
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // 生成两个大素数 p 和 q
    mpz_urandomb(p, state, bit_size / 2);   // 生成随机数
    mpz_nextprime(p, p);    // 找到大于 p 的下一个素数
    mpz_urandomb(q, state, bit_size / 2);
    mpz_nextprime(q, q);

    // 计算 n = p * q
    mpz_mul(*this->n, p, q);

    // 计算 φ(n) = (p-1)*(q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);

    // 生成 e，使 e 为大于 n^k 的素数
    mpz_pow_ui(nk, *this->n, k);
    mpz_nextprime(*this->e, nk);

    // 计算私钥 d，使得 e * d ≡ 1 (mod φ(n))
    mpz_invert(*this->d, *this->e, phi);    // 计算 d = e^(-1) mod φ(n)

    // 清理中间变量
    mpz_clears(p, q, phi, gcd, nk, NULL);
}

/**
 * RSA密钥生成函数 
 * e > n^k
 */
void MyRSA::rsa_generate_keys_2(unsigned long bit_size, unsigned long int k, mpz_t *phi) {
    mpz_t p, q, gcd, nk;
    mpz_inits(p, q, gcd, nk, NULL);

    // 设置随机数种子
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // 生成两个大素数 p 和 q
    mpz_urandomb(p, state, bit_size / 2);   // 生成随机数
    mpz_nextprime(p, p);    // 找到大于 p 的下一个素数
    mpz_urandomb(q, state, bit_size / 2);
    mpz_nextprime(q, q);

    // 计算 n = p * q
    mpz_mul(*this->n, p, q);

    // 计算 φ(n) = (p-1)*(q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(*phi, p, q);

    // 生成 e，使 e 为大于 n^k 的素数
    mpz_pow_ui(nk, *this->n, k);
    mpz_nextprime(*this->e, nk);

    // 计算私钥 d，使得 e * d ≡ 1 (mod φ(n))
    mpz_invert(*this->d, *this->e, *phi);    // 计算 d = e^(-1) mod φ(n)

    // 清理中间变量
    mpz_clears(p, q, gcd, nk, NULL);
}

/**
 * 生成大素数 p 和 q，计算 n
 */
void MyRSA::rsa_generate_keys_pqn(unsigned long bit_size, mpz_t *p, mpz_t *q, mpz_t *n) {
    // 设置随机数种子
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // 生成两个大素数 p 和 q
    mpz_urandomb(*p, state, bit_size / 2);   // 生成随机数
    mpz_nextprime(*p, *p);    // 找到大于 p 的下一个素数
    mpz_urandomb(*q, state, bit_size / 2);
    mpz_nextprime(*q, *q);

    // 计算 n = p * q
    mpz_mul(*n, *p, *q);
}


/**
 * RSA密钥生成函数 
 * input: e
 * output: n, d
 */
void MyRSA::rsa_generate_keys_with_e(unsigned long bit_size, mpz_t *e) {
    mpz_t p, q, phi, gcd, nk;
    mpz_inits(p, q, phi, gcd, nk, NULL);

    // 设置随机数种子
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    // 生成两个大素数 p 和 q
    mpz_urandomb(p, state, bit_size / 2);   // 生成随机数
    mpz_nextprime(p, p);    // 找到大于 p 的下一个素数
    mpz_urandomb(q, state, bit_size / 2);
    mpz_nextprime(q, q);

    // 计算 n = p * q
    mpz_mul(*this->n, p, q);

    // 计算 φ(n) = (p-1)*(q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);

    // e
    mpz_set(*this->e, *e);

    // 计算私钥 d，使得 e * d ≡ 1 (mod φ(n))
    mpz_invert(*this->d, *this->e, phi);    // 计算 d = e^(-1) mod φ(n)

    // 清理中间变量
    mpz_clears(p, q, phi, gcd, nk, NULL);
}


mpz_t *MyRSA::getN(){
    return this->n;
}

mpz_t *MyRSA::getE(){
    return this->e;
}

mpz_t *MyRSA::getD(){
    return this->d;
}