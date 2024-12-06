#include <scheme/CH_KEF_NoMH_AM_2004.h>

CH_KEF_NoMH_AM_2004::CH_KEF_NoMH_AM_2004() {
    mpz_init(this->p);
    mpz_init(this->q);
}

/**
 * input: k
 * output: pk, sk
 */
void CH_KEF_NoMH_AM_2004::GenKey(int k, pk *pk, sk *sk) {
    GenerateRandomWithLength(this->p, k);
    gmp_printf("Prime p = %Zd\n", this->p);

    // q = (p-1)/2
    mpz_sub_ui(this->q, this->p, 1);
    mpz_div_ui(this->q, this->q, 2);
    gmp_printf("Prime q = %Zd\n", this->q);

    // find g
    Find_generator(&pk->g, &this->p, &this->q);
    gmp_printf("Generator g = %Zd\n", pk->g);

    // chooses as secret key x at random in [1, q − 1]
    GenerateRandomInN(sk->x, this->q);
    gmp_printf("Secret key x = %Zd\n", sk->x);

    // y = g^x mod p
    mpz_powm(pk->y, pk->g, sk->x, this->p);
}

/**
 * 找到二次剩余子群的生成元 g
 */
void CH_KEF_NoMH_AM_2004::Find_generator(mpz_t *g, mpz_t *p, mpz_t *q) {
    // TODO
    // !!! how to find generator
    mpz_t exp, result;
    mpz_init(exp);
    mpz_init(result);

    // exp = q
    mpz_set(exp, *q);
    
    // 尝试 g = 2, 3, ..., p-1
    for (mpz_set_ui(*g, 2); mpz_cmp(*g, *p) < 0; mpz_add_ui(*g, *g, 1)) {
        // 计算 g^q mod p
        mpz_powm(result, *g, exp, *p);

        // 如果 g^q mod p == p-1，则 g 是生成元
    if (mpz_cmp_ui(result, 1) == 0) {
            break;
        }
    }

    mpz_clear(exp);
    mpz_clear(result);
}



/**
 * input: pk, m, r, s
 * output: h
 */
void CH_KEF_NoMH_AM_2004::Hash(pk *pk, mpz_t *m, mpz_t *r, mpz_t *s, mpz_t *h) {
    // random r,s
    GenerateRandomInN(*r, this->q);
    GenerateRandomInN(*s, this->q);
    gmp_printf("r = %Zd\n", *r);
    gmp_printf("s = %Zd\n", *s);

    mpz_t e;
    mpz_inits(e, NULL);
    // e = H(m,r)
    this->H(m, r, &e);

    // h = r - ((y^e)(g^s) mod p)mod q
    mpz_t y_pow_e, g_pow_s, tmp, tmp_2;
    mpz_inits(y_pow_e, g_pow_s, tmp, tmp_2, NULL);
    mpz_powm(y_pow_e, pk->y, e, this->p);
    mpz_powm(g_pow_s, pk->g, *s, this->p);
    mpz_mul(tmp, y_pow_e, g_pow_s);
    mpz_mod(tmp, tmp, this->p);

    mpz_sub(tmp_2, *r, tmp);
    mpz_mod(*h, tmp_2, this->q);
    

    mpz_clears(e, y_pow_e, g_pow_s, tmp, tmp_2, NULL);
}

/**
 * Hash function
 */
void CH_KEF_NoMH_AM_2004::H(mpz_t *m1, mpz_t *m2, mpz_t *res){
    // 2^256
    mpz_t mpz_2_256;
    mpz_init(mpz_2_256);
    mpz_ui_pow_ui(mpz_2_256, 2, 256);
    Hgsm_n(*m1, *m2, *res, mpz_2_256);
    mpz_clear(mpz_2_256);
}

/**
 * input: pk, sk, m_p, h
 * output: r_p, s_p
 */
void CH_KEF_NoMH_AM_2004::Forge(pk *pk,sk *sk, mpz_t *m_p, mpz_t *h, mpz_t *r_p, mpz_t *s_p){
    // random k_p ∈ [1,q-1]
    mpz_t k_p, g_pow_k_p,e_p,e_p_x;
    mpz_inits(k_p, g_pow_k_p,e_p,e_p_x, NULL);
    GenerateRandomInN(k_p, this->q);
    // r_p = h + (g^k_p mod p) mod q
    mpz_powm(g_pow_k_p, pk->g, k_p, this->p);
    mpz_add(*r_p, *h, g_pow_k_p);
    mpz_mod(*r_p, *r_p, this->q);

    // e_p = H(m_p, r_p)
    this->H(m_p, r_p, &e_p);

    // s_p = k_p - e_p*x mod q
    mpz_mul(e_p_x, e_p, sk->x);
    mpz_sub(*s_p, k_p, e_p_x);
    mpz_mod(*s_p, *s_p, this->q);
}



/**
 * input: pk, m, r, s, h
 * ouput: bool
 */
bool CH_KEF_NoMH_AM_2004::Check(pk *pk, mpz_t *m, mpz_t *r, mpz_t *s, mpz_t *h){
    mpz_t e;
    mpz_inits(e, NULL);
    // e = H(m,r)
    this->H(m, r, &e);

    // h = r - ((y^e)(g^s) mod p)mod q
    mpz_t y_pow_e, g_pow_s, tmp, tmp_2;
    mpz_inits(y_pow_e, g_pow_s, tmp, tmp_2, NULL);
    mpz_powm(y_pow_e, pk->y, e, this->p);
    mpz_powm(g_pow_s, pk->g, *s, this->p);
    mpz_mul(tmp, y_pow_e, g_pow_s);
    mpz_mod(tmp, tmp, this->p);

    mpz_sub(tmp_2, *r, tmp);
    mpz_mod(tmp_2, tmp_2, this->q);

    if(mpz_cmp(*h, tmp_2) == 0){
        return true;
        mpz_clears(e, y_pow_e, g_pow_s, tmp, tmp_2, NULL);
    }else{
        return false;
        mpz_clears(e, y_pow_e, g_pow_s, tmp, tmp_2, NULL);
    } 
}


/**
 * input: pk, m_p, r_p, s_p, h
 * ouput: bool
 */
bool CH_KEF_NoMH_AM_2004::Verify(pk *pk, mpz_t *m_p, mpz_t *r_p, mpz_t *s_p, mpz_t *h){
    return this->Check(pk, m_p, r_p, s_p, h);
}

CH_KEF_NoMH_AM_2004::~CH_KEF_NoMH_AM_2004() {
 
}