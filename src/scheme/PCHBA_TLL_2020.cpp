#include <scheme/PCHBA_TLL_2020.h>

/**
 * input : (y,h,m),(u11,u12,u2)
 * output: res
 */
void PCHBA_TLL_2020::H(element_t *m, element_t *res) {
    Hm_1(*m, *res);
}

PCHBA_TLL_2020::PCHBA_TLL_2020(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT) {
    this->G1 = _G1;
    this->G2 = _G2;
    this->Zn = _Zn;
    this->GT = _GT;

    element_init_same_as(this->tmp_G1, *this->G1);
    element_init_same_as(this->tmp_G1_2, *this->G1);  
    element_init_same_as(this->tmp_G1_3, *this->G1);  
    element_init_same_as(this->tmp_G1_4, *this->G1);
    element_init_same_as(this->tmp_G2, *this->G2);
    element_init_same_as(this->tmp_Zn, *this->Zn);  
    element_init_same_as(this->tmp_Zn_2, *this->Zn);  
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_GT_3, *this->GT);
    

    element_init_same_as(this->h, *this->G2);
    element_init_same_as(this->g, *this->G1);
    element_init_same_as(this->x, *this->Zn);

    element_init_same_as(this->a1, *this->Zn);
    element_init_same_as(this->a2, *this->Zn);
    element_init_same_as(this->b1, *this->Zn);
    element_init_same_as(this->b2, *this->Zn);
    element_init_same_as(this->a, *this->Zn);
    element_init_same_as(this->b, *this->Zn);

    element_init_same_as(this->d1, *this->Zn);
    element_init_same_as(this->d2, *this->Zn);
    element_init_same_as(this->d3, *this->Zn);

    element_init_same_as(this->r, *this->Zn);
    element_init_same_as(this->r1, *this->Zn);
    element_init_same_as(this->r2, *this->Zn);

    
}

/**
 * input : k
 * output: sk,pk
 *         mpk = g,h,H1,H2,T1,T2,array_g{g1, · · · gk},array_g_pow_a{g1^a, · · · ,gk^a}, array_h{h1, · · · hk },
 *               g_pow_a(g^α), h_pow_d_div_a(h^(d/α)), h_pow_1_div_a(h^(1/α)), h_pow_b_div_a(h^(β/α)) 
 *         msk = a1, a2,b1,b2, α, β,g_pow_d1(g^d1) ,g_pow_d2(g^d2) ,g_pow_d3(g^d3) , array_z{z1, · · · , zk }
 */
void PCHBA_TLL_2020::PG(unsigned long int k,
                        element_t *sk, element_t *pk, 
                        element_t *_g, element_t *_h, element_t *H1, element_t *H2, element_t *T1, element_t *T2,
                            element_t *array_g, element_t *array_g_pow_a,
                            element_t *array_h, element_t* g_pow_a, element_t* h_pow_d_div_a, element_t* h_pow_1_div_a, element_t* h_pow_b_div_a,
                        element_t *_a1, element_t *_a2, element_t *_b1, element_t *_b2, element_t *_a, element_t *_b,
                            element_t *g_pow_d1, element_t *g_pow_d2, element_t *g_pow_d3, element_t *array_z) {
    element_random(this->h);
    element_random(this->g);

    // 1) chameleon key pair (sk, pk)
    element_random(this->x);
    element_set(*sk, this->x);
    element_printf("sk = %B\n", *sk);
    // pk = h^x
    element_pow_zn(*pk, this->h, this->x);
    element_printf("pk = %B\n", *pk);

    // 2) masterpublic key mpk
    element_set(*_g, this->g);
    element_set(*_h, this->h);
    // H1 = h^a1
    element_random(this->a1);
    element_pow_zn(*H1, this->h, this->a1);
    // H2 = h^a2
    element_random(this->a2);
    element_pow_zn(*H2, this->h, this->a2);
    // T1 =e(g,h)^(d1 *a1 + d3/α)
    element_pairing(this->tmp_GT, this->g, this->h);
    element_random(this->d1);
    element_random(this->d3);
    element_random(this->a);
    element_mul(this->tmp_Zn, this->d1, this->a1);
    element_div(this->tmp_Zn_2, this->d3, this->a);
    element_add(this->tmp_Zn, this->tmp_Zn, this->tmp_Zn_2);
    element_pow_zn(*T1, this->tmp_GT, this->tmp_Zn);
    // T2 = e(g,h)^(d2 * a2 + d3/α)
    element_random(this->d2);
    element_mul(this->tmp_Zn, this->d2, this->a2);
    element_add(this->tmp_Zn, this->tmp_Zn, this->tmp_Zn_2);
    element_pow_zn(*T2, this->tmp_GT, this->tmp_Zn);
    // {g1, · · · ,gk } = {g^z1 , · · · ,g^zk }, {z1, · · · , zk } ∈ Zq
    // {g1^a, · · · ,gk^a}
    // {h1, · · · ,hk } = {h^z1 , · · · ,h^zk }
    for(unsigned long int i = 1; i <= k; i++){
        element_random(array_z[i]);
        element_pow_zn(array_g[i], this->g, array_z[i]);
        element_pow_zn(array_g_pow_a[i], array_g[i], this->a);
        element_pow_zn(array_h[i], this->h, array_z[i]);
    }
    // g_pow_a = g^α
    element_pow_zn(*g_pow_a, this->g, this->a);
    // h_pow_d_div_a = h^(d/α)
    // d = d1 +d2 + d3
    element_add(this->tmp_Zn, this->d1, this->d2);
    element_add(this->tmp_Zn, this->tmp_Zn, this->d3);
    element_div(this->tmp_Zn, this->tmp_Zn, this->a);
    element_pow_zn(*h_pow_d_div_a, this->h, this->tmp_Zn);
    // h_pow_1_div_a = h^(1/α)
    element_invert(this->tmp_Zn, this->a);
    element_pow_zn(*h_pow_1_div_a, this->h, this->tmp_Zn);
    // h_pow_b_div_a = h^(β/α)
    element_random(this->b);
    element_div(this->tmp_Zn, this->b, this->a);
    element_pow_zn(*h_pow_b_div_a, this->h, this->tmp_Zn);

    // 3) master secret key msk
    element_set(*_a1, this->a1);
    element_set(*_a2, this->a2);
    element_random(this->b1);
    element_set(*_b1, this->b1);
    element_random(this->b2);
    element_set(*_b2, this->b2);
    element_set(*_a, this->a);
    element_set(*_b, this->b);
    // g_pow_d1 = g^d1
    element_pow_zn(*g_pow_d1, this->g, this->d1);
    // g_pow_d2 = g^d2
    element_pow_zn(*g_pow_d2, this->g, this->d2);
    // g_pow_d3 = g^d3
    element_pow_zn(*g_pow_d3, this->g, this->d3);
}

/**
 * input : sk, δ, 
 * output: skδi = (x,sski)
 */
void PCHBA_TLL_2020::KG() {  
    // r = r1 + r2
    element_random(this->r1);
    element_random(this->r2);
    element_add(this->r, this->r1, this->r2);
    
}
 

/**
 * input : ID, L, m
 * output: r(r1,r2), h
 */
void PCHBA_TLL_2020::Hash(element_t *ID, element_t *L, element_t *m, element_t *r1, element_t *r2, element_t *h) {
    // r1 = a * P
    element_random(this->a);
    element_mul_zn(*r1, this->P, this->a);
    element_printf("r1 = %B\n", *r1);
    // r2 = e(a * Ppub, QID)
    element_mul_zn(this->tmp_G1, this->Ppub, this->a);
    element_pairing(*r2, this->tmp_G1, this->QID);
    element_printf("r2 = %B\n", *r2);
    // h = a * P + m * H(L)
    this->H(L, &this->tmp_G1);
    element_mul_zn(this->tmp_G1, this->tmp_G1, *m);
    element_add(*h, *r1, this->tmp_G1);
    element_printf("h = %B\n", *h);

    // check the correctness of the r
    // e(a * P,SID) == e(a * Ppub, QID)
    element_pairing(this->tmp_GT, *r1, this->SID);
    element_mul_zn(this->tmp_G1_2, this->Ppub, this->a);
    element_pairing(this->tmp_GT_2, this->tmp_G1_2, this->QID);
    if(element_cmp(this->tmp_GT, this->tmp_GT_2) == 0){
        printf("Hash success\n");
    }
    else{
        printf("Hash failed, r is invaid\n");
    }

}

/**
 * input : h, L, m, r1
 * output: bool
 */
bool PCHBA_TLL_2020::Check(element_t *h, element_t *L,element_t *m, element_t *r1){
    // h = r1 + m * H(L)
    this->H(L, &this->tmp_G1);
    element_mul_zn(this->tmp_G1, this->tmp_G1, *m);
    element_add(this->tmp_G1, *r1, this->tmp_G1);

    return element_cmp(*h, this->tmp_G1) == 0;    
}

/**
 * input : SID, ID, L, h, m, r1, r2, m_p
 * output: r_p(r1_p, r2_p)
 */
void PCHBA_TLL_2020::Forge(element_t *_SID, element_t *ID, element_t *L, element_t *h, element_t *m, element_t *r1, element_t *r2, element_t *m_p, 
                                element_t *r1_p, element_t *r2_p) {
    // r1_p = r1 + (m - m_p) * H(L)
    element_sub(this->tmp_Zn, *m, *m_p);
    this->H(L, &this->tmp_G1);
    element_mul_zn(this->tmp_G1_2, this->tmp_G1, this->tmp_Zn);
    element_add(*r1_p, *r1, this->tmp_G1_2);
    element_printf("r1_p = %B\n", *r1_p);
    
    // r2_p = r2 * e(SID, H(L))^(m-m_p)
    element_pairing(this->tmp_GT, *_SID, this->tmp_G1);
    element_pow_zn(this->tmp_GT_2, this->tmp_GT, this->tmp_Zn);
    element_mul(*r2_p, *r2, this->tmp_GT_2);
    element_printf("r2_p = %B\n", *r2_p);

    // check the correctness of the r_p
    // e(r1_p, SID) == r2_p
    element_pairing(this->tmp_GT_3, *r1_p, *_SID);
    if(element_cmp(this->tmp_GT_3, *r2_p) == 0){
        printf("Forge success\n");
    }
    else{
        printf("Forge failed, r_p is invaid\n");
    }
}

/**
 * input : h, L, m_p, r1_p
 * output: bool
 */
bool PCHBA_TLL_2020::Verify(element_t *h, element_t *L,element_t *m_p, element_t *r1_p) {
    return this->Check(h, L, m_p, r1_p);
}


PCHBA_TLL_2020::~PCHBA_TLL_2020() {
    element_clear(this->tmp_G1);
    element_clear(this->tmp_G1_2);
    element_clear(this->tmp_G1_3);
    element_clear(this->tmp_G1_4);
    element_clear(this->tmp_G2);
    element_clear(this->tmp_Zn);
    element_clear(this->tmp_Zn_2);
    element_clear(this->tmp_GT);
    element_clear(this->tmp_GT_2);
    element_clear(this->tmp_GT_3);

    element_clear(this->P);
    element_clear(this->x);
    element_clear(this->Ppub);
    element_clear(this->SID);
    element_clear(this->QID);
    element_clear(this->a);
}