#include <scheme/IB_CH_Our.h>

Our_IB_CH::Our_IB_CH(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2) {
    this->G1 = _G1;
    this->G2 = _G2;
    this->GT = _GT;
    this->Zn = _Zn;
    this->rev_G1G2 = _rev_G1G2;
    element_init_same_as(this->tmp_G1, *this->G1);
    element_init_same_as(this->_g_1, *this->G1);
    element_init_same_as(this->g_1, *this->G1);
    element_init_same_as(this->g_2, *this->G2);
    element_init_same_as(this->_g_2, *this->G2);
    element_init_same_as(this->tmp_G2, *this->G2);
    element_init_same_as(this->eg2g, *this->GT);
    element_init_same_as(this->egg, *this->GT);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->tmp_Zn_2, *this->Zn);
    element_init_same_as(this->msk_1, *this->Zn);
    element_init_same_as(this->msk_2, *this->Zn);
}

void Our_IB_CH::Setup() {
    element_random(this->_g_1);
    element_random(this->_g_2);
    element_random(this->msk_1);
    element_random(this->msk_2);
    element_mul_zn(this->g_1, this->_g_1, this->msk_1);
    element_mul_zn(this->g_2, this->_g_2, this->msk_2);
    if(this->rev_G1G2) element_pairing(this->egg, this->_g_2, this->_g_1);
    else element_pairing(this->egg, this->_g_1, this->_g_2);
    if(this->rev_G1G2) element_pairing(this->eg2g, this->g_2, this->_g_1);
    else element_pairing(this->eg2g, this->_g_1, this->g_2);
}

void Our_IB_CH::Keygen(element_t *ID, element_t *td_1, element_t *td_2) {
    element_random(*td_1);
    element_sub(this->tmp_Zn, this->msk_2, *td_1);
    element_sub(this->tmp_Zn_2, this->msk_1, *ID);
    element_div(this->tmp_Zn, this->tmp_Zn, this->tmp_Zn_2);
    element_pow_zn(*td_2, this->_g_2, this->tmp_Zn);
}

void Our_IB_CH::base_hash(element_t *h, element_t *m, element_t *ID, element_t *r_1, element_t *r_2) {
    element_pow_zn(this->tmp_G1, this->_g_1, *ID);
    element_div(this->tmp_G1, this->g_1, this->tmp_G1);
    if(this->rev_G1G2) element_pairing(*h, *r_2, this->tmp_G1);
    else element_pairing(*h, this->tmp_G1, *r_2);
    element_pow_zn(this->tmp_GT, this->egg, *r_1);
    element_mul(*h, *h, this->tmp_GT);
    element_pow_zn(this->tmp_GT, this->eg2g, *m);
    element_mul(*h, *h, this->tmp_GT);
}


void Our_IB_CH::Hash(element_t *h, element_t *m, element_t *ID, element_t *r_1, element_t *r_2) {
    element_random(*r_1);
    element_random(*r_2);
    this->base_hash(h, m, ID, r_1, r_2);
}

void Our_IB_CH::Collision(element_t *td_1, element_t *td_2, element_t *m, element_t *m_p, element_t *r_1, element_t *r_2, element_t *r_1_p, element_t *r_2_p) {
    element_sub(this->tmp_Zn, *m, *m_p);
    element_mul_zn(*r_1_p, *td_1, this->tmp_Zn);
    element_pow_zn(*r_2_p, *td_2, this->tmp_Zn);
    element_add(*r_1_p, *r_1, *r_1_p);
    element_mul(*r_2_p, *r_2, *r_2_p);
}

bool Our_IB_CH::Verify(element_t *h, element_t *m, element_t *ID, element_t *r_1, element_t *r_2) {
    this->base_hash(&this->tmp_GT_2, m, ID, r_1, r_2);
    return element_cmp(*h, this->tmp_GT_2) == 0;
}

Our_IB_CH::~Our_IB_CH() {
    element_clear(this->tmp_G1);
    element_clear(this->tmp_G2);
    element_clear(this->tmp_GT);
    element_clear(this->tmp_GT_2);
    element_clear(this->tmp_Zn);
    element_clear(this->tmp_Zn_2);
    element_clear(this->g_1);
    element_clear(this->g_2);
    element_clear(this->_g_1);
    element_clear(this->_g_2);
    element_clear(this->eg2g);
    element_clear(this->egg);
    element_clear(this->msk_1);
    element_clear(this->msk_2);
}

Our_IB_CH_KEF::Our_IB_CH_KEF(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2): Our_IB_CH(_G1, _G2, _Zn, _GT, _rev_G1G2) {
    element_init_same_as(this->h_2, *this->G2);
    element_init_same_as(this->u_2, *this->G2);
    element_init_same_as(this->tmp_G2_2, *this->G2);
    element_init_same_as(this->tmp_G1_2, *this->G1);
    element_init_same_as(this->td_1b, *this->Zn);
    element_init_same_as(this->td_2b, *this->G2);
    element_init_same_as(this->td_3b, *this->G1);
}

void Our_IB_CH_KEF::Setup() {
    Our_IB_CH::Setup();
    element_random(this->h_2);
    element_pow_zn(this->u_2, this->h_2, this->msk_1);
}

void Our_IB_CH_KEF::base_hash(element_t *h, element_t *m, element_t *ID, element_t *L, element_t *r_1, element_t *r_2, element_t *r_3) {
    Our_IB_CH::base_hash(h, m, ID, r_1, r_2);
    this->get_ab_ID(ID, &this->tmp_G2, &this->u_2, &this->h_2);
    element_pow_zn(this->tmp_G2, this->tmp_G2, *L);
    if(this->rev_G1G2) element_pairing(this->tmp_GT, this->tmp_G2, *r_3);
    else element_pairing(this->tmp_GT, *r_3, this->tmp_G2);
    element_mul(*h, *h, this->tmp_GT);
}

void Our_IB_CH_KEF::get_ab_ID(element_t *ID, element_t *res, element_t *a, element_t *b) {
    element_pow_zn(*res, *a, *ID);
    element_div(*res, *b, *res);
}

void Our_IB_CH_KEF::Hash(element_t *h, element_t *m, element_t *ID, element_t *L, element_t *r_1, element_t *r_2, element_t *r_3) {
    element_random(*r_1);
    element_random(*r_2);
    element_random(*r_3);
    this->base_hash(h, m, ID, L, r_1, r_2, r_3);
}

void Our_IB_CH_KEF::Collision(element_t *ID, element_t *td_1, element_t *td_2, element_t *L, element_t *m, element_t *m_p, element_t *r_1, element_t *r_2, element_t *r_3, element_t *r_1_p, element_t *r_2_p, element_t *r_3_p) {
    element_set(this->td_1b, *td_1);
    element_random(this->tmp_Zn);
    element_random(this->tmp_Zn_2);
    element_add(this->tmp_Zn, this->tmp_Zn, this->tmp_Zn_2);
    this->get_ab_ID(ID, &this->tmp_G1_2, &this->g_1, &this->_g_1);
    element_pow_zn(this->td_3b, this->tmp_G1, this->tmp_Zn);
    element_mul_zn(this->tmp_Zn, this->tmp_Zn, *L);
    this->get_ab_ID(ID, &this->tmp_G2_2, &this->u_2, &this->h_2);
    element_pow_zn(this->td_2b, this->tmp_G2_2, this->tmp_Zn);
    element_mul(this->td_2b, this->td_2b, *td_2);
    element_sub(this->tmp_Zn_2, *m, *m_p);
    element_mul_zn(*r_1_p, this->td_1b, this->tmp_Zn_2);
    element_add(*r_1_p, *r_1, *r_1_p);
    element_pow_zn(*r_3_p, this->td_3b, this->tmp_Zn_2);
    element_div(*r_3_p, *r_3, *r_3_p);
    element_pow_zn(*r_2_p, this->td_2b, this->tmp_Zn_2);
    element_mul(*r_2_p, *r_2, *r_2_p);
    // element_random(this->tmp_Zn);
    // element_sub(this->tmp_Zn_2, *m, *m_p);
    // element_mul_zn(*r_1_p, this->td_1b, this->tmp_Zn_2);
    // element_add(*r_1_p, *r_1, *r_1_p);
    // element_pow_zn(this->tmp_G1_2, this->tmp_G1_2, this->tmp_Zn);
    // element_mul(this->tmp_G1_2, this->td_3b, this->tmp_G1_2);
    // element_pow_zn(this->tmp_G1_2, this->tmp_G1_2, this->tmp_Zn_2);
    // element_mul(*r_3_p, *r_3, this->tmp_G1_2);
    // element_mul_zn(this->tmp_Zn, this->tmp_Zn, *L);
    // element_pow_zn(this->tmp_G2_2, this->tmp_G2_2, this->tmp_Zn);
    // element_mul(this->tmp_G2_2, this->td_2b, this->tmp_G2_2);
    // element_pow_zn(this->tmp_G2_2, this->tmp_G2_2, this->tmp_Zn_2);
    // element_mul(*r_2_p, *r_2, this->tmp_G2_2);
}

bool Our_IB_CH_KEF::Verify(element_t *h, element_t *m, element_t *ID, element_t *L, element_t *r_1, element_t *r_2, element_t *r_3) {
    this->base_hash(&this->tmp_GT_2, m, ID, L, r_1, r_2, r_3);
    return element_cmp(*h, this->tmp_GT_2) == 0;
}

Our_IB_CH_KEF::~Our_IB_CH_KEF() {
    element_clear(this->h_2);
    element_clear(this->u_2);
    element_clear(this->td_1b);
    element_clear(this->td_2b);
    element_clear(this->td_3b);
    element_clear(this->tmp_G2_2);
    element_clear(this->tmp_G1_2);
}