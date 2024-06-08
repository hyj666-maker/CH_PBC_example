#include <scheme/IB_CH_KEF.h>

void IB_CH_KEF::H(element_t *m, element_t *res) {
    Hm(*m, *res, this->tmp_Zn, *this->G2);
}

void IB_CH_KEF::H_G1(element_t *m, element_t *res) {
    Hm(*m, *res, this->tmp_Zn, *this->G1);
}

IB_CH_KEF::IB_CH_KEF(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2) {
    this->G1 = _G1;
    this->G2 = _G2;
    this->Zn = _Zn;
    this->GT = _GT;
    this->rev_G1G2 = _rev_G1G2;
    element_init_same_as(this->P, *this->G1);
    element_init_same_as(this->P_pub, *this->G1);
    element_init_same_as(this->tmp_G1, *this->G1);
    element_init_same_as(this->tmp_G2, *this->G2);
    element_init_same_as(this->tmp_G1_2, *this->G1);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->x, *this->Zn);
}

void IB_CH_KEF::Setup() {
    element_random(this->P);
    element_random(this->x);
    element_mul_zn(this->P_pub, this->P, this->x);
}

void IB_CH_KEF::Extract(element_t *ID, element_t *S_ID) {
    this->H(ID, &this->tmp_G2);
    element_mul_zn(*S_ID, this->tmp_G2, this->x);
}

void IB_CH_KEF::base_hash(element_t *ID, element_t *L, element_t *H, element_t *m, element_t *r_1, element_t *r_2) {
    this->H_G1(L, &this->tmp_G1);
    element_mul_zn(*H, this->tmp_G1, *m);
    element_add(*H, *H, *r_1);
}

void IB_CH_KEF::Hash(element_t *ID, element_t *L, element_t *H, element_t *m, element_t *r_1, element_t *r_2) {
    element_random(this->tmp_Zn);
    element_mul_zn(*r_1, this->P, this->tmp_Zn);
    this->H(ID, &this->tmp_G2);
    element_mul_zn(this->tmp_G1, this->P_pub, this->tmp_Zn);
    if(this->rev_G1G2) element_pairing(*r_2, this->tmp_G2, this->tmp_G1);
    else element_pairing(*r_2, this->tmp_G1, this->tmp_G2);
    this->base_hash(ID, L, H, m, r_1, r_2);
}

void IB_CH_KEF::Forge(element_t *S_ID, element_t *L, element_t *m, element_t *m_p, element_t *r_1, element_t *r_2, element_t *r_1_p, element_t *r_2_p) {
    element_sub(this->tmp_Zn, *m, *m_p);
    this->H_G1(L, &this->tmp_G1);
    element_mul_zn(*r_1_p, this->tmp_G1, this->tmp_Zn);
    element_add(*r_1_p, *r_1, *r_1_p);
    if(this->rev_G1G2) element_pairing(*r_2_p, *S_ID, this->tmp_G1);
    else element_pairing(*r_2_p, this->tmp_G1, *S_ID);
    element_pow_zn(*r_2_p, *r_2_p, this->tmp_Zn);
    element_mul(*r_2_p, *r_2, *r_2_p);
}

bool IB_CH_KEF::Verify(element_t *ID, element_t *L, element_t *H, element_t *m, element_t *r_1, element_t *r_2, element_t *S_ID) {
    this->base_hash(ID, L, &this->tmp_G1, m, r_1, r_2);
    if(element_cmp(*H, this->tmp_G1) != 0) return 0;
    if(this->rev_G1G2) element_pairing(this->tmp_GT, *S_ID, *r_1);
    else element_pairing(this->tmp_GT, *r_1, *S_ID);
    return element_cmp(*r_2, this->tmp_GT) == 0;

}

IB_CH_KEF::~IB_CH_KEF() {
    element_clear(this->P);
    element_clear(this->x);
    element_clear(this->P_pub);
    element_clear(this->tmp_G1);
    element_clear(this->tmp_G2);
    element_clear(this->tmp_G1_2);
    element_clear(this->tmp_GT);
    element_clear(this->tmp_Zn);
}