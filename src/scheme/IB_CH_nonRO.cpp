#include <scheme/IB_CH_nonRO.h>

IB_CH_nonRO::IB_CH_nonRO(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2) {
    this->G1 = _G1;
    this->G2 = _G2;
    this->GT = _GT;
    this->Zn = _Zn;
    this->rev_G1G2 = _rev_G1G2;
    element_init_same_as(this->g_1, *this->G1);
    element_init_same_as(this->g, *this->G1);
    element_init_same_as(this->tmp_G1, *this->G1);
    element_init_same_as(this->g_2, *this->G2);
    element_init_same_as(this->tmp_G2, *this->G2);
    element_init_same_as(this->tmp_G2_2, *this->G2);
    element_init_same_as(this->msk, *this->G2);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_GT_3, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    this->u = new ElementList(2, -1, *this->G2, 1, 0);
}

void IB_CH_nonRO::Setup(int n) {
    this->u->resize(n);
    this->u->random();
    element_random(this->tmp_Zn);
    element_random(this->g);
    element_random(this->g_2);
    element_pow_zn(this->g_1, this->g, this->tmp_Zn);
    element_pow_zn(this->msk, this->g_2, this->tmp_Zn);
}

void IB_CH_nonRO::Keygen(element_t *tk_1, element_t *tk_2, ElementList *I) {
    element_random(this->tmp_Zn);
    element_pow_zn(*tk_2, this->g, this->tmp_Zn);
    this->get_u0uiIi(I, tk_1);
    element_pow_zn(*tk_1, *tk_1, this->tmp_Zn);
    element_mul(*tk_1, this->msk, *tk_1);
}

void IB_CH_nonRO::get_u0uiIi(ElementList *I, element_t *res) {
    element_set(*res, *this->u->At(0));
    for(int i = 1;i <= I->len();i++) if(element_is1(*I->At(i))) element_mul(*res, *res, *this->u->At(i));
}

void IB_CH_nonRO::base_hash(ElementList *I, element_t *h, element_t *m, element_t *r_1, element_t *r_2) {
    this->get_u0uiIi(I, &this->tmp_G2_2);
    if(this->rev_G1G2) element_pairing(*h, this->tmp_G2_2, *r_2);
    else element_pairing(*h, *r_2, this->tmp_G2_2);
    if(this->rev_G1G2) element_pairing(this->tmp_GT_3, this->g_2, this->g_1);
    else element_pairing(this->tmp_GT_3, this->g_1, this->g_2);
    element_pow_zn(this->tmp_GT, this->tmp_GT_3, *m);
    element_div(*h, this->tmp_GT, *h);
    if(this->rev_G1G2) element_pairing(this->tmp_GT, *r_1, this->g);
    else element_pairing(this->tmp_GT, this->g, *r_1);
    element_mul(*h, this->tmp_GT, *h);
}

bool IB_CH_nonRO::Verify(ElementList *I, element_t *h, element_t *m, element_t *r_1, element_t *r_2) {
    this->base_hash(I, &this->tmp_GT_2, m, r_1, r_2);
    return element_cmp(*h, this->tmp_GT_2) == 0;
}

void IB_CH_nonRO::Hash(ElementList *I, element_t *h, element_t *m, element_t *r_1, element_t *r_2) {
    element_random(*r_1);
    element_random(*r_2);
    this->base_hash(I, h, m, r_1, r_2);
}

void IB_CH_nonRO::Collision(
        element_t *tk_1, element_t *tk_2, element_t *h, element_t *m, element_t *m_p, 
        element_t *r_1, element_t *r_2, element_t *r_1_p, element_t *r_2_p
) {
    element_sub(this->tmp_Zn, *m, *m_p);
    element_pow_zn(*r_1_p, *tk_1, this->tmp_Zn);
    element_pow_zn(*r_2_p, *tk_2, this->tmp_Zn);
    element_mul(*r_1_p, *r_1, *r_1_p);
    element_mul(*r_2_p, *r_2, *r_2_p);
}

IB_CH_nonRO::~IB_CH_nonRO() {
    element_clear(this->msk);
    element_clear(this->tmp_G1);
    element_clear(this->tmp_G2);
    element_clear(this->tmp_G2_2);
    element_clear(this->tmp_GT);
    element_clear(this->tmp_GT_2);
    element_clear(this->tmp_GT_3);
    element_clear(this->tmp_Zn);
    element_clear(this->g);
    element_clear(this->g_1);
    element_clear(this->g_2);
    delete this->u;
}