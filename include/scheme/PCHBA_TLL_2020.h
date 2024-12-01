#ifndef IMPORT_ELEMENTLIST
#define IMPORT_ELEMENTLIST
#include "base/ElementList.h"
#endif //IMPORT_ELEMENTLIST

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC


#ifndef PCHBA_TLL_2020_H
#define PCHBA_TLL_2020_H

#include <stdexcept>  // 包含 std::invalid_argument

class PCHBA_TLL_2020 {
    protected:
    element_t *G1, *G2, *Zn, *GT;
    element_t tmp_G1, tmp_G1_2,tmp_G1_3,tmp_G1_4, tmp_G2, tmp_Zn,tmp_Zn_2, tmp_GT,tmp_GT_2,tmp_GT_3;

    element_t h;  // generator of group H
    element_t g;  // generator of group G
    element_t x;
    element_t a1, a2,b1,b2, a,b;  // a1, a2,b1,b2,α, β ∈ Z∗q
    element_t d1,d2,d3;  // (d1,d2,d3) ∈ Zq

    element_t r,r1,r2;  // (r1,r2) ∈ Z∗q


    public:
    PCHBA_TLL_2020(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT);

    void PG(unsigned long int k,
            element_t *sk, element_t *pk, 
            element_t *_g, element_t *_h, element_t *H1, element_t *H2, element_t *T1, element_t *T2,
                element_t *array_g, element_t *array_g_pow_a,
                element_t *array_h, element_t* g_pow_a, element_t* h_pow_d_div_a, element_t* h_pow_1_div_a, element_t* h_pow_b_div_a,
            element_t *_a1, element_t *_a2, element_t *_b1, element_t *_b2, element_t *_a, element_t *_b,
                element_t *g_pow_d1, element_t *g_pow_d2, element_t *g_pow_d3, element_t *array_z);

    void KG(element_t *_x, element_t *ID, element_t *SID);

    void H(element_t *m, element_t *res);

    void Hash(element_t *ID, element_t *L, element_t *m, element_t *r1, element_t *r2, element_t *h);

    bool Check(element_t *h, element_t *L,element_t *m, element_t *r1);

    void Forge(element_t *SID, element_t *ID, element_t *L, element_t *h, element_t *m, element_t *r1, element_t *r2, element_t *m_p, 
                                element_t *r1_p, element_t *r2_p);

    bool Verify(element_t *h, element_t *L,element_t *m_p, element_t *r1_p);


    ~PCHBA_TLL_2020();
};


#endif //PCHBA_TLL_2020_H