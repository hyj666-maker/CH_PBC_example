#ifndef IMPORT_ELEMENTLIST
#define IMPORT_ELEMENTLIST
#include "base/ElementList.h"
#endif //IMPORT_ELEMENTLIST

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC


#ifndef CH_KEF_CZK_2004_H
#define CH_KEF_CZK_2004_H

#include <stdexcept>  // 包含 std::invalid_argument

class CH_KEF_CZK_2004 {
    protected:
    element_t *G1, *G2, *Zn, *GT;
    element_t tmp_G1, tmp_G1_2, tmp_G2, tmp_Zn,tmp_Zn_2, tmp_GT,tmp_GT_2,tmp_GT_3;

    element_t g;  // 生成元g
    element_t x;  // secret x ∈ Zp
    element_t a;


    public:
    CH_KEF_CZK_2004(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT);

    void PG();

    void KG(element_t *y);

    void Hash(element_t *I, element_t *m, element_t *y, element_t *h, element_t *r1, element_t *r2);

    void hash_with_r(element_t *I, element_t *m, element_t *r1, element_t *r2, element_t *h);

    void Forge(element_t *h, element_t *m, element_t *r1, element_t *r2, element_t *m_p, element_t *I, element_t *r1_p, element_t *r2_p);

    bool Verify(element_t *I, element_t *m_p, element_t *r1_p, element_t *r2_p, element_t *h);

    ~CH_KEF_CZK_2004();
};


#endif //CH_KEF_CZK_2004_H