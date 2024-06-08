#ifndef IMPORT_ELEMENTLIST
#define IMPORT_ELEMENTLIST
#include "base/ElementList.h"
#endif //IMPORT_ELEMENTLIST

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC


#ifndef IB_CH_KEF_H
#define IB_CH_KEF_H

class IB_CH_KEF {
    protected:
    element_t *G1, *G2, *Zn, *GT, P, P_pub, x, tmp_G1, tmp_G1_2, tmp_G2, tmp_Zn, tmp_GT;
    int rev_G1G2;

    void H(element_t *m, element_t *res);

    void H_G1(element_t *m, element_t *res);

    void base_hash(element_t *ID, element_t *L, element_t *H, element_t *m, element_t *r_1, element_t *r_2);

    public:
    IB_CH_KEF(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2);

    int public_key_size() {
        return CountSize(this->P) + CountSize(this->P_pub);
    };

    void Setup();

    void Extract(element_t *ID, element_t *S_ID);

    void Hash(element_t *ID, element_t *L, element_t *H, element_t *m, element_t *r_1, element_t *r_2);

    void Forge(element_t *S_ID, element_t *L, element_t *m, element_t *m_p, element_t *r_1, element_t *r_2, element_t *r_1_p, element_t *r_2_p);

    bool Verify(element_t *ID, element_t *L, element_t *H, element_t *m, element_t *r_1, element_t *r_2, element_t *S_ID);

    ~IB_CH_KEF();
};


#endif //IB_CH_KEF_H