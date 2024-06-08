#ifndef IMPORT_ELEMENTLIST
#define IMPORT_ELEMENTLIST
#include "base/ElementList.h"
#endif //IMPORT_ELEMENTLIST

#ifndef IMPORT_UTIL_FUNC
#define IMPORT_UTIL_FUNC
#include "utils/func.h"
#endif //IMPORT_UTIL_FUNC

#ifndef IB_CH_nonRO_H
#define IB_CH_nonRO_H

class IB_CH_nonRO {
    private:
    element_t *G1, *G2, *Zn, *GT, msk, tmp_G1, tmp_G2, tmp_G2_2, tmp_Zn, tmp_GT, tmp_GT_2, tmp_GT_3, g, g_1, g_2;
    ElementList *u = NULL;
    int rev_G1G2;

    void base_hash(ElementList *I, element_t *h, element_t *m, element_t *r_1, element_t *r_2);
    
    void get_u0uiIi(ElementList *I, element_t *res);

    public:
    int public_key_size() {
        return CountSize(this->g_1) + CountSize(this->g_2) + CountSize(this->g) + this->u->ByteSize();
    };

    IB_CH_nonRO(element_t *_G1, element_t *_G2, element_t *_Zn, element_t *_GT, int _rev_G1G2);

    void Setup(int n);

    void Keygen(element_t *tk_1, element_t *tk_2, ElementList *I);

    void Hash(ElementList *I, element_t *h, element_t *m, element_t *r_1, element_t *r_2);

    void Collision(
        element_t *tk_1, element_t *tk_2, element_t *h, element_t *m, element_t *m_p, 
        element_t *r_1, element_t *r_2, element_t *r_1_p, element_t *r_2_p
    );
    
    bool Verify(ElementList *I, element_t *h, element_t *m, element_t *r_1, element_t *r_2);

    ~IB_CH_nonRO();
};

#endif //IB_CH_nonRO_H