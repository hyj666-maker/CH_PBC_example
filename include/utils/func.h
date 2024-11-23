#ifndef IMPORT_PBC
#define IMPORT_PBC
#include <pbc/pbc.h>
#endif //IMPORT_PBC

#ifndef IMPORT_STRING
#define IMPORT_STRING
#include <string>
#endif //IMPORT_STRING

#ifndef UTIL_FUNC_H
#define UTIL_FUNC_H
void Hm(element_t &m, element_t &res, element_t &tmp_Zp, element_t &g);

void Hgsm(element_t &gs, element_t &m, element_t &res, element_t &tmp_Zp, element_t &g);

void Hgsm_1(element_t &gs, element_t &m, element_t &res);

void Hm_2(element_t &y, element_t &h, element_t &m,element_t &u1,element_t &u2, element_t &res);

void Hm_3(element_t &y, element_t &h1, element_t &h2, element_t &m,
            element_t &u11,element_t &u12, element_t &u2, 
            element_t &res);

int CountSize(element_t &t);
#endif //UTIL_FUNC_H