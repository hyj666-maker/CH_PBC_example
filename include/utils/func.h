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

void Hm_1(element_t &m, element_t &res);

void Hgsm_1(element_t &gs, element_t &m, element_t &res);

void Hm_2(element_t &y, element_t &h, element_t &m,element_t &u1,element_t &u2, element_t &res);

void Hm_3(element_t &y, element_t &h1, element_t &h2, element_t &m,
            element_t &u11,element_t &u12, element_t &u2, 
            element_t &res);

void Hm_4(element_t &m1, element_t &m2, element_t &m3, element_t &res);

void PrintElement(std::string element_name, element_t &element);
void PrintElementsize(std::string element_name, element_t &element);
void PrintElementAndSize(std::string element_name, element_t &element);

int CountSize(element_t &t);
#endif //UTIL_FUNC_H