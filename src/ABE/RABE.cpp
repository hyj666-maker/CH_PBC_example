#include <ABE/RABE.h>

RABE::RABE(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn){
    this->G = _G;
    this->H = _H;
    this->GT = _GT;
    this->Zn = _Zn;

    element_init_same_as(this->a1, *this->Zn);
    element_init_same_as(this->a2, *this->Zn);
    element_init_same_as(this->b1, *this->Zn);
    element_init_same_as(this->b2, *this->Zn);

    element_init_same_as(this->d1, *this->Zn);
    element_init_same_as(this->d2, *this->Zn);
    element_init_same_as(this->d3, *this->Zn);

}

RABE::~RABE(){
    element_clear(this->a1);
    element_clear(this->a2);
    element_clear(this->b1);
    element_clear(this->b2);

    element_clear(this->d1);
    element_clear(this->d2);
    element_clear(this->d3);
}

/**
 * input: n
 * output: mpk, msk, st, rl
 */
void RABE::Setup(){
    element_random(this->a1);
    element_random(this->a2);
    element_random(this->b1);
    element_random(this->b2);
    element_random(this->d1);
    element_random(this->d2);
    element_random(this->d3);
}