#ifndef RABE_H
#define RABE_H

#include <pbc/pbc.h>

class RABE{
    protected:
        element_t *G, *H, *GT, *Zn;

        element_t a1,a2,b1,b2;
        element_t d1,d2,d3;
    
    public:
        struct mpk
        {
            element_t h,H1,H2,T1,T2,H;

            mpk(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn){
                element_init_same_as(h, *_H);
                element_init_same_as(H1, *_H);
                element_init_same_as(H2, *_H);
                element_init_same_as(T1, *_GT);
                element_init_same_as(T2, *_GT);
                element_init_same_as(H, *_G);
            }
            ~mpk(){
                element_clear(h);
                element_clear(H1);
                element_clear(H2);
                element_clear(T1);
                element_clear(T2);
                element_clear(H);
            }
        };

        struct msk
        {
            element_t g,h,a1,a2,b1,b2,g_pow_d1,g_pow_d2,g_pow_d3;

            msk(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn){
                element_init_same_as(g, *_G);
                element_init_same_as(h, *_H);
                element_init_same_as(a1, *_Zn);
                element_init_same_as(a2, *_Zn);
                element_init_same_as(b1, *_Zn);
                element_init_same_as(b2, *_Zn);
                element_init_same_as(g_pow_d1, *_G);
                element_init_same_as(g_pow_d2, *_G);
                element_init_same_as(g_pow_d3, *_G);
            }
            ~msk(){
                element_clear(g);
                element_clear(h);
                element_clear(a1);
                element_clear(a2);
                element_clear(b1);
                element_clear(b2);
                element_clear(g_pow_d1);
                element_clear(g_pow_d2);
                element_clear(g_pow_d3);
            }
        };
        
        

        RABE(element_t *_G, element_t *_H, element_t *_GT, element_t *_Zn);

        ~RABE();

        void Setup();
};

#endif  // RABE_H