#ifndef CH_KEF_NoMH_AM_2004_H
#define CH_KEF_NoMH_AM_2004_H

#include <stdio.h>
#include <gmp.h>
#include <utils/func.h>

class CH_KEF_NoMH_AM_2004{
    private:
        mpz_t p,q;
        

    public:
        struct pk{
            mpz_t g,y;

            void Init(){
                mpz_init(g);
                mpz_init(y);
            }

            ~pk(){
                mpz_clear(g);
                mpz_clear(y);
            }
        };

        struct sk{
            mpz_t x;

            void Init(){
                mpz_init(x);
            }

            ~sk(){
                mpz_clear(x);
            }
        };

        CH_KEF_NoMH_AM_2004();

        ~CH_KEF_NoMH_AM_2004();

        void GenKey(int k, pk *pk, sk *sk);

        void Find_generator(mpz_t *g, mpz_t *p, mpz_t *q);


        void Hash(pk *pk, mpz_t *m, mpz_t *r, mpz_t *s, mpz_t *h);

        void H(mpz_t *m1, mpz_t *m2, mpz_t *res);

        void Forge(pk *pk,sk *sk, mpz_t *m_p, mpz_t *h, mpz_t *r_p, mpz_t *s_p);

     
        bool Check(pk *pk, mpz_t *m, mpz_t *r, mpz_t *s, mpz_t *h);

        bool Verify(pk *pk, mpz_t *m_p, mpz_t *r_p, mpz_t *s_p, mpz_t *h);

};

#endif  //CH_KEF_NoMH_AM_2004_H