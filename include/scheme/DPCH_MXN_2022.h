#ifndef DPCH_MXN_2022_H
#define DPCH_MXN_2022_H

#include <stdexcept>  // 包含 std::invalid_argument
#include "utils/func.h"
#include <RSA/RSA.h>
#include <ABE/MA_ABE.h>
#include <SE/AES.h>
#include <signature/BLS.h>


class DPCH_MXN_2022 {
    protected:
        MyRSA rsa;
        MA_ABE ma_abe;
        AES aes;
        BLS bls;

        mpz_t *n,e,d;
        element_t *G1, *G2, *GT, *Zn;
        element_t tmp_G,tmp_G_2,tmp_G_3,tmp_G_4,tmp_H,tmp_H_2,tmp_H_3,tmp_GT,tmp_GT_2,tmp_GT_3,tmp_Zn,tmp_Zn_2,tmp_Zn_3;
    

    public:
        struct pp{
            element_t g;
            MA_ABE::gpk gpkMA_ABE;
            BLS::pp ppBLS;
            void Init(element_t *_G){
                element_init_same_as(g, *_G);
                gpkMA_ABE.Init(_G);
                ppBLS.Init(_G);
            }
            ~pp(){
                element_clear(g);
            }
        };
        struct pkCHET{
            mpz_t n0,e0;
            pkCHET(){
                mpz_inits(n0,e0,NULL);
            }
            ~pkCHET(){
                mpz_clears(n0,e0,NULL);
            }
        };
        struct skCHET{
            mpz_t d0;
            skCHET(){
                mpz_init(d0);
            }
            ~skCHET(){
                mpz_clear(d0);
            }
        };
        struct pkDPCH{
            DPCH_MXN_2022::pkCHET pkCHET;
            BLS::pk pkBLS;
            void Init(element_t *_G){
                pkBLS.Init(_G);
            }
        };
        struct skDPCH{
            DPCH_MXN_2022::skCHET skCHET;
            BLS::sk skBLS;
            void Init(element_t *_Zn){
                skBLS.Init(_Zn);
            }
        };
        struct skGid{
            mpz_t d0;
            skGid(){
                mpz_init(d0);
            }
            ~skGid(){
                mpz_clear(d0);
            }
        };
        struct sigmaGid{
            element_t signature;
            void Init(element_t *_H){
                element_init_same_as(signature, *_H);
            }
            ~sigmaGid(){
                element_clear(signature);
            }
        };
        struct pkTheta{
            MA_ABE::pkTheta pk;
            void Init(element_t *_G, element_t *_GT){
                pk.Init(_G, _GT);
            }
        };
        struct skTheta{
            MA_ABE::skTheta sk;
            void Init(element_t *_Zn){
                sk.Init(_Zn);
            }
        };
        struct skGidA{
            MA_ABE::skgidA sk;
            void Init(element_t *_G){
                sk.Init(_G);
            }
        };
        
        


        DPCH_MXN_2022(mpz_t *_n,mpz_t *_e, mpz_t *_d, element_t *_G, element_t *_H, element_t *_Zn, element_t *_GT);

        void SetUp(int k, pp *pp, pkDPCH *pkDPCH, skDPCH *skDPCH);

        void ModSetUp(skDPCH *skDPCH, string gid, skGid *skGid, sigmaGid *sigmaGid);

        void AuthSetUp(pp *pp, string A, pkTheta *pkTheta, skTheta *skTheta);

        void ModKeyGen(pp *pp, pkDPCH *pkDPCH, string gid, sigmaGid *sigmaGid, skTheta *skTheta, string A, skGidA *skGidA);

        // void H1(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res);
        // void H2(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res);
        // void H4(mpz_t *r, string A, element_t *u1, element_t *u2);

        void Hash();

        // bool Check(pkPCH *pkPCH, mpz_t *m, h *h, r *r);

        // void Forge(pkPCH * pkPCH, sksPCH *sksPCH, mpz_t *m, mpz_t *m_p, h *h, DPCH_MXN_2022::r *r, DPCH_MXN_2022::r *r_p);

        // bool Verify(pkPCH *pkPCH, mpz_t *m_p, h *h, r *r_p);


        ~DPCH_MXN_2022();
};


#endif //DPCH_MXN_2022_H