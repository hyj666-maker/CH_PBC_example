#include <scheme/DPCH_MXN_2022.h>

DPCH_MXN_2022::DPCH_MXN_2022(mpz_t *_n,mpz_t *_e, mpz_t *_d, element_t *_G, element_t *_H, element_t *_Zn, element_t *_GT) 
    : rsa(_n, _e, _d), ma_abe(_G, _H, _GT, _Zn), aes(), bls(_G, _H, _GT, _Zn) {
    this->G1 = _G;
    this->G2 = _H;
    this->GT = _GT;
    this->Zn = _Zn;
    element_init_same_as(this->tmp_G, *this->G1);
    element_init_same_as(this->tmp_G_2, *this->G1);
    element_init_same_as(this->tmp_G_3, *this->G1);
    element_init_same_as(this->tmp_G_4, *this->G1);
    element_init_same_as(this->tmp_H, *this->G2);
    element_init_same_as(this->tmp_H_2, *this->G2);
    element_init_same_as(this->tmp_H_3, *this->G2);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_GT_3, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->tmp_Zn_2, *this->Zn);
    element_init_same_as(this->tmp_Zn_3, *this->Zn);
   
}

/**
 * @param k: key size
 * @param pp: public parameters
 * @param pkDPCH: public key of DPCH
 * @param skDPCH: secret key of DPCH
 */
void DPCH_MXN_2022::SetUp(int k, pp *pp, pkDPCH *pkDPCH, skDPCH *skDPCH) {
    element_random(pp->g);

    rsa.rsa_generate_keys(k);

    ma_abe.GlobalSetup(&pp->gpkMA_ABE, &pp->g);

    bls.Setup(&pp->ppBLS, &pp->g);
    bls.KeyGen(&pp->ppBLS, &pkDPCH->pkBLS, &skDPCH->skBLS);
}

/**
 * @param skDPCH: secret key of DPCH
 * @param gid: global id
 * @param skGid: secret key of gid
 * @param sigmaGid: signature of gid
 */
void DPCH_MXN_2022::ModSetUp(skDPCH *skDPCH, string gid, skGid *skGid, sigmaGid *sigmaGid){
    mpz_set(skGid->d0, skDPCH->skCHET.d0);
    bls.Sign(&skDPCH->skBLS, gid, &sigmaGid->signature);
}

/**
 * @param pkTheta: public key of Theta
 * @param skTheta: secret key of Theta
 */
void DPCH_MXN_2022::AuthSetUp(pp *pp, string A, pkTheta *pkTheta, skTheta *skTheta){
    ma_abe.AuthSetup(&pp->gpkMA_ABE, A, &pkTheta->pk, &skTheta->sk);
}

/**
 * @param pp: public parameters
 * @param pkDPCH: public key of DPCH
 * @param gid: global id
 * @param sigmaGid: signature of gid
 * @param skTheta: secret key of Theta
 * @param A: attribute
 * @param skGidA: secret key of gid and attribute
 */
void DPCH_MXN_2022::ModKeyGen(pp *pp, pkDPCH *pkDPCH, string gid, sigmaGid *sigmaGid, skTheta *skTheta, string A, skGidA *skGidA){
    if(!(bls.Verify(&pp->ppBLS, &pkDPCH->pkBLS, gid, &sigmaGid->signature))){
            throw std::runtime_error("ModKeyGen(): Signature Verify failed!");
    }

    ma_abe.KeyGen(&pp->gpkMA_ABE, &skTheta->sk, gid, A, &skGidA->sk);
}


// void DPCH_MXN_2022::H1(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res){
//     Hgsm_n_2(*m, *N1, *N2, *n, *res);
// }
// void DPCH_MXN_2022::H2(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res){
//     Hgsm_n_2(*m, *N1, *N2, *n, *res);
// }
// /**
//  * (u1,u2)<-H4((r,A))
//  */
// void DPCH_MXN_2022::H4(mpz_t *r, string A, element_t *u1, element_t *u2){
//     // r -> string
//     string r_str = mpz_get_str(NULL, 10, *r);
//     // str -> element_t
//     element_from_hash(this->tmp_Zn, (unsigned char *)r_str.c_str(), r_str.length());
//     element_from_hash(this->tmp_Zn_2, (unsigned char *)A.c_str(), A.length());
//     Hm_1(this->tmp_Zn, *u1);
//     Hm_1(this->tmp_Zn_2, *u2);
// }


// /**
//  * input : pkPCH, m, policy_str
//  * output: h, r
//  */
// void DPCH_MXN_2022::Hash(pkPCH *pkPCH, mpz_t *m, string policy_str, h *h,r *r) {
//     mpz_t tmp1, tmp2, rr, kk;
//     mpz_inits(tmp1, tmp2, rr, kk, NULL);
//     this->rsa.rsa_generate_keys_with_e(this->k, &pkPCH->pkCHET.e);

//     // h.N2
//     mpz_set(h->N2, *this->rsa.getN());
    
//     // r1 ∈ ZN1*
//     GenerateRandomInZnStar(r->r1, pkPCH->pkCHET.N1);
//     // r2 ∈ ZN2*
//     GenerateRandomInZnStar(r->r2, *this->rsa.getN());

//     // h1 = H1(m,N1,N2)* r1^e mod N1
//     H1(m, &pkPCH->pkCHET.N1, this->rsa.getN(), &pkPCH->pkCHET.N1, &tmp1);
//     // r1^e mod N1
//     mpz_powm(tmp2, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
//     mpz_mul(h->h1, tmp1, tmp2);
//     mpz_mod(h->h1, h->h1, pkPCH->pkCHET.N1);
//     // h2 = H2(m,N1,N2)* r2^e mod N2
//     H2(m, &pkPCH->pkCHET.N1, this->rsa.getN(), this->rsa.getN(), &tmp1);
//     // r2^e mod N2
//     mpz_powm(tmp2, r->r2, pkPCH->pkCHET.e, *this->rsa.getN());
//     mpz_mul(h->h2, tmp1, tmp2);
//     mpz_mod(h->h2, h->h2, *this->rsa.getN());

//     this->aes.KGen(256, &this->K);
//     // (u1,u2)<-H4((r,A))
//     H4(&rr, policy_str, &u1, &u2);


//     this->cp_abe.Encrypt(&pkPCH->mpkABE, &this->K, policy_str, &u1, &u2, &h->ct);

//     // ct_
//     this->aes.Enc(&this->K, this->rsa.getD(), &h->ct_);

//     mpz_clears(tmp1, tmp2, rr, kk, NULL);
// }

// /**
//  * input : pkPCH, m, h, r
//  * output: bool
//  */
// bool DPCH_MXN_2022::Check(pkPCH *pkPCH, mpz_t *m, h *h, r *r) {
//     mpz_t tmp1, tmp2, tmp3;
//     mpz_inits(tmp1, tmp2, tmp3, NULL);
//     // h1 = H1(m,N1,N2)* r1^e mod N1
//     H1(m, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &tmp1);
//     // r1^e mod N1
//     mpz_powm(tmp2, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
//     mpz_mul(tmp3, tmp1, tmp2);
//     mpz_mod(tmp3, tmp3, pkPCH->pkCHET.N1);
//     if(mpz_cmp(tmp3, h->h1) != 0){
//         mpz_clears(tmp1, tmp2,tmp3, NULL);
//         return false;
//     }
//     // h2 = H2(m,N1,N2)* r2^e mod N2
//     H2(m, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &tmp1);
//     // r2^e mod N2
//     mpz_powm(tmp2, r->r2, pkPCH->pkCHET.e, h->N2);
//     mpz_mul(tmp3, tmp1, tmp2);
//     mpz_mod(tmp3, tmp3, h->N2);
//     if(mpz_cmp(tmp3, h->h2) != 0){
//         mpz_clears(tmp1, tmp2,tmp3, NULL);
//         return false;
//     }
//     mpz_clears(tmp1, tmp2, tmp3, NULL);
//     return true;
// }

// /**
//  * input : pkPCH, sksPCH, m, m', h, r
//  * output: r'
//  */
// void DPCH_MXN_2022::Forge(pkPCH * pkPCH, sksPCH *sksPCH, mpz_t *m, mpz_t *m_p, h *h, DPCH_MXN_2022::r *r, DPCH_MXN_2022::r *r_p) {
//     mpz_t kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2;
//     mpz_inits(kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2,NULL);

//     cp_abe.Decrypt(&pkPCH->mpkABE, &h->ct, &sksPCH->sksABE, &this->K);

//     // DecSE(K, ct_) -> d2
//     this->aes.Dec(&this->K, &h->ct_, &d2);

//     // x1 = H1(m, N1, N2)
//     H1(m, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &x1);
//     // x1' = H1(m', N1, N2)
//     H1(m_p, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &x1_p);
//     // y1 = x1 r1^e mod N1
//     mpz_powm(y1, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
//     mpz_mul(y1, x1, y1);
//     mpz_mod(y1, y1, pkPCH->pkCHET.N1);
//     // x2 = H2(m, N1, N2)
//     H2(m, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &x2);
//     // x2' = H2(m', N1, N2)
//     H2(m_p, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &x2_p);
//     // y2 = x2 r2^e mod N2
//     mpz_powm(y2, r->r2, pkPCH->pkCHET.e, h->N2);
//     mpz_mul(y2, x2, y2);
//     mpz_mod(y2, y2, h->N2);
//     // r1' = (y1(x1'^(-1)))^d1 mod N1
//     mpz_invert(x1_p, x1_p, pkPCH->pkCHET.N1);
//     mpz_mul(r_p->r1, y1, x1_p);
//     mpz_mod(r_p->r1, r_p->r1, pkPCH->pkCHET.N1);
//     mpz_powm(r_p->r1, r_p->r1, sksPCH->skCHET.d1, pkPCH->pkCHET.N1);
//     // r2' = (y2(x2'^(-1)))^d2 mod N2
//     mpz_invert(x2_p, x2_p, h->N2);
//     mpz_mul(r_p->r2, y2, x2_p);
//     mpz_mod(r_p->r2, r_p->r2, h->N2);
//     mpz_powm(r_p->r2, r_p->r2, d2, h->N2);
  

//     mpz_clears(kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2,NULL);
// }

// /**
//  * input : pkPCH, m', h, r'
//  * output: bool
//  */
// bool DPCH_MXN_2022::Verify(pkPCH *pkPCH, mpz_t *m_p, h *h, r *r_p) {
//     return this->Check(pkPCH, m_p, h, r_p);
// }


DPCH_MXN_2022::~DPCH_MXN_2022() {
    element_clear(this->tmp_G);
    element_clear(this->tmp_G_2);
    element_clear(this->tmp_G_3);
    element_clear(this->tmp_G_4);
    element_clear(this->tmp_H);
    element_clear(this->tmp_H_2);
    element_clear(this->tmp_H_3);
    element_clear(this->tmp_GT);
    element_clear(this->tmp_GT_2);
    element_clear(this->tmp_GT_3);
    element_clear(this->tmp_Zn);
    element_clear(this->tmp_Zn_2);
    element_clear(this->tmp_Zn_3);
}