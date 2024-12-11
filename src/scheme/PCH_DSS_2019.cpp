#include <scheme/PCH_DSS_2019.h>

PCH_DSS_2019::PCH_DSS_2019(mpz_t *_n,mpz_t *_e, mpz_t *_d, element_t *_G, element_t *_H, element_t *_Zn, element_t *_GT) 
    : rsa(_n, _e, _d), cp_abe(_G, _H, _GT, _Zn){
    
    this->G = _G;
    this->H = _H;
    this->GT = _GT;
    this->Zn = _Zn;

    element_init_same_as(this->tmp_G, *this->G);
    element_init_same_as(this->tmp_G_2, *this->G);
    element_init_same_as(this->tmp_G_3, *this->G);
    element_init_same_as(this->tmp_G_4, *this->G);
    element_init_same_as(this->tmp_H, *this->H);
    element_init_same_as(this->tmp_H_2, *this->H);
    element_init_same_as(this->tmp_H_3, *this->H);
    element_init_same_as(this->tmp_GT, *this->GT);
    element_init_same_as(this->tmp_GT_2, *this->GT);
    element_init_same_as(this->tmp_GT_3, *this->GT);
    element_init_same_as(this->tmp_Zn, *this->Zn);
    element_init_same_as(this->tmp_Zn_2, *this->Zn);
    element_init_same_as(this->tmp_Zn_3, *this->Zn);

    element_init_same_as(this->u1, *this->Zn);
    element_init_same_as(this->u2, *this->Zn);
    element_init_same_as(this->K, *this->GT);
   
}

/**
 * input : k
 * output: skPCH, pkPCH
 */
void PCH_DSS_2019::PG(int k, skPCH *skPCH, pkPCH *pkPCH) {
    this->k = k;
    // e > N
    this->rsa.rsa_generate_keys_2(k, 1);
    // set d1
    mpz_set(skPCH->skCHET.d1, *(this->rsa.getD()));
    // set N1,e
    mpz_set(pkPCH->pkCHET.N1, *(this->rsa.getN()));
    mpz_set(pkPCH->pkCHET.e, *(this->rsa.getE()));

    this->cp_abe.Setup(&skPCH->mskABE, &pkPCH->mpkABE);
}

/**
 * input : skPCH, pkPCH, attr_list
 * output: sksPCH
 */
void PCH_DSS_2019::KG(skPCH *skPCH, pkPCH *pkPCH, std::vector<std::string> *attr_list, sksPCH *sksPCH) {
    this->cp_abe.KeyGen(&skPCH->mskABE, &pkPCH->mpkABE, attr_list, &sksPCH->sksABE);
    mpz_set(sksPCH->skCHET.d1, skPCH->skCHET.d1);
}

void PCH_DSS_2019::H1(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res){
    Hgsm_n_2(*m, *N1, *N2, *n, *res);
}
void PCH_DSS_2019::H2(mpz_t *m, mpz_t *N1, mpz_t *N2, mpz_t * n, mpz_t *res){
    Hgsm_n_2(*m, *N1, *N2, *n, *res);
}
/**
 * (u1,u2)<-H4((r,A))
 */
void PCH_DSS_2019::H4(mpz_t *r, string A, element_t *u1, element_t *u2){
    // r -> string
    string r_str = mpz_get_str(NULL, 10, *r);
    // str -> element_t
    element_from_hash(this->tmp_Zn, (unsigned char *)r_str.c_str(), r_str.length());
    element_from_hash(this->tmp_Zn_2, (unsigned char *)A.c_str(), A.length());
    Hm_1(this->tmp_Zn, *u1);
    Hm_1(this->tmp_Zn_2, *u2);
}

/**
 * K ← encode(k, r)
 * input: k,r
 * output: K
 */
void PCH_DSS_2019::encode(element_t *K, mpz_t *k, mpz_t * r) {
    // TODO: 优化 encode 和 decode 函数
    PrintElement("encode:K", *K);
    // size_t k_len = (mpz_sizeinbase(*k, 2) + 7) / 8;
    // size_t r_len = (mpz_sizeinbase(*r, 2) + 7) / 8;
    // printf("encode: k_len: %zu\n", k_len);
    // printf("encode: r_len: %zu\n", r_len);
    // PrintMpz("encode: k", *k);
    // PrintMpz("encode: r", *r);

    // unsigned char *buffer = (unsigned char *)malloc(128);
    // memset(buffer, 0, 128);

    // size_t k_len_actual = 0, r_len_actual = 0;
    // mpz_export(buffer, &k_len_actual, 1, 1, 0, 0, *k);
    // mpz_export(buffer + k_len, &r_len_actual, 1, 1, 0, 0, *r);
    // printf("encode: k_len_actual: %zu\n", k_len_actual);
    // printf("encode: r_len_actual: %zu\n", r_len_actual);

    // element_from_bytes(*K, buffer);
    
    // // print buffer
    // for (size_t i = 0; i < 128; i++) {
    //     printf("%02x", buffer[i]);
    // }
    // printf("\n");

    // free(buffer);

    // 合并 k 和 r
    mpz_t combined;
    mpz_init(combined);

    // 获取 k 的位宽
    size_t k_bits = 256;
    mpz_mul_2exp(combined, *r, k_bits); // r 左移 k 的位数
    mpz_add(combined, combined, *r);    // 合并 k
    PrintMpz("encode: combined", combined);

    // 将 combined 映射到 K
    element_set_mpz(*K, combined);
    // // 获取 mpz_t 的字节长度
    // size_t byte_size = (mpz_sizeinbase(combined, 2) + 7) / 8;
    // // 分配字节数组
    // unsigned char *buffer = (unsigned char *)malloc(byte_size);
    // // 导出 mpz_t 到字节数组
    // mpz_export(buffer, NULL, 1, 1, 0, 0, combined);
    // // 将字节数组导入到 element_t
    // element_from_bytes(*K, buffer);
    // // 释放缓冲区
    // free(buffer);

    mpz_clear(combined);
}

/**
 * (k, r) ← decode(K)
 * input: K, k_len, r_len
 * output: k, r
 */
void PCH_DSS_2019::decode(mpz_t *k, mpz_t *r, element_t *K, size_t k_len, size_t r_len) {
    PrintElement("decode:K", *K);
    // printf("decode: k_len: %zu\n", k_len);
    // printf("decode: r_len: %zu\n", r_len);
    // size_t K_len = element_length_in_bytes(*K);
    // printf("decode: K_len: %zu\n", K_len);
    // unsigned char *buffer = (unsigned char *)malloc(128);
    // memset(buffer, 0, 128);

    // element_to_bytes(buffer, *K);
    
    // // print buffer
    // for (size_t i = 0; i < 128; i++) {
    //     printf("%02x", buffer[i]);
    // }
    // printf("\n");

    // mpz_import(*k, k_len, 1, 1, 0, 0, buffer);         
    // mpz_import(*r, r_len, 1, 1, 0, 0, buffer + k_len); 

    // PrintMpz("decode: k", *k);
    // PrintMpz("decode: r", *r);
    // free(buffer);

    mpz_t combined;
    mpz_init(combined);

    // 将 K 转换回 combined
    element_to_mpz(combined, *K);
    PrintMpz("decode: combined", combined);
    
    size_t k_bits = 256;

    // 提取 k 和 r
    mpz_fdiv_q_2exp(*r, combined, k_bits); // 提取高位部分为 r
    mpz_fdiv_r_2exp(*k, combined, k_bits); // 提取低位部分为 k

    mpz_clear(combined);
}

/**
 * input : pkPCH, m, policy_str
 * output: h, r
 */
void PCH_DSS_2019::Hash(pkPCH *pkPCH, mpz_t *m, string policy_str, h *h,r *r) {
    mpz_t tmp1, tmp2, rr, kk;
    mpz_inits(tmp1, tmp2, rr, kk, NULL);
    this->rsa.rsa_generate_keys_with_e(this->k, &pkPCH->pkCHET.e);

    // h.N2
    mpz_set(h->N2, *this->rsa.getN());
    
    // r1 ∈ ZN1*
    GenerateRandomInZnStar(r->r1, pkPCH->pkCHET.N1);
    // r2 ∈ ZN2*
    GenerateRandomInZnStar(r->r2, *this->rsa.getN());

    // h1 = H1(m,N1,N2)* r1^e mod N1
    H1(m, &pkPCH->pkCHET.N1, this->rsa.getN(), &pkPCH->pkCHET.N1, &tmp1);
    // r1^e mod N1
    mpz_powm(tmp2, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
    mpz_mul(h->h1, tmp1, tmp2);
    mpz_mod(h->h1, h->h1, pkPCH->pkCHET.N1);
    // h2 = H2(m,N1,N2)* r2^e mod N2
    H2(m, &pkPCH->pkCHET.N1, this->rsa.getN(), this->rsa.getN(), &tmp1);
    // r2^e mod N2
    mpz_powm(tmp2, r->r2, pkPCH->pkCHET.e, *this->rsa.getN());
    mpz_mul(h->h2, tmp1, tmp2);
    mpz_mod(h->h2, h->h2, *this->rsa.getN());

    // rr ∈ {0,1}^k
    GenerateRandomWithLength(rr, this->k);
    // kk = kGenSE(1^k), let k = 256
    this->aes.KGen(256, &kk);
    // (u1,u2)<-H4((r,A))
    H4(&rr, policy_str, &u1, &u2);

    // K ← encode(k, r)
    encode(&K, &kk, &rr);

    this->cp_abe.Encrypt(&pkPCH->mpkABE, &K, policy_str, &u1, &u2, &h->ct);

    // ct_
    this->aes.Enc(&kk, this->rsa.getD(), &h->ct_);

    mpz_clears(tmp1, tmp2, rr, kk, NULL);
}

/**
 * input : pkPCH, m, h, r
 * output: bool
 */
bool PCH_DSS_2019::Check(pkPCH *pkPCH, mpz_t *m, h *h, r *r) {
    mpz_t tmp1, tmp2, tmp3;
    mpz_inits(tmp1, tmp2, tmp3, NULL);
    // h1 = H1(m,N1,N2)* r1^e mod N1
    H1(m, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &tmp1);
    // r1^e mod N1
    mpz_powm(tmp2, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(tmp3, tmp3, pkPCH->pkCHET.N1);
    if(mpz_cmp(tmp3, h->h1) != 0){
        mpz_clears(tmp1, tmp2,tmp3, NULL);
        return false;
    }
    // h2 = H2(m,N1,N2)* r2^e mod N2
    H2(m, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &tmp1);
    // r2^e mod N2
    mpz_powm(tmp2, r->r2, pkPCH->pkCHET.e, h->N2);
    mpz_mul(tmp3, tmp1, tmp2);
    mpz_mod(tmp3, tmp3, h->N2);
    if(mpz_cmp(tmp3, h->h2) != 0){
        mpz_clears(tmp1, tmp2,tmp3, NULL);
        return false;
    }
    mpz_clears(tmp1, tmp2, tmp3, NULL);
    return true;
}

/**
 * input : pkPCH, sksPCH, m, m', h, r
 * output: r'
 */
void PCH_DSS_2019::Forge(pkPCH * pkPCH, sksPCH *sksPCH, mpz_t *m, mpz_t *m_p, h *h, PCH_DSS_2019::r *r, PCH_DSS_2019::r *r_p) {
    // assume that S satisfies the policy
    // TODO need judge

    mpz_t kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2;
    mpz_inits(kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2,NULL);

    cp_abe.Decrypt(&pkPCH->mpkABE, &h->ct, &sksPCH->sksABE, &this->K);
    decode(&kk, &rr, &this->K, 256/8, (this->k)/8);

    // DecSE(kk, ct_) -> d2
    this->aes.Dec(&kk, &h->ct_, &d2);

    // x1 = H1(m, N1, N2)
    H1(m, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &x1);
    // x1' = H1(m', N1, N2)
    H1(m_p, &pkPCH->pkCHET.N1, &h->N2, &pkPCH->pkCHET.N1, &x1_p);
    // y1 = x1 r1^e mod N1
    mpz_powm(y1, r->r1, pkPCH->pkCHET.e, pkPCH->pkCHET.N1);
    mpz_mul(y1, x1, y1);
    mpz_mod(y1, y1, pkPCH->pkCHET.N1);
    // x2 = H2(m, N1, N2)
    H2(m, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &x2);
    // x2' = H2(m', N1, N2)
    H2(m_p, &pkPCH->pkCHET.N1, &h->N2, &h->N2, &x2_p);
    // y2 = x2 r2^e mod N2
    mpz_powm(y2, r->r2, pkPCH->pkCHET.e, h->N2);
    mpz_mul(y2, x2, y2);
    mpz_mod(y2, y2, h->N2);
    // r1' = (y1(x1'^(-1)))^d1 mod N1
    mpz_invert(x1_p, x1_p, pkPCH->pkCHET.N1);
    mpz_mul(r_p->r1, y1, x1_p);
    mpz_mod(r_p->r1, r_p->r1, pkPCH->pkCHET.N1);
    mpz_powm(r_p->r1, r_p->r1, sksPCH->skCHET.d1, pkPCH->pkCHET.N1);
    // r2' = (y2(x2'^(-1)))^d2 mod N2
    mpz_invert(x2_p, x2_p, h->N2);
    mpz_mul(r_p->r2, y2, x2_p);
    mpz_mod(r_p->r2, r_p->r2, h->N2);
    mpz_powm(r_p->r2, r_p->r2, d2, h->N2);
  

    mpz_clears(kk,rr,d2,x1,x1_p,y1,x2,x2_p,y2,NULL);
}

/**
 * input : pkPCH, m', h, r'
 * output: bool
 */
bool PCH_DSS_2019::Verify(pkPCH *pkPCH, mpz_t *m_p, h *h, r *r_p) {
    return this->Check(pkPCH, m_p, h, r_p);
}


PCH_DSS_2019::~PCH_DSS_2019() {
   
}