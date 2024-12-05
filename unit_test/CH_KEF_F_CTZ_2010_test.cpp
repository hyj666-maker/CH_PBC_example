#include <scheme/CH_KEF_F_CTZ_2010.h>

CH_KEF_F_CTZ_2010::pk pk;
CH_KEF_F_CTZ_2010::sk sk;

mpz_t m,m_p,m_pp;
mpz_t r,r_p,r_pp;
mpz_t b,b_p,b_pp;
mpz_t h;
mpz_t L;


void test_init(){
    mpz_inits(m, m_p, m_pp, r, r_p, r_pp, b, b_p, b_pp, h, L, NULL);
    pk.Init();
    sk.Init();
}

void test_clear(){
    mpz_clears(m, m_p, m_pp, r, r_p, r_pp, b, b_p, b_pp, h, L, NULL);
}

int main(){
    printf("Test CH_KEF_F_CTZ_2010\n");
    test_init();

    CH_KEF_F_CTZ_2010 *test = new CH_KEF_F_CTZ_2010();

    // k = 1024
    int k = 1024;
    test->GenKey(k, &pk, &sk);

    // random L
    GenerateRandomWithLength(L, 1024);
    gmp_printf("L = %Zd\n", L);
    // m ∈ {0,1}^fk
    GenerateRandomWithLength(m, test->getfk());
    gmp_printf("m = %Zd\n", m);
    test->Hash(&pk, &L, &m, &r, &b, &h);
    gmp_printf("h = %Zd\n", h);

    GenerateRandomWithLength(m_p, test->getfk());
    gmp_printf("m_p = %Zd\n", m_p);
    test->Uforge(&pk, &sk, &L, &m, &r, &b, &m_p, &r_p, &b_p);
    gmp_printf("r_p = %Zd\n", r_p);
    gmp_printf("b_p = %Zd\n", b_p);
    
    GenerateRandomWithLength(m_pp, test->getfk());
    gmp_printf("m_pp = %Zd\n", m_pp);
    test->Iforge(&pk, &L, &m, &r, &b, &h, &m_p, &r_p, &b_p, &m_pp, &r_pp, &b_pp);
    gmp_printf("r_pp = %Zd\n", r_pp);
    gmp_printf("b_pp = %Zd\n", b_pp);

    if(test->Verify(&pk, &L, &m_p, &r_p, &b_p, &h)){
        printf("Uforge Verify success\n");
    }
    else{
        printf("Uforge Verify failed\n");
    }
    if (test->Verify(&pk, &L, &m_pp, &r_pp, &b_pp, &h)){
        printf("Iforge Verify success\n");
    }
    else{
        printf("Iforge Verify failed\n");
    }

    test_clear();
}