#include <scheme/CH_KEF_NoMH_AM_2004.h>

CH_KEF_NoMH_AM_2004::pk pk;
CH_KEF_NoMH_AM_2004::sk sk;
mpz_t m,m_p;
mpz_t r,r_p;
mpz_t s,s_p;
mpz_t h;


void test_init(){
    mpz_inits(m, m_p, r, r_p,s,s_p, h, NULL);
    pk.Init();
    sk.Init();
}

void test_clear(){
    mpz_clears(m, m_p, r, r_p,s,s_p, h, NULL);
}

int main(){
    printf("Test CH_KEF_NoMH_AM_2004\n");
    test_init();

    CH_KEF_NoMH_AM_2004 *test = new CH_KEF_NoMH_AM_2004();

    int k = 512;
    test->GenKey(k, &pk, &sk);

    GenerateRandomWithLength(m, 1024);
    gmp_printf("m = %Zd\n", m);
    test->Hash(&pk, &m, &r, &s, &h);
    gmp_printf("h = %Zd\n", h);

    GenerateRandomWithLength(m_p, 1024);
    test->Forge(&pk, &sk, &m_p, &h, &r_p, &s_p);
    gmp_printf("r_p = %Zd\n", r_p);
    gmp_printf("s_p = %Zd\n", s_p);

    if(test->Verify(&pk, &m_p, &r_p, &s_p, &h)){
        printf("Verify success\n");
    }
    else{
        printf("Verify failed\n");
    }

    test_clear();
    return 0;
}