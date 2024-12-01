#include <scheme/PCHBA_TLL_2020.h>
#include "curve/params.h"
#include <chrono>
#include <iostream>
#include <cstring>
#include "pbc/pbc.h"

FILE *out = NULL;

int turns = 0, turns_pg = 1, turns_kg = 1, turns_h = 1, turns_f = 1;

const bool out_file = true, visiable = false;

pbc_param_t par;
pairing_t pairing;
element_t G1, G2, GT, Zp;

unsigned long int k;
element_t sk,pk; 
element_t g,h,H1,H2,T1,T2;
element_t *array_g, *array_g_pow_a, *array_h;
element_t g_pow_a, h_pow_d_div_a, h_pow_1_div_a, h_pow_b_div_a;
element_t a1, a2,b1,b2,a,b;
element_t g_pow_d1, g_pow_d2, g_pow_d3;
element_t *array_z;



std::chrono::_V2::system_clock::time_point ts, te;

CurveParams curves;

void init_type(std::string &param) {
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    element_init_G1(G1, pairing);
    element_init_G2(G2, pairing);
    element_init_GT(GT, pairing);
    element_init_Zr(Zp, pairing);

    element_init_same_as(sk, Zp);
    element_init_same_as(pk, G2);
    element_init_same_as(g, G1);
    element_init_same_as(h, G2);
    element_init_same_as(H1, G2);
    element_init_same_as(H2, G2);
    element_init_same_as(T1, GT);
    element_init_same_as(T2, GT);
    array_g = new element_t[k+1];
    array_g_pow_a = new element_t[k+1];
    array_h = new element_t[k+1];
    array_z = new element_t[k+1];
    for (unsigned long int i = 0; i <= k; i++)
    {
        element_init_same_as(array_g[i], G1);
        element_init_same_as(array_g_pow_a[i], G1);
        element_init_same_as(array_h[i], G2);
        element_init_same_as(array_z[i], Zp);
    }
    element_init_same_as(g_pow_a, G1);
    element_init_same_as(h_pow_d_div_a, G2);
    element_init_same_as(h_pow_1_div_a, G2);
    element_init_same_as(h_pow_b_div_a, G2);

    element_init_same_as(a1, Zp);
    element_init_same_as(a2, Zp);
    element_init_same_as(b1, Zp);
    element_init_same_as(b2, Zp);
    element_init_same_as(a, Zp);
    element_init_same_as(b, Zp);
    element_init_same_as(g_pow_d1, G1);
    element_init_same_as(g_pow_d2, G1);
    element_init_same_as(g_pow_d3, G1);
    

}


void OutTime(std::string name, int id, double us) {
    us /= 1000;
    if(out_file) fprintf(out, "%s %d time: %lf ms.\n", name.c_str(), id, us);
    else if(visiable) printf("%s %d time: %lf ms.\n", name.c_str(), id, us);
}

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
    
void PCHBA_TLL_2020_test() {
    printf("PCHBA_TLL_2020_test begin\n");

    k = 10;
    printf("k = %d\n", k);

    unsigned long int m_bit_length = element_length_in_bytes(m) * 8;
    std::cout << "Bit length of m: " << m_bit_length << std::endl;

    PCHBA_TLL_2020 *test = new PCHBA_TLL_2020(&G1, &G2, &Zp, &GT);
    
    printf("——————————PG() start——————————\n");
    for(int _ = 0;_ < turns_pg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->PG(k, 
                &sk, &pk, 
                &g, &h, &H1, &H2, &T1, &T2, 
                    array_g, array_g_pow_a, 
                    array_h, &g_pow_a, &h_pow_d_div_a, &h_pow_1_div_a, &h_pow_b_div_a, 
                &a1, &a2, &b1, &b2, &a, &b, 
                    &g_pow_d1, &g_pow_d2, &g_pow_d3, array_z);
        // size of x
        // printf("sizeof(x):  %d bytes\n",element_length_in_bytes(x));
        te = std::chrono::high_resolution_clock::now();
        OutTime("PG", _, time_cast(te, ts));
    }
    printf("——————————PG() finished——————————\n");

    printf("——————————KG() start——————————\n");
    for(int _ = 0;_ < turns_kg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->KG(&x, &ID, &SID);
        // size of SID
        printf("sizeof(SID):  %d bytes\n",element_length_in_bytes(SID));
        te = std::chrono::high_resolution_clock::now();
        OutTime("keygen", _, time_cast(te, ts));
    }
    printf("——————————KG() finished——————————\n");

    printf("——————————Hash() start——————————\n");
    for(int _ = 0;_ < turns_h;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->Hash(&ID, &L, &m, &r1, &r2, &h);
        // size of h
        printf("sizeof(h):  %d bytes\n",element_length_in_bytes(h));
        
        if(test->Check(&h, &L, &m, &r1)){
            printf("Check success\n");
        }
        else{
            printf("Check failed\n");
        }
        te = std::chrono::high_resolution_clock::now();
        OutTime("hash", _, time_cast(te, ts));
    }
    printf("——————————Hash() finished——————————\n");

    printf("——————————Forge() start——————————\n");
    for(int _ = 0;_ < turns_f;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->Forge(&SID, &ID, &L, &h, &m, &r1, &r2, &m_p, &r1_p, &r2_p);
        te = std::chrono::high_resolution_clock::now();
       
        if(test->Verify(&h, &L, &m_p, &r1_p)){
            printf("Verify success\n");
        }
        else{
            printf("Verify failed\n");
        }
        OutTime("collision", _, time_cast(te, ts));
    }
    printf("——————————Forge() finished——————————\n");

    if(out_file) fprintf(out, "-----------------------------------\n");
    if(visiable) printf("\n");
}

#undef time_cast

int main(int argc, char *argv[]) { // curve, scheme, turns, T;
    if(argc < 4) {
        printf("usage: %s [a|e|i|f|d224] {total_turns} [pg|kg|h|f|all]\n", argv[0]);
        return 0;
    }
    turns = atoi(argv[2]);

    if(strcmp(argv[3], "pg") == 0) turns_pg = turns;
    else if(strcmp(argv[3], "kg") == 0) turns_kg = turns;
    else if(strcmp(argv[3], "h") == 0) turns_h = turns;
    else if(strcmp(argv[3], "f") == 0) turns_f = turns;
    else if(strcmp(argv[3], "all") == 0) {
        turns_pg = turns;
        turns_kg = turns;
        turns_h = turns;
        turns_f = turns;
    }else return 0;
    
    if(strcmp(argv[1], "a") == 0) init_type(curves.a_param);
    // else if(strcmp(argv[1], "a80") == 0) init_type(curves.a_param_80);
    // else if(strcmp(argv[1], "a112") == 0) init_type(curves.a_param_112);
    // else if(strcmp(argv[1], "a128") == 0) init_type(curves.a_param_128);
    // else if(strcmp(argv[1], "a160") == 0) init_type(curves.a_param_160);
    else if(strcmp(argv[1], "a1") == 0) init_type(curves.a1_param);
    else if(strcmp(argv[1], "e") == 0) init_type(curves.e_param);
    else if(strcmp(argv[1], "i") == 0) init_type(curves.i_param);
    else if(strcmp(argv[1], "f") == 0) init_type(curves.f_param);
    else if(strcmp(argv[1], "d224") == 0) init_type(curves.d224_param);
    else return 0;
    out = fopen("tmp_PCHBA_TLL_2020.txt", "w");
    fflush(out);

    PCHBA_TLL_2020_test();

    fclose(out);
    return 0;
}