#include <scheme/IB_CH_KEF.h>
#include "curve/params.h"
#include <chrono>
#include <iostream>
#include <cstring>
#include "pbc/pbc.h"

FILE *out = NULL;

int turns = 0, turns_setup = 1, turns_keygen = 1, turns_hash = 1, turns_collision = 1, rev_G1G2;

const bool out_file = true, visiable = false;

pbc_param_t par;
pairing_t pairing;
element_t G1, G2, GT, Zp, S_ID, ID, m, m_p, r_1, r_2, r_1_p, r_2_p, H, L;

std::chrono::_V2::system_clock::time_point ts, te;

CurveParams curves;

void init_type(std::string &param) {
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);
    if(rev_G1G2) {
        element_init_G2(G1, pairing);
        element_init_G1(G2, pairing);
    } else {
        element_init_G1(G1, pairing);
        element_init_G2(G2, pairing);
    }
    element_init_GT(GT, pairing);
    element_init_Zr(Zp, pairing);

    element_init_same_as(r_1, G1);
    element_init_same_as(r_1_p, G1);
    element_init_same_as(H, G1);
    element_init_same_as(S_ID, G2);
    element_init_same_as(r_2, GT);
    element_init_same_as(r_2_p, GT);
    element_init_same_as(m, Zp);
    element_init_same_as(m_p, Zp);
    element_init_same_as(L, Zp);
    element_init_same_as(ID, Zp);
}


void OutTime(std::string name, int id, double us) {
    us /= 1000;
    if(out_file) fprintf(out, "%s %d time: %lf ms.\n", name.c_str(), id, us);
    else if(visiable) printf("%s %d time: %lf ms.\n", name.c_str(), id, us);
}

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
    
void IB_CH_KEF_test() {
    IB_CH_KEF *test = new IB_CH_KEF(&G1, &G2, &Zp, &GT, rev_G1G2);

    if(out_file) fprintf(out, "public_key: %d B, secret_key: %d B, hash_value: %d B, random_value: %d B\n", test->public_key_size(), CountSize(S_ID), CountSize(H), CountSize(r_1) + CountSize(r_2));
    if(out_file) fprintf(out, "turns_setup: %d, turns_extract: %d, turns_hash: %d, turns_forge: %d\n", turns_setup, turns_keygen, turns_hash, turns_collision);

    for(int _ = 0;_ < turns_setup;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->Setup();
        te = std::chrono::high_resolution_clock::now();
        OutTime("setup", _, time_cast(te, ts));
    }

    for(int _ = 0;_ < turns_keygen;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->Extract(&ID, &S_ID);
        te = std::chrono::high_resolution_clock::now();
        OutTime("keygen", _, time_cast(te, ts));
    }

    for(int _ = 0;_ < turns_hash;_++) {
        element_random(m);
        element_random(L);
        ts = std::chrono::high_resolution_clock::now();
        test->Hash(&ID, &L, &H, &m, &r_1, &r_2);
        te = std::chrono::high_resolution_clock::now();
        OutTime("hash", _, time_cast(te, ts));
    }

    for(int _ = 0;_ < turns_collision;_++) {
        element_random(m_p);
        ts = std::chrono::high_resolution_clock::now();
        test->Forge(&S_ID, &L, &m, &m_p, &r_1, &r_2, &r_1_p, &r_2_p);
        te = std::chrono::high_resolution_clock::now();
        // printf("%d\n", test->Verify(&ID, &L, &H, &m_p, &r_1_p, &r_2_p, &S_ID));
        OutTime("collision", _, time_cast(te, ts));
    }

    if(out_file) fprintf(out, "-----------------------------------\n");
    if(visiable) printf("\n");
}

#undef time_cast

int main(int argc, char *argv[]) { // curve, scheme, turns, T;
    if(argc < 4) {
        printf("usage: %s [a|e|i|f|d224] {total_turns} [setup|hash|keygen|collision|all] [0|1]\n", argv[0]);
        return 0;
    }
    turns = atoi(argv[2]);
    rev_G1G2 = atoi(argv[4]);

    if(strcmp(argv[3], "setup") == 0) turns_setup = turns;
    else if(strcmp(argv[3], "hash") == 0) turns_hash = turns;
    else if(strcmp(argv[3], "keygen") == 0) turns_keygen = turns;
    else if(strcmp(argv[3], "collision") == 0) turns_collision = turns;
    else if(strcmp(argv[3], "all") == 0) {
        turns_setup = turns;
        turns_hash = turns;
        turns_keygen = turns;
        turns_collision = turns;
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
    out = fopen("tmp.txt", "w");
    fflush(out);

    IB_CH_KEF_test();

    fclose(out);
    return 0;
}