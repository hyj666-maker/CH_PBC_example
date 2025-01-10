#include <signature/BLS.h>
#include "curve/params.h"
#include <chrono>
#include <iostream>
#include <cstring>

int test_result = 1;

FILE *out = NULL;

int turns = 0, turns_pg = 1, turns_kg = 1, turns_h = 1, turns_f = 1;

const bool out_file = true, visiable = false;

pbc_param_t par;
pairing_t pairing;
element_t G1, G2, GT, Zp;

BLS::pk pk;
BLS::sk sk;
string message;
element_t signature;


std::chrono::_V2::system_clock::time_point ts, te;

CurveParams curves;


void init_type(std::string &param) {
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    element_init_G1(G1, pairing);
    element_init_G2(G2, pairing);
    element_init_GT(GT, pairing);
    element_init_Zr(Zp, pairing);

    pk.Init(&G1);
    sk.Init(&Zp);
    element_init_same_as(signature, G2);
}


void OutTime(std::string name, int id, double us) {
    us /= 1000;
    if(out_file) fprintf(out, "%s %d time: %lf ms.\n", name.c_str(), id, us);
    else if(visiable) printf("%s %d time: %lf ms.\n", name.c_str(), id, us);
}

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
    
void BLS_test() {
    printf("BLS_test begin\n");
    BLS *test = new BLS(&G1, &G2, &GT, &Zp);

    printf("——————————KeyGen() start——————————\n");
    for(int _ = 0;_ < turns_pg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->KeyGen(&pk, &sk);
        te = std::chrono::high_resolution_clock::now();
        OutTime("KeyGen", _, time_cast(te, ts));
    }
    printf("——————————KeyGen() finished——————————\n");


    printf("——————————Sign() start——————————\n");
    for(int _ = 0;_ < turns_h;_++) {
        message = "Hello, BLS!";

        ts = std::chrono::high_resolution_clock::now();
        test->Sign(&sk, message, &signature);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Sign", _, time_cast(te, ts));

        PrintElement("signature", signature);
    }
    printf("——————————Sign() finished——————————\n");


    printf("——————————Verify() start——————————\n");
    for(int _ = 0;_ < turns_f;_++) {
        bool verify_result;
        ts = std::chrono::high_resolution_clock::now();
        verify_result = test->Verify(&pk, message, &signature);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Decrypt", _, time_cast(te, ts));

        if(verify_result){
            printf("Verify successfully.\n");
            test_result = 0;
        }else{
            printf("Verify failed.\n");
        }
    }
    printf("——————————Verify() finished——————————\n");

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
    out = fopen("tmp_BLS.txt", "w");
    fflush(out);

    BLS_test();

    fclose(out);

    return test_result;
}