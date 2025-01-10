#include <ABE/MA_ABE.h>
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


const string POLICY = "(ONE&THREE)&(TWO|FOUR)";
const int SIZE_OF_POLICY = 4;   // Policy的属性个数（不去重）

// attribute
const string A = "ONE";
const string B = "TWO";
const string C = "THREE";
const string D = "FOUR";
const string ATTRIBUTES[] = {A, B, C, D};
const int SIZE_OF_ATTRIBUTES = sizeof(ATTRIBUTES) / sizeof(ATTRIBUTES[0]);

const string GID = "GID of A B C D with attribute ONE TOW THREE FOUR";

vector<MA_ABE::pkTheta *> pkThetas;
vector<MA_ABE::skTheta *> skThetas;
vector<MA_ABE::skgidA *> skgidAs;

MA_ABE::gpk gpk;

element_t msg,res;
MA_ABE::ciphertext c;


std::chrono::_V2::system_clock::time_point ts, te;

CurveParams curves;



void init_type(std::string &param) {
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    element_init_G1(G1, pairing);
    element_init_G2(G2, pairing);
    element_init_GT(GT, pairing);
    element_init_Zr(Zp, pairing);

    gpk.Init(&G1);
    c.Init(&G1, &GT, SIZE_OF_POLICY);

    element_init_same_as(msg, GT);
    element_init_same_as(res, GT);
}


void OutTime(std::string name, int id, double us) {
    us /= 1000;
    if(out_file) fprintf(out, "%s %d time: %lf ms.\n", name.c_str(), id, us);
    else if(visiable) printf("%s %d time: %lf ms.\n", name.c_str(), id, us);
}

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
    
void MA_ABE_test() {
    printf("MA_ABE_test begin\n");
    MA_ABE *test = new MA_ABE(&G1, &G2, &GT, &Zp);

    
    printf("——————————GlobalSetup() start——————————\n");
    for(int _ = 0;_ < turns_pg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->GlobalSetup(&gpk);
        te = std::chrono::high_resolution_clock::now();
        OutTime("GlobalSetup", _, time_cast(te, ts));
    }
    printf("——————————GlobalSetup() finished——————————\n");

    printf("——————————AuthSetup() start——————————\n");
    for(int _ = 0;_ < SIZE_OF_ATTRIBUTES;_++) {
        MA_ABE::pkTheta *pkTheta = new MA_ABE::pkTheta;
        MA_ABE::skTheta *skTheta = new MA_ABE::skTheta;
        pkTheta->Init(&G1, &GT);
        skTheta->Init(&Zp);

        ts = std::chrono::high_resolution_clock::now();
        test->AuthSetup(&gpk, ATTRIBUTES[_], pkTheta, skTheta);
        te = std::chrono::high_resolution_clock::now();
        OutTime("AuthSetup", _, time_cast(te, ts));

        pkThetas.push_back(pkTheta);
        skThetas.push_back(skTheta);
    }
    printf("——————————AuthSetup() finished——————————\n");


    printf("——————————KeyGen() start——————————\n");
    for(int _ = 0;_ < 4;_++) {
        MA_ABE::skgidA *skgidA = new MA_ABE::skgidA;
        skgidA->Init(&G1);

        ts = std::chrono::high_resolution_clock::now();
        test->KeyGen(&gpk, skThetas[_], GID, ATTRIBUTES[_], skgidA);
        te = std::chrono::high_resolution_clock::now();
        OutTime("KeyGen", _, time_cast(te, ts));

        skgidAs.push_back(skgidA);
        // PrintElement("skgidA_0", skgidA->skgidA_0);
        // PrintElement("skgidA_1", skgidA->skgidA_1);
    }
    printf("——————————KeyGen() finished——————————\n");

    printf("——————————Encrypt() start——————————\n");
    for(int _ = 0;_ < turns_h;_++) {
        element_random(msg);
        PrintElementAndSize("msg", msg);

        ts = std::chrono::high_resolution_clock::now();
        test->Encrypt(&gpk, &pkThetas, POLICY, &msg, &c);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Encrypt", _, time_cast(te, ts));

        // PrintElement("c0", c.c0);
        // for(int i = 0;i < SIZE_OF_POLICY;i++) {
        //     PrintElement("ci_1", c.ci[i]->ci_1);
        //     PrintElement("ci_2", c.ci[i]->ci_2);
        //     PrintElement("ci_3", c.ci[i]->ci_3);
        //     PrintElement("ci_4", c.ci[i]->ci_4);
        // }
       
    }
    printf("——————————Encrypt() finished——————————\n");

    printf("——————————Decrypt() start——————————\n");
    for(int _ = 0;_ < turns_f;_++) {
        vector<MA_ABE::skgidA *> _skgidAs;
        for(int i = 0;i < skgidAs.size();i++) {
            _skgidAs.push_back(skgidAs[i]);
        }

        ts = std::chrono::high_resolution_clock::now();
        test->Decrypt(&_skgidAs, &c, &res);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Decrypt", _, time_cast(te, ts));

        PrintElement("msg", msg);
        PrintElement("res", res);

        if(element_cmp(msg, res) == 0){
            printf("Decrypt successfully.\n");
            test_result = 0;
        }else{
            printf("Decrypt failed.\n");
        } 
    }
    printf("——————————Decrypt() finished——————————\n");

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
    out = fopen("tmp_MA_ABE.txt", "w");
    fflush(out);

    MA_ABE_test();

    fclose(out);

    return test_result;
}