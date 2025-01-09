#include <ABE/RABE_TMM.h>
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

const int N = 8;  // a binary tree with N leaf nodes
const int DEPTH = 4;  // log2(N) + 1
std::vector<std::string> attr_list = {"ONE","TWO","THREE","FOUR"};
const int SIZE_OF_ATTR = attr_list.size();  // S, S是Policy所有属性的子集
const string POLICY = "(ONE&THREE)&(TWO|FOUR)";
const int SIZE_OF_POLICY = 4;   // Policy的属性个数（不去重）
const time_t T = TimeCast(2024, 12, 21, 0, 0, 0);  // present time

RABE_TMM::mpk mpk;
RABE_TMM::msk msk;
RABE_TMM::skid skid;
RABE_TMM::kut kut;
RABE_TMM::dkidt dkidt;
RABE_TMM::ciphertext ciphertext;

vector<RABE_TMM::revokedPreson *> rl;
binary_tree_RABE *st;

element_t id;

element_t msg,res;

element_t s1,s2;


std::chrono::_V2::system_clock::time_point ts, te;

CurveParams curves;



void init_type(std::string &param) {
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(pairing, par);

    element_init_G1(G1, pairing);
    element_init_G2(G2, pairing);
    element_init_GT(GT, pairing);
    element_init_Zr(Zp, pairing);

    msk.Init(&G1, &Zp);
    mpk.Init(&G1, &G2, &GT);
    skid.Init(&G1, &G2, SIZE_OF_ATTR);
    dkidt.Init(&G1, &G2, SIZE_OF_ATTR);
    ciphertext.Init(&G1, &G2, &Zp, SIZE_OF_POLICY);

    element_init_same_as(id, Zp);

    element_init_same_as(msg, Zp);
    element_init_same_as(res, Zp);

    element_init_same_as(s1, Zp);
    element_init_same_as(s2, Zp);
}


void OutTime(std::string name, int id, double us) {
    us /= 1000;
    if(out_file) fprintf(out, "%s %d time: %lf ms.\n", name.c_str(), id, us);
    else if(visiable) printf("%s %d time: %lf ms.\n", name.c_str(), id, us);
}

#define time_cast(a, b) std::chrono::duration_cast<std::chrono::microseconds>(a - b).count()
    
void RABE_TMM_test() {
    printf("RABE_TMM_test begin\n");
    RABE_TMM *test = new RABE_TMM(&G1, &G2, &GT, &Zp);

    
    printf("——————————Setup() start——————————\n");
    for(int _ = 0;_ < turns_pg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->Setup(N ,&mpk, &msk, &rl, st);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Setup", _, time_cast(te, ts));

        // st->printTree();
        // PrintElement("g", msk.g);
        // PrintElement("h", msk.h);
        // PrintElement("a1", msk.a1);
        // PrintElement("a2", msk.a2);
        // PrintElement("b1", msk.b1);
        // PrintElement("b2", msk.b2);
        // PrintElement("g_pow_d1", msk.g_pow_d1);
        // PrintElement("g_pow_d2", msk.g_pow_d2);
        // PrintElement("g_pow_d3", msk.g_pow_d3);
        // PrintElement("h", mpk.h);
        // PrintElement("H1", mpk.H1);
        // PrintElement("H2", mpk.H2);
        // PrintElement("T1", mpk.T1);
        // PrintElement("T2", mpk.T2);

    }
    printf("——————————Setup() finished——————————\n");


    printf("——————————KeyGen() start——————————\n");
    for(int _ = 0;_ < turns_kg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->KGen(&mpk, &msk, st, &id, &attr_list, &skid);
        te = std::chrono::high_resolution_clock::now();
        OutTime("KeyGen", _, time_cast(te, ts));

        // PrintElement("sk0.sk_1", skid.sk0.sk_1);
        // PrintElement("sk0.sk_2", skid.sk0.sk_2);
        // PrintElement("sk0.sk_3", skid.sk0.sk_3);
        // for(int i = 0;i < SIZE_OF_ATTR;i++){
        //     PrintElement("sk_y[" + std::to_string(i) + "].sk_1", skid.sk_y[i]->sk_1);
        //     PrintElement("sk_y[" + std::to_string(i) + "].sk_2", skid.sk_y[i]->sk_2);
        //     PrintElement("sk_y[" + std::to_string(i) + "].sk_3", skid.sk_y[i]->sk_3);
        // }
        // PrintElement("sk_prime.sk_1", skid.sk_prime.sk_1);
        // PrintElement("sk_prime.sk_2", skid.sk_prime.sk_2);
        // PrintElement("sk_prime.sk_3", skid.sk_prime.sk_3);
    }
    printf("——————————KeyGen() finished——————————\n");

    printf("——————————KUpt() start——————————\n");
    for(int _ = 0;_ < turns_kg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->KUpt(&mpk, st, &rl, T, &kut);
        te = std::chrono::high_resolution_clock::now();
        OutTime("KeyGen", _, time_cast(te, ts));

        printf("size of kut.ku_theta: %ld\n", kut.ku_theta.size());
    }
    printf("——————————KUpt() finished——————————\n");

    printf("——————————DKGen() start——————————\n");
    for(int _ = 0;_ < turns_kg;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->DKGen(&mpk, &skid, &kut, &dkidt);
        te = std::chrono::high_resolution_clock::now();
        OutTime("KeyGen", _, time_cast(te, ts));

        printf("size of kut.ku_theta: %ld\n", kut.ku_theta.size());
    }
    printf("——————————DKGen() finished——————————\n");

    printf("——————————Encrypt() start——————————\n");
    for(int _ = 0;_ < turns_h;_++) {
        element_random(msg);
        PrintElementAndSize("msg", msg);
        element_random(s1);
        element_random(s2);

        ts = std::chrono::high_resolution_clock::now();
        test->Enc(&mpk, &msg, POLICY, T, &s1, &s2, &ciphertext);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Encrypt", _, time_cast(te, ts));

        // PrintElement("ct0.ct_1", ciphertext.ct0.ct_1);
        // PrintElement("ct0.ct_2", ciphertext.ct0.ct_2);
        // PrintElement("ct0.ct_3", ciphertext.ct0.ct_3);
        // for(int i = 0;i < SIZE_OF_POLICY;i++){
        //     PrintElement("ct_y[" + std::to_string(i) + "].ct_1", ciphertext.ct_y[i]->ct_1);
        //     PrintElement("ct_y[" + std::to_string(i) + "].ct_2", ciphertext.ct_y[i]->ct_2);
        //     PrintElement("ct_y[" + std::to_string(i) + "].ct_3", ciphertext.ct_y[i]->ct_3);
        // }
        // PrintElement("ct_prime", ciphertext.ct_prime);
    }
    printf("——————————Encrypt() finished——————————\n");

    printf("——————————Decrypt() start——————————\n");
    for(int _ = 0;_ < turns_f;_++) {
        ts = std::chrono::high_resolution_clock::now();
        test->Dec(&mpk, &ciphertext, &dkidt, &res);
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

    printf("——————————Rev() start——————————\n");
    for(int _ = 0;_ < turns_f;_++) {
        ts = std::chrono::high_resolution_clock::now();
        time_t target_time = TimeCast(2025, 12, 31, 0, 0, 0);
        test->Rev(&rl, &id, target_time);
        te = std::chrono::high_resolution_clock::now();
        OutTime("Rev", _, time_cast(te, ts));
    }
    printf("——————————Rev() finished——————————\n");

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
    out = fopen("tmp_RABE_TMM.txt", "w");
    fflush(out);

    RABE_TMM_test();

    fclose(out);

    return test_result;
}