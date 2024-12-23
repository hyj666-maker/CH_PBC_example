#include "utils/func.h"
#include <openssl/sha.h>
#include <sys/time.h>


void Hm(element_t &m, element_t &res, element_t &tmp_Zp, element_t &g) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void Hgsm(element_t &gs, element_t &m, element_t &res, element_t &tmp_Zp, element_t &g) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(gs)];
    element_to_bytes(bytes1, gs);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m)];
    element_to_bytes(bytes2, m);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * res = H(m)
 */
void Hm_1(element_t &m, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(m)];
    element_to_bytes(bytes1, m);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

void Hgsm_1(element_t &gs, element_t &m, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char bytes1[element_length_in_bytes(gs)];
    element_to_bytes(bytes1, gs);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m)];
    element_to_bytes(bytes2, m);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}


/**
 * FCR_CH_PreQA_DKS_2020
 */
void Hm_2(element_t &y, element_t &h, element_t &m,element_t &u1,element_t &u2, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(y)];
    element_to_bytes(bytes1, y);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(h)];
    element_to_bytes(bytes2, h);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(m)];
    element_to_bytes(bytes3, m);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
    unsigned char bytes4[element_length_in_bytes(u1)];
    element_to_bytes(bytes4, u1);
    SHA256_Update(&sha256, bytes4, sizeof(bytes4));
    unsigned char bytes5[element_length_in_bytes(u2)];
    element_to_bytes(bytes5, u2);
    SHA256_Update(&sha256, bytes5, sizeof(bytes5));

    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * CR_CH_DSS_2020
 */
void Hm_3(element_t &y, element_t &h1, element_t &h2, element_t &m,
            element_t &u11,element_t &u12, element_t &u2, 
            element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(y)];
    element_to_bytes(bytes1, y);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(h1)];
    element_to_bytes(bytes2, h1);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(h2)];
    element_to_bytes(bytes3, h2);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
    unsigned char bytes4[element_length_in_bytes(m)];
    element_to_bytes(bytes4, m);
    SHA256_Update(&sha256, bytes4, sizeof(bytes4));
    unsigned char bytes5[element_length_in_bytes(u11)];
    element_to_bytes(bytes5, u11);
    SHA256_Update(&sha256, bytes5, sizeof(bytes5));
    unsigned char bytes6[element_length_in_bytes(u12)];
    element_to_bytes(bytes6, u12);
    SHA256_Update(&sha256, bytes6, sizeof(bytes6));
    unsigned char bytes7[element_length_in_bytes(u2)];
    element_to_bytes(bytes7, u2);
    SHA256_Update(&sha256, bytes7, sizeof(bytes7));
    
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

/**
 * input: m1,m2,m3
 * output: res
 */
void Hm_4(element_t &m1, element_t &m2, element_t &m3, element_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char bytes1[element_length_in_bytes(m1)];
    element_to_bytes(bytes1, m1);
    SHA256_Update(&sha256, bytes1, sizeof(bytes1));
    unsigned char bytes2[element_length_in_bytes(m2)];
    element_to_bytes(bytes2, m2);
    SHA256_Update(&sha256, bytes2, sizeof(bytes2));
    unsigned char bytes3[element_length_in_bytes(m3)];
    element_to_bytes(bytes3, m3);
    SHA256_Update(&sha256, bytes3, sizeof(bytes3));
        
    SHA256_Final(hash, &sha256);
    element_from_hash(res, hash, SHA256_DIGEST_LENGTH);
}

int CountSize(element_t &t) {
    return element_length_in_bytes(t);
}


void PrintElement(std::string element_name, element_t &element){
    printf("%s = ", element_name.c_str());
    element_printf("%B\n", element);
}
void PrintElementsize(std::string element_name, element_t &element){
    printf("size of %s = %d bytes\n", element_name.c_str(), CountSize(element));
}
void PrintElementAndSize(std::string element_name, element_t &element){
    PrintElement(element_name, element);
    PrintElementsize(element_name, element);
}
void PrintMpz(std::string mpz_name, mpz_t &mpz){
    gmp_printf("%s = %Zd\n", mpz_name.c_str(), mpz);
}
void PrintMpzsize(std::string mpz_name, mpz_t &mpz){
    printf("size of %s = %ld bytes\n", mpz_name.c_str(), (mpz_sizeinbase(mpz, 2) + 7) / 8);
}
void PrintMpzAndSize(std::string mpz_name, mpz_t &mpz){
    PrintMpz(mpz_name, mpz);
    PrintMpzsize(mpz_name, mpz);
}

/**
 * hash mod n
 */
void Hm_n(mpz_t &m, mpz_t &res,  mpz_t &n) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    size_t m_size = (mpz_sizeinbase(m, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes1 = new unsigned char[m_size];
    mpz_export(bytes1, nullptr, 1, 1, 0, 0, m);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes1, m_size);           // 更新哈希值
    delete[] bytes1;  // 释放内存

  
    SHA256_Final(hash, &sha256);
    
    // 将哈希值转换为 mpz_t 并存储到 res 中
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 将结果映射到 n 的范围内，计算 res = res mod n
    mpz_mod(res, res, n);
}

/**
 * hash mod n
 */
void Hgsm_n(mpz_t &gs, mpz_t &m, mpz_t &res,  mpz_t &n) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    // 将第一个参数 gs 转换为字节数组
    size_t gs_size = (mpz_sizeinbase(gs, 2) + 7) / 8;  // 计算字节大小
    unsigned char* bytes1 = new unsigned char[gs_size];
    mpz_export(bytes1, nullptr, 1, 1, 0, 0, gs);  // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes1, gs_size);      // 更新哈希值
    delete[] bytes1;  // 释放内存

    // 将第二个参数 m 转换为字节数组
    size_t m_size = (mpz_sizeinbase(m, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes2 = new unsigned char[m_size];
    mpz_export(bytes2, nullptr, 1, 1, 0, 0, m);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes2, m_size);           // 更新哈希值
    delete[] bytes2;  // 释放内存

    // 计算最终哈希值
    SHA256_Final(hash, &sha256);

    // 将哈希值转换为 mpz_t 并存储到 res 中
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 将结果映射到 n 的范围内，计算 res = res mod n
    mpz_mod(res, res, n);
}

/**
 * hash mod n
 * input: m1,m2,m3, n
 * output: res
 */
void Hgsm_n_2(mpz_t &m1, mpz_t &m2, mpz_t &m3, mpz_t &n, mpz_t &res) {
    // 计算SHA-256哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    size_t m_size = (mpz_sizeinbase(m1, 2) + 7) / 8;  // 计算字节大小
    unsigned char* bytes1 = new unsigned char[m_size];
    mpz_export(bytes1, nullptr, 1, 1, 0, 0, m1);  // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes1, m_size);      // 更新哈希值
    delete[] bytes1;  // 释放内存

    m_size = (mpz_sizeinbase(m2, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes2 = new unsigned char[m_size];
    mpz_export(bytes2, nullptr, 1, 1, 0, 0, m2);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes2, m_size);           // 更新哈希值
    delete[] bytes2;  // 释放内存

    m_size = (mpz_sizeinbase(m3, 2) + 7) / 8;   // 计算字节大小
    unsigned char* bytes3 = new unsigned char[m_size];
    mpz_export(bytes3, nullptr, 1, 1, 0, 0, m3);       // 将 mpz_t 转换为字节数组
    SHA256_Update(&sha256, bytes3, m_size);           // 更新哈希值
    delete[] bytes3;  // 释放内存

    // 计算最终哈希值
    SHA256_Final(hash, &sha256);

    // 将哈希值转换为 mpz_t 并存储到 res 中
    mpz_import(res, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    // 将结果映射到 n 的范围内，计算 res = res mod n
    mpz_mod(res, res, n);
}


/**
 * gnerate random in length
 */
void GenerateRandomWithLength(mpz_t &res, int length){
    // 生成随机数
    gmp_randstate_t state;
    gmp_randinit_default(state);          
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long seed = tv.tv_sec * 1000000 + tv.tv_usec;

    gmp_randseed_ui(state, seed);
    mpz_urandomb(res, state, length); // 生成一个随机数，长度为 length 位
    gmp_randclear(state);
}

/**
 * 生成随机数 res，使得 0 <= res < max
 */
void GenerateRandomInN(mpz_t &res, mpz_t &max){
    // 生成随机数
    gmp_randstate_t state;
    gmp_randinit_default(state);          
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long seed = tv.tv_sec * 1000000 + tv.tv_usec;

    gmp_randseed_ui(state, seed);
    mpz_urandomm(res, state, max); // 生成一个随机数小于max
    gmp_randclear(state);
}

/**
 * generate random ∈ Zn*
 */
void GenerateRandomInZnStar(mpz_t &res, mpz_t &max){
    GenerateRandomInN(res, max);
    mpz_t gcd;
    mpz_inits(gcd, NULL);
    mpz_gcd(gcd, res, max);
    while(mpz_cmp_ui(gcd, 1) != 0) {
        GenerateRandomInN(res, max);
        mpz_gcd(gcd, res, max);
    }
    mpz_clears(gcd, NULL);
}

time_t TimeCast(int year, int month, int day, int hour, int minute, int second)
{
    // time_t = 2025.12.31 0:00:00
    struct tm timeinfo = {};
    timeinfo.tm_year = year - 1900;
    timeinfo.tm_mon = month - 1;
    timeinfo.tm_mday = day;           
    timeinfo.tm_hour = hour;        
    timeinfo.tm_min = minute;             
    timeinfo.tm_sec = second;     
    timeinfo.tm_isdst = -1;  
    return mktime(&timeinfo);
}