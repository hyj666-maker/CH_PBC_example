#include <SE/AES.h>

AES::AES(){
    this->k = 256;
}

/**
 * KGen 
 * input: k
 * output: key
 */
void AES::KGen(int k, element_t *key){
    if(this->k != 256){
        throw std::invalid_argument("AES-256 Enc: k must be 256");
    }
    this->k = k;
    element_random(*key);
}

/**
 * AES-256 KGen 
 * output: key
 */
void AES::KGen(element_t *key){
    element_random(*key);
}

/**
 * AES-256 Enc
 * input: key, plaintext
 * output: ciphertext
 */
void AES::Enc(element_t *key, mpz_t *plaintext, mpz_t *ciphertext){
    unsigned char aes_key[element_length_in_bytes(*key)];
    element_to_bytes(aes_key, *key);

    // printf("AES Key (Hex): ");
    // for (size_t i = 0; i < key_size; i++) {
    //     printf("%02x", aes_key[i]);
    // }
    // printf("\n");

    size_t plaintext_size = (mpz_sizeinbase(*plaintext, 2) + 7) / 8;
    unsigned char *plaintext_bytes = new unsigned char[plaintext_size];
    memset(plaintext_bytes, 0, sizeof(plaintext_bytes));
    mpz_export(plaintext_bytes, nullptr, 1, sizeof(plaintext_bytes[0]), 0, 0, *plaintext);

    unsigned char ciphertext_bytes[256];
    int ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, NULL); // 使用 AES-256-CBC 模式
    ciphertext_len = 0;
    int len;
    // 加密
    EVP_EncryptUpdate(ctx, ciphertext_bytes, &len, plaintext_bytes, plaintext_size);
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext_bytes + ciphertext_len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    // printf("Ciphertext (Hex): ");
    // for (int i = 0; i < strlen((const char *)ciphertext_bytes); i++) {
    //     printf("%02x", ciphertext_bytes[i]);
    // }
    // printf("\n");

    // ciphertext_bytes -> ciphertext
    mpz_import(*ciphertext, ciphertext_len, 1, sizeof(ciphertext_bytes[0]), 0, 0, ciphertext_bytes);
}

/**
 * input: key, ciphertext
 * output: decrypted_plaintext
 */
void AES::Dec(element_t *key, mpz_t *ciphertext, mpz_t *decrypted_plaintext){
    unsigned char aes_key[element_length_in_bytes(*key)];
    element_to_bytes(aes_key, *key);

    unsigned char ciphertext_bytes[256];
    memset(ciphertext_bytes, 0, sizeof(ciphertext_bytes));
    size_t ciphertext_size;
    mpz_export(ciphertext_bytes, &ciphertext_size, 1, sizeof(ciphertext_bytes[0]), 0, 0, *ciphertext);

    unsigned char decrypted_bytes[256];
    int decrypted_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, NULL);
    decrypted_len = 0;
    int len;
    // 解密
    EVP_DecryptUpdate(ctx, decrypted_bytes, &len, ciphertext_bytes, ciphertext_size);
    decrypted_len += len;
    EVP_DecryptFinal_ex(ctx, decrypted_bytes + decrypted_len, &len);
    decrypted_len += len;
    decrypted_bytes[decrypted_len] = '\0'; // 添加结束符
    EVP_CIPHER_CTX_free(ctx);

    mpz_import(*decrypted_plaintext, decrypted_len, 1, sizeof(decrypted_bytes[0]), 0, 0, decrypted_bytes);
}

AES::~AES(){

}