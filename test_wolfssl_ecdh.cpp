#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdh.h>
#include <iostream>
#include <vector>
#include <iomanip>

int main() {
    wolfSSL_Init();
    
    WOLFSSL_EC_KEY* key_a = wolfSSL_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    wolfSSL_EC_KEY_generate_key(key_a);
    
    WOLFSSL_EC_KEY* key_b = wolfSSL_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    wolfSSL_EC_KEY_generate_key(key_b);
    
    std::vector<uint8_t> secret(64);
    int secret_len = wolfSSL_ECDH_compute_key(secret.data(), (int)secret.size(),
                                           wolfSSL_EC_KEY_get0_public_key(key_b),
                                           key_a, nullptr);
    
    std::cout << "Secret length: " << secret_len << std::endl;
    std::cout << "Secret: ";
    for (int i = 0; i < secret_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)secret[i];
    }
    std::cout << std::dec << std::endl;
    
    wolfSSL_EC_KEY_free(key_a);
    wolfSSL_EC_KEY_free(key_b);
    wolfSSL_Cleanup();
    return 0;
}
