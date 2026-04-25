#ifndef NKCRYPTOTOOL_WOLFSSL_BACKEND_HPP
#define NKCRYPTOTOOL_WOLFSSL_BACKEND_HPP

#include "IBackend.hpp"
#include <wolfssl/options.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/random.h>

namespace nk::backend {

class WolfSslAeadBackend : public IAeadBackend {
public:
    WolfSslAeadBackend(WOLFSSL_EVP_CIPHER_CTX* ctx);
    ~WolfSslAeadBackend() override;
    std::expected<size_t, CryptoError> update(const uint8_t* in, size_t in_len, uint8_t* out) override;
    std::expected<size_t, CryptoError> finalize(uint8_t* out) override;
    std::expected<void, CryptoError> getTag(uint8_t* tag, size_t tag_len) override;
    std::expected<void, CryptoError> setTag(const uint8_t* tag, size_t tag_len) override;

private:
    WOLFSSL_EVP_CIPHER_CTX* ctx_;
};

class WolfSslHashBackend : public IHashBackend {
public:
    WolfSslHashBackend(WOLFSSL_EVP_MD_CTX* ctx, const WOLFSSL_EVP_MD* md);
    ~WolfSslHashBackend() override;
    std::expected<void, CryptoError> update(const uint8_t* data, size_t len) override;
    std::expected<void, CryptoError> initSign(const std::vector<uint8_t>& priv_key_der) override;
    std::expected<std::vector<uint8_t>, CryptoError> finalizeSign() override;
    std::expected<void, CryptoError> initVerify(const std::vector<uint8_t>& pub_key_der) override;
    std::expected<bool, CryptoError> finalizeVerify(const std::vector<uint8_t>& signature) override;

private:
    WOLFSSL_EVP_MD_CTX* ctx_;
    const WOLFSSL_EVP_MD* md_;
    WOLFSSL_EVP_PKEY* pkey_ = nullptr;
    std::vector<uint8_t> buffer_;
};

class WolfSslBackend : public ICryptoBackend {
public:
    std::expected<std::unique_ptr<IAeadBackend>, CryptoError> createAead(const std::string& cipher_name, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt) override;
    std::expected<std::unique_ptr<IHashBackend>, CryptoError> createHash(const std::string& algo_name) override;
    std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> generateEccKeyPair(const std::string& curve_name) override;
    std::expected<std::vector<uint8_t>, CryptoError> eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der) override;
    std::expected<std::vector<uint8_t>, CryptoError> extractPublicKey(const std::vector<uint8_t>& priv_der) override;
    std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> generatePqcSignKeyPair(const std::string& algo_name) override;
    std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> pqcEncap(const std::vector<uint8_t>& pub_key_der) override;
    std::expected<std::vector<uint8_t>, CryptoError> pqcDecap(const std::vector<uint8_t>& priv_key_der, const std::vector<uint8_t>& kem_ct) override;
    std::vector<uint8_t> hkdf(const std::vector<uint8_t>& secret, size_t out_len, const std::vector<uint8_t>& salt, const std::string& info, const std::string& md_name) override;
    std::expected<void, CryptoError> randomBytes(uint8_t* out, size_t len) override;
    void cleanse(void* ptr, size_t len) override;
    std::string base64Encode(const std::vector<uint8_t>& data) override;
    std::vector<uint8_t> base64Decode(const std::string& base64_str) override;
};

} // namespace nk::backend

#endif // NKCRYPTOTOOL_WOLFSSL_BACKEND_HPP
