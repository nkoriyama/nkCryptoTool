#ifndef NKCRYPTOTOOL_OPENSSL_BACKEND_HPP
#define NKCRYPTOTOOL_OPENSSL_BACKEND_HPP

#include "IBackend.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include "../OpenSSLDeleters.hpp"

namespace nk::backend {

class OpenSslAeadBackend : public IAeadBackend {
public:
    OpenSslAeadBackend(std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx);
    std::expected<size_t, CryptoError> update(const uint8_t* in, size_t in_len, uint8_t* out) override;
    std::expected<size_t, CryptoError> finalize(uint8_t* out) override;
    std::expected<void, CryptoError> getTag(uint8_t* tag, size_t tag_len) override;
    std::expected<void, CryptoError> setTag(const uint8_t* tag, size_t tag_len) override;

private:
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx_;
};

class OpenSslHashBackend : public IHashBackend {
public:
    OpenSslHashBackend(std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx, const EVP_MD* md);
    std::expected<void, CryptoError> update(const uint8_t* data, size_t len) override;
    std::expected<void, CryptoError> initSign(const std::vector<uint8_t>& priv_key_der) override;
    std::expected<std::vector<uint8_t>, CryptoError> finalizeSign() override;
    std::expected<void, CryptoError> initVerify(const std::vector<uint8_t>& pub_key_der) override;
    std::expected<bool, CryptoError> finalizeVerify(const std::vector<uint8_t>& signature) override;

private:
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx_;
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey_;
    const EVP_MD* md_;
    std::vector<uint8_t> buffer_;
};

class OpenSslBackend : public ICryptoBackend {
public:
    OpenSslBackend();
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

// OpenSSL 3.0 以降のエンコーダ/デコーダ用パスフレーズコールバック
int ossl_passphrase_cb(char *pass, size_t pass_max, size_t *pass_len, const OSSL_PARAM params[], void *arg);

} // namespace nk::backend

#endif // NKCRYPTOTOOL_OPENSSL_BACKEND_HPP
