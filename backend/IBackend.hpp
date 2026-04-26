#ifndef NKCRYPTOTOOL_IBACKEND_HPP
#define NKCRYPTOTOOL_IBACKEND_HPP

#include <vector>
#include <string>
#include <expected>
#include <memory>
#include "../CryptoError.hpp"

namespace nk::backend {

/**
 * 認証付き暗号 (AEAD) バックエンド インターフェース
 */
class IAeadBackend {
public:
    virtual ~IAeadBackend() = default;
    virtual std::expected<size_t, CryptoError> update(const uint8_t* in, size_t in_len, uint8_t* out) = 0;
    virtual std::expected<size_t, CryptoError> finalize(uint8_t* out) = 0;
    virtual std::expected<void, CryptoError> getTag(uint8_t* tag, size_t tag_len) = 0;
    virtual std::expected<void, CryptoError> setTag(const uint8_t* tag, size_t tag_len) = 0;
};

/**
 * ハッシュ・署名バックエンド インターフェース
 */
class IHashBackend {
public:
    virtual ~IHashBackend() = default;
    virtual std::expected<void, CryptoError> update(const uint8_t* data, size_t len) = 0;
    virtual std::expected<void, CryptoError> initSign(const std::vector<uint8_t>& priv_key_der) = 0;
    virtual std::expected<std::vector<uint8_t>, CryptoError> finalizeSign() = 0;
    virtual std::expected<void, CryptoError> initVerify(const std::vector<uint8_t>& pub_key_der) = 0;
    virtual std::expected<bool, CryptoError> finalizeVerify(const std::vector<uint8_t>& signature) = 0;
};

/**
 * 抽象暗号バックエンド インターフェース
 */
class ICryptoBackend {
public:
    virtual ~ICryptoBackend() = default;

    // AEAD 関連
    virtual std::expected<std::unique_ptr<IAeadBackend>, CryptoError> createAead(const std::string& cipher_name, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt) = 0;

    // ハッシュ・署名関連
    virtual std::expected<std::unique_ptr<IHashBackend>, CryptoError> createHash(const std::string& algo_name) = 0;

    // ECC 関連
    virtual std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> generateEccKeyPair(const std::string& curve_name) = 0;
    virtual std::expected<std::vector<uint8_t>, CryptoError> eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der) = 0;
    virtual std::expected<std::vector<uint8_t>, CryptoError> extractPublicKey(const std::vector<uint8_t>& priv_der) = 0;

    // PQC 関連
    virtual std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> generatePqcSignKeyPair(const std::string& algo_name) = 0;
    virtual std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> pqcEncap(const std::vector<uint8_t>& pub_key_der) = 0;
    virtual std::expected<std::vector<uint8_t>, CryptoError> pqcDecap(const std::vector<uint8_t>& priv_key_der, const std::vector<uint8_t>& kem_ct) = 0;

    // 鍵導出
    virtual std::vector<uint8_t> hkdf(const std::vector<uint8_t>& secret, size_t out_len, const std::vector<uint8_t>& salt, const std::string& info, const std::string& md_name) = 0;

    // ユーティリティ
    virtual std::expected<void, CryptoError> randomBytes(uint8_t* out, size_t len) = 0;
    virtual void cleanse(void* ptr, size_t len) = 0;

    // Base64 エンコード/デコード
    virtual std::string base64Encode(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> base64Decode(const std::string& base64_str) = 0;
};

} // namespace nk::backend

// 現在のビルド構成で最適なバックエンドを取得する (GLOBAL)
std::shared_ptr<nk::backend::ICryptoBackend> get_nk_backend();

#endif // NKCRYPTOTOOL_IBACKEND_HPP
