#ifndef PQC_STRATEGY_HPP
#define PQC_STRATEGY_HPP

#include "ICryptoStrategy.hpp"
#include <openssl/evp.h>
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <expected>
#include <filesystem>

class PQCStrategy : public ICryptoStrategy {
public:
    PQCStrategy();
    ~PQCStrategy() override;

    // 鍵生成
    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) override;
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) override;

    // パイプライン・トランスフォーマー
    std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>& key_paths) override;
    std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>& key_paths, std::string& passphrase) override;
    std::vector<char> encryptTransform(const std::vector<char>& data) override;
    std::vector<char> decryptTransform(const std::vector<char>& data) override;
    std::expected<void, CryptoError> finalizeEncryption(std::vector<char>& out_final) override;
    std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>& tag) override;

    // 署名・検証
    std::expected<void, CryptoError> prepareSigning(const std::filesystem::path& priv_key_path, std::string& passphrase, const std::string& digest_algo) override;
    std::expected<void, CryptoError> prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) override;
    void updateHash(const std::vector<char>& data) override;
    std::expected<std::vector<char>, CryptoError> signHash() override;
    std::expected<bool, CryptoError> verifyHash(const std::vector<char>& signature) override;

    // ヘッダー情報
    size_t getHeaderSize() const override;
    std::vector<char> serializeHeader() const override;
    std::expected<void, CryptoError> deserializeHeader(const std::vector<char>& data) override;
    size_t getTagSize() const override;

    // ハイブリッド連携用
    std::vector<unsigned char> getEncapsulatedKey() const { return encapsulated_key_; }
    void setEncapsulatedKey(const std::vector<unsigned char>& key) { encapsulated_key_ = key; }
    std::vector<unsigned char> getSalt() const { return salt_; }
    void setSalt(const std::vector<unsigned char>& s) { salt_ = s; }
    std::vector<unsigned char> getIV() const { return iv_; }
    void setIV(const std::vector<unsigned char>& i) { iv_ = i; }
    std::vector<unsigned char> getSharedSecret() const { return shared_secret_; }

private:
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> cipher_ctx_;
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx_;
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sign_key_;
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> verify_key_;
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> encryption_priv_key_;
    std::vector<unsigned char> encryption_key_;
    std::vector<unsigned char> iv_;
    std::vector<unsigned char> salt_;
    std::vector<unsigned char> encapsulated_key_;
    std::vector<unsigned char> shared_secret_;
    std::vector<unsigned char> decrypt_buffer_; // 末尾タグを保持するためのバッファ
    std::vector<char> message_buffer_; // 署名・検証用のメッセージ蓄積バッファ
};

#endif // PQC_STRATEGY_HPP
