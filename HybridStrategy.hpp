#ifndef HYBRID_STRATEGY_HPP
#define HYBRID_STRATEGY_HPP

#include "ICryptoStrategy.hpp"
#include "ECCStrategy.hpp"
#include "PQCStrategy.hpp"
#include <memory>
#include <vector>
#include <string>
#include <map>
#include <expected>

namespace nk {

class HybridStrategy : public ICryptoStrategy {
public:
    HybridStrategy();
    ~HybridStrategy() override;

    StrategyType getStrategyType() const override { return StrategyType::Hybrid; }

    void setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider) override {
        if (ecc_strategy_) ecc_strategy_->setKeyProvider(provider);
        if (pqc_strategy_) pqc_strategy_->setKeyProvider(provider);
    }

    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) override;
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) override;
    std::expected<void, CryptoError> regeneratePublicKey(const std::filesystem::path& priv_path, const std::filesystem::path& pub_path, SecureString& passphrase) override;

    std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>& key_paths) override;
    std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) override;
    std::vector<char> encryptTransform(const std::vector<char>& data) override;
    std::vector<char> decryptTransform(const std::vector<char>& data) override;
    std::expected<void, CryptoError> finalizeEncryption(std::vector<char>& out_final) override;
    std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>& tag) override;

    std::expected<void, CryptoError> prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) override;
    std::expected<void, CryptoError> prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) override;
    void updateHash(const std::vector<char>& data) override;
    std::expected<std::vector<char>, CryptoError> signHash() override;
    std::expected<bool, CryptoError> verifyHash(const std::vector<char>& signature) override;

    std::vector<char> serializeSignatureHeader() const override;
    std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>& data) override;

    std::map<std::string, std::string> getMetadata(const std::string& magic = "") const override;
    size_t getHeaderSize() const override;
    std::vector<char> serializeHeader() const override;
    std::expected<size_t, CryptoError> deserializeHeader(const std::vector<char>& data) override;
    size_t getTagSize() const override;

private:
    std::unique_ptr<nk::ECCStrategy> ecc_strategy_;
    std::unique_ptr<PQCStrategy> pqc_strategy_;
    std::unique_ptr<nk::backend::IAeadBackend> aead_ctx_;
    std::vector<unsigned char> encryption_key_;
    std::vector<unsigned char> iv_;
};

} // namespace nk

#endif // HYBRID_STRATEGY_HPP
