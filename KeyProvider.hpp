#ifndef KEY_PROVIDER_HPP
#define KEY_PROVIDER_HPP

#include "IKeyProvider.hpp"

namespace nk {

/**
 * 鍵保護操作のフロントエンドクラス。
 */
class KeyProvider {
public:
    KeyProvider() = default;

    void set(std::shared_ptr<IKeyProvider> provider) {
        provider_ = std::move(provider);
    }

    /**
     * 秘密鍵をラップする
     */
    std::expected<SecureString, CryptoError> wrap(const std::vector<uint8_t>& der_key, const SecureString& passphrase = "") {
        if (!provider_) return std::unexpected(CryptoError::ProviderNotAvailable);
        return provider_->wrapKey(der_key, passphrase);
    }

    /**
     * ラップされた鍵をアンラップする
     */
    std::expected<std::vector<uint8_t>, CryptoError> unwrap(const SecureString& wrapped_pem, const SecureString& passphrase = "") {
        if (!provider_) return std::unexpected(CryptoError::ProviderNotAvailable);
        return provider_->unwrapKey(wrapped_pem, passphrase);
    }

    bool isAvailable() const {
        return provider_ && provider_->isAvailable();
    }

private:
    std::shared_ptr<IKeyProvider> provider_;
};

/**
 * デフォルトの鍵プロバイダー（何もしない）
 */
class DefaultKeyProvider : public IKeyProvider {
public:
    std::expected<SecureString, CryptoError> wrapKey(const std::vector<uint8_t>&, const SecureString& = "") override {
        return std::unexpected(CryptoError::ProviderNotAvailable);
    }
    std::expected<std::vector<uint8_t>, CryptoError> unwrapKey(const SecureString&, const SecureString& = "") override {
        return std::unexpected(CryptoError::ProviderNotAvailable);
    }
    bool isAvailable() override { return false; }
};

} // namespace nk

#endif // KEY_PROVIDER_HPP
