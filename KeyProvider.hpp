#ifndef KEY_PROVIDER_HPP
#define KEY_PROVIDER_HPP

#include "IKeyProvider.hpp"

namespace nk {

/**
 * 鍵保護操作のフロントエンドクラス。
 * 具象的な実装（TPM等）をラップし、統一されたインターフェースを提供する。
 */
class KeyProvider {
public:
    KeyProvider() = default;

    /**
     * プロバイダー（TPM実装など）を設定する
     */
    void set(std::shared_ptr<IKeyProvider> provider) {
        provider_ = std::move(provider);
    }

    /**
     * 秘密鍵をラップする
     */
    std::expected<SecureString, CryptoError> wrap(EVP_PKEY* pkey, const SecureString& passphrase = "") {
        if (!provider_) return std::unexpected(CryptoError::ProviderNotAvailable);
        return provider_->wrapKey(pkey, passphrase);
    }

    /**
     * ラップされた鍵をアンラップする
     */
    std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> unwrap(const SecureString& wrapped_pem, const SecureString& passphrase = "") {
        if (!provider_) return std::unexpected(CryptoError::ProviderNotAvailable);
        return provider_->unwrapKey(wrapped_pem, passphrase);
    }

    /**
     * プロバイダーが利用可能かチェックする
     */
    bool isAvailable() const {
        return provider_ && provider_->isAvailable();
    }

private:
    std::shared_ptr<IKeyProvider> provider_;
};

} // namespace nk

#endif // KEY_PROVIDER_HPP
