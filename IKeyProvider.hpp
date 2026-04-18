#ifndef I_KEY_PROVIDER_HPP
#define I_KEY_PROVIDER_HPP

#include <expected>
#include <memory>
#include <string>
#include <openssl/evp.h>
#include "SecureMemory.hpp"
#include "CryptoError.hpp"
#include "OpenSSLDeleters.hpp"

namespace nk {

/**
 * 鍵保護プロバイダーのインターフェース
 */
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;

    virtual std::expected<SecureString, CryptoError> wrapKey(EVP_PKEY* pkey, const SecureString& passphrase = "") = 0;
    virtual std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> unwrapKey(const SecureString& wrapped_pem, const SecureString& passphrase = "") = 0;
    virtual bool isAvailable() = 0;
};

} // namespace nk

#endif // I_KEY_PROVIDER_HPP
