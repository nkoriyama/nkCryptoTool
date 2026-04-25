#ifndef I_KEY_PROVIDER_HPP
#define I_KEY_PROVIDER_HPP

#include <expected>
#include <memory>
#include <string>
#include <vector>
#include "SecureMemory.hpp"
#include "CryptoError.hpp"

namespace nk {

/**
 * 鍵保護プロバイダーのインターフェース
 */
class IKeyProvider {
public:
    virtual ~IKeyProvider() = default;

    /**
     * 秘密鍵をラップする
     * @param der_key ラップ対象の秘密鍵 (DER形式)
     */
    virtual std::expected<SecureString, CryptoError> wrapKey(const std::vector<uint8_t>& der_key, const SecureString& passphrase = "") = 0;
    
    /**
     * ラップされた鍵をアンラップする
     * @return 復元された秘密鍵 (DER形式)
     */
    virtual std::expected<std::vector<uint8_t>, CryptoError> unwrapKey(const SecureString& wrapped_pem, const SecureString& passphrase = "") = 0;
    
    virtual bool isAvailable() = 0;
};

} // namespace nk

#endif // I_KEY_PROVIDER_HPP
