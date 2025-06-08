// nkCryptoToolECC.hpp

#ifndef NKCRYPTOTOOL_ECC_HPP
#define NKCRYPTOTOOL_ECC_HPP

#include "nkCryptoToolBase.hpp"
#include <openssl/ec.h>
#include <openssl/rand.h>

class nkCryptoToolECC : public nkCryptoToolBase {
private:
    std::vector<unsigned char> generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);
    struct SigningState;
    struct VerificationState;
    void handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishSigning(std::shared_ptr<SigningState> state);
    void handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishVerification(std::shared_ptr<VerificationState> state);

public:
    nkCryptoToolECC();
    virtual ~nkCryptoToolECC();

    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    void encryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) override;
    void decryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;
    
    void encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) override;
    void decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;

    void signFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::string&, std::function<void(std::error_code)>) override;
    void verifySignature(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code, bool)>) override;

    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif
