// nkCryptoToolECC.hpp

#ifndef NKCRYPTOTOOLECC_HPP
#define NKCRYPTOTOOLECC_HPP

#include "nkCryptoToolBase.hpp"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <vector> // For std::vector
#include <string> // For std::string
#include <filesystem> // For std::filesystem::path


class nkCryptoToolECC : public nkCryptoToolBase {
private:
    // Helper function to print OpenSSL errors
    void printOpenSSLErrors();

    // Helper function to load public key
    EVP_PKEY* loadPublicKey(const std::filesystem::path& public_key_path);

    // Helper function to load private key
    EVP_PKEY* loadPrivateKey(const std::filesystem::path& private_key_path);

    // Helper function to generate a shared secret using ECDH
    std::vector<unsigned char> generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);

    // Helper function for HKDF derivation
    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                          const std::string& salt, const std::string& info,
                                          const std::string& digest_algo);

    // Helper function for AES-GCM encryption/decryption
    bool aesGcmEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext,
                       std::vector<unsigned char>& tag);
    bool aesGcmDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag,
                       std::vector<unsigned char>& plaintext);

public:
    nkCryptoToolECC();
    ~nkCryptoToolECC();

    // Override key generation methods
    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    // Override encryption/decryption methods
    bool encryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path) override;
    bool decryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) override;

    // Override signing/verification methods
    bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) override;
    bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) override;

    // Override methods for default key paths
    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOLECC_HPP
