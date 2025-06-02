// nkCryptoToolPQC.hpp

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/evp.h> // Required for EVP_PKEY and other OpenSSL types
#include <openssl/bio.h> // Required for BIO

// Forward declarations for OpenSSL PQC types if needed,
// though generally PQC algorithms are integrated through EVP_PKEY
// and EVP_CIPHER/EVP_MD.

// Custom deleters for OpenSSL unique_ptr (forward declarations if needed, but better in .cpp)
// These are typically defined in the .cpp where they are used, or in a common utility header.
// For now, they are kept in .cpp to avoid header dependencies if not strictly necessary here.

class nkCryptoToolPQC : public nkCryptoToolBase {
private:
    // Helper function to print OpenSSL errors (if using OpenSSL for PQC primitives)
    void printOpenSSLErrors();

    // Helper functions for PQC operations, moved from nkCryptoToolECC.hpp as they are common utilities
    EVP_PKEY* loadPublicKey(const std::filesystem::path& public_key_path);
    EVP_PKEY* loadPrivateKey(const std::filesystem::path& private_key_path);

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
    nkCryptoToolPQC();
    ~nkCryptoToolPQC();

    // Override key generation methods
    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override; // Make sure this matches the base class exactly
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    // Override encryption/decryption methods
    bool encryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path) override;
    bool encryptFileHybrid(
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_public_key_path,
        const std::filesystem::path& recipient_ecdh_public_key_path) override;
    bool decryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) override;
    bool decryptFileHybrid(
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_private_key_path,
        const std::filesystem::path& recipient_ecdh_private_key_path) override;
    // Override signing/verification methods
    bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) override;
    bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) override;

    // Override methods for default key paths
    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOLPQC_HPP
