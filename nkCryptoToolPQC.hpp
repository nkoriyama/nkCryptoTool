// nkCryptoToolPQC.hpp

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"
#include <string>
#include <vector>
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
    EVP_PKEY* loadPublicKey(const std::string& public_key_path);
    EVP_PKEY* loadPrivateKey(const std::string& private_key_path);

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
    bool generateEncryptionKeyPair(const std::string& public_key_path, const std::string& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::string& public_key_path, const std::string& private_key_path, const std::string& passphrase) override;

    // Override encryption/decryption methods
    bool encryptFile(const std::string& input_filepath, const std::string& output_filepath, const std::string& recipient_public_key_path) override;
    bool decryptFile(const std::string& input_filepath, const std::string& output_filepath, const std::string& user_private_key_path, const std::string& sender_public_key_path) override;

    // Override signing/verification methods
    bool signFile(const std::string& input_filepath, const std::string& signature_filepath, const std::string& signing_private_key_path, const std::string& digest_algo) override;
    bool verifySignature(const std::string& input_filepath, const std::string& signature_filepath, const std::string& signing_public_key_path) override;

    // Override methods for default key paths
    std::string getEncryptionPrivateKeyPath() const override;
    std::string getSigningPrivateKeyPath() const override;
    std::string getEncryptionPublicKeyPath() const override;
    std::string getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOLPQC_HPP
