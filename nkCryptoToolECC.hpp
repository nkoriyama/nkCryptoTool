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


class nkCryptoToolECC : public nkCryptoToolBase {
private:
    // Helper function to print OpenSSL errors
    void printOpenSSLErrors();

    // Helper function to load public key
    EVP_PKEY* loadPublicKey(const std::string& public_key_path);

    // Helper function to load private key
    EVP_PKEY* loadPrivateKey(const std::string& private_key_path);

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

#endif // NKCRYPTOTOOLECC_HPP
