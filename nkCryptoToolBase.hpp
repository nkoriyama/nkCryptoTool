// nkCryptoToolBase.hpp

#ifndef NKCRYPTOTOOLBASE_HPP
#define NKCRYPTOTOOLBASE_HPP

#include <string>
#include <vector>
#include <stdexcept> // For std::runtime_error
#include <filesystem> // For std::filesystem::path

class nkCryptoToolBase {
private:
    static std::filesystem::path key_base_directory;

protected:
    // Helper function to read file content into a vector of bytes
    std::vector<unsigned char> readFile(const std::filesystem::path& filepath);

    // Helper function to write content from a vector of bytes to a file
    bool writeFile(const std::filesystem::path& filepath, const std::vector<unsigned char>& data);

public:

    nkCryptoToolBase();
    virtual ~nkCryptoToolBase();

    // Static method to set the base directory for keys
    static void setKeyBaseDirectory(const std::filesystem::path& dir);
    // Static method to get the base directory for keys
    static std::filesystem::path getKeyBaseDirectory();

    // Key generation methods (virtual for specific implementations)
    virtual bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;

    // Encryption/Decryption methods (virtual for specific implementations)
    virtual bool encryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path) = 0;
    virtual bool decryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) = 0;

    // Signing/Verification methods (virtual for specific implementations)
    virtual bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) = 0;
    virtual bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) = 0;

    // Virtual methods for getting default key paths (used in main for key generation)
    // These are marked 'override' in derived classes
    virtual std::filesystem::path getEncryptionPrivateKeyPath() const = 0;
    virtual std::filesystem::path getSigningPrivateKeyPath() const = 0;
    virtual std::filesystem::path getEncryptionPublicKeyPath() const = 0;
    virtual std::filesystem::path getSigningPublicKeyPath() const = 0;
};

#endif // NKCRYPTOTOOLBASE_HPP
