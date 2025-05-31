// nkCryptoToolBase.hpp

#ifndef NKCRYPTOTOOLBASE_HPP
#define NKCRYPTOTOOLBASE_HPP

#include <string>
#include <vector>
#include <stdexcept> // For std::runtime_error
#include <filesystem> // For std::filesystem::path

// Platform-specific path separator
#if defined(_WIN32) || defined(__WIN32__) || defined(__MINGW32__)
const std::string PATH_SEPARATOR_CHAR = "\\";
#else
const std::string PATH_SEPARATOR_CHAR = "/";
#endif

class nkCryptoToolBase {
private:
    static std::string key_base_directory;

protected:
    // Helper function to read file content into a vector of bytes
    std::vector<unsigned char> readFile(const std::string& filepath);

    // Helper function to write content from a vector of bytes to a file
    bool writeFile(const std::string& filepath, const std::vector<unsigned char>& data);

public:
    static const std::string PATH_SEPARATOR; // Declared as static const

    nkCryptoToolBase();
    virtual ~nkCryptoToolBase();

    // Static method to set the base directory for keys
    static void setKeyBaseDirectory(const std::string& dir);
    // Static method to get the base directory for keys
    static std::string getKeyBaseDirectory();

    // Key generation methods (virtual for specific implementations)
    virtual bool generateEncryptionKeyPair(const std::string& public_key_path, const std::string& private_key_path, const std::string& passphrase) = 0;
    virtual bool generateSigningKeyPair(const std::string& public_key_path, const std::string& private_key_path, const std::string& passphrase) = 0;

    // Encryption/Decryption methods (virtual for specific implementations)
    virtual bool encryptFile(const std::string& input_filepath, const std::string& output_filepath, const std::string& recipient_public_key_path) = 0;
    virtual bool decryptFile(const std::string& input_filepath, const std::string& output_filepath, const std::string& user_private_key_path, const std::string& sender_public_key_path) = 0;

    // Signing/Verification methods (virtual for specific implementations)
    virtual bool signFile(const std::string& input_filepath, const std::string& signature_filepath, const std::string& signing_private_key_path, const std::string& digest_algo) = 0;
    virtual bool verifySignature(const std::string& input_filepath, const std::string& signature_filepath, const std::string& signing_public_key_path) = 0;

    // Virtual methods for getting default key paths (used in main for key generation)
    // These are marked 'override' in derived classes
    virtual std::string getEncryptionPrivateKeyPath() const = 0;
    virtual std::string getSigningPrivateKeyPath() const = 0;
    virtual std::string getEncryptionPublicKeyPath() const = 0;
    virtual std::string getSigningPublicKeyPath() const = 0;
};

#endif // NKCRYPTOTOOLBASE_HPP
