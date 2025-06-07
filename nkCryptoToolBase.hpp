// nkCryptoToolBase.hpp

#ifndef NKCRYPTOTOOLBASE_HPP
#define NKCRYPTOTOOLBASE_HPP

#include <string>
#include <vector>
#include <stdexcept> // For std::runtime_error
#include <filesystem> // For std::filesystem::path
#include <functional> // For std::function
#include <system_error> // For std::error_code

// Forward declaration for Asio
namespace asio {
class io_context;
}

class nkCryptoToolBase {
private:
    std::filesystem::path key_base_directory; // Now non-static

protected:
    // Helper function to read file content into a vector of bytes (still synchronous, used by other non-async methods)
    std::vector<unsigned char> readFile(const std::filesystem::path& filepath);

    // Helper function to write content from a vector of bytes to a file (still synchronous, used by other non-async methods)
    bool writeFile(const std::filesystem::path& filepath, const std::vector<unsigned char>& data);

public:
    nkCryptoToolBase();
    virtual ~nkCryptoToolBase();

    // Non-static method to set the base directory for keys
    void setKeyBaseDirectory(const std::filesystem::path& dir);
    // Non-static method to get the base directory for keys
    std::filesystem::path getKeyBaseDirectory() const;

    // Key generation methods (virtual for specific implementations) - These can remain synchronous for now
    virtual bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;

    // Asynchronous Encryption/Decryption methods (virtual for specific implementations)
    // Now takes io_context and a completion handler
    virtual void encryptFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_public_key_path,
        std::function<void(std::error_code)> completion_handler) = 0;

    virtual void encryptFileHybrid(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_public_key_path,
        const std::filesystem::path& recipient_ecdh_public_key_path,
        std::function<void(std::error_code)> completion_handler) = 0;

    virtual void decryptFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& user_private_key_path,
        // sender_public_key_path is now redundant for ECC decryption as ephemeral key is in file header,
        // but kept for virtual method compatibility.
        const std::filesystem::path& sender_public_key_path, 
        std::function<void(std::error_code)> completion_handler) = 0;

    virtual void decryptFileHybrid(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_private_key_path,
        const std::filesystem::path& recipient_ecdh_private_key_path,
        std::function<void(std::error_code)> completion_handler) = 0;

    // Signing/Verification methods (virtual for specific implementations) - Can remain synchronous
    virtual bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) = 0;
    virtual bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) = 0;

    // Virtual methods for getting default key paths (used in main for key generation)
    virtual std::filesystem::path getEncryptionPrivateKeyPath() const = 0;
    virtual std::filesystem::path getSigningPrivateKeyPath() const = 0;
    virtual std::filesystem::path getEncryptionPublicKeyPath() const = 0;
    virtual std::filesystem::path getSigningPublicKeyPath() const = 0;
};

#endif
