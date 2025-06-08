// nkCryptoToolBase.hpp

#ifndef NKCRYPTOTOOLBASE_HPP
#define NKCRYPTOTOOLBASE_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <filesystem>
#include <functional>
#include <system_error>
#include <memory>
#include <asio.hpp>
#include <asio/stream_file.hpp>
#include <asio/buffer.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>

// Forward declaration for Asio
namespace asio {
class io_context;
}

// --- OpenSSL Custom Deleters ---
struct EVP_PKEY_Deleter { void operator()(EVP_PKEY *p) const; };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX *p) const; };
struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX *p) const; };
struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX *p) const; };
struct BIO_Deleter { void operator()(BIO *b) const; };
struct EVP_KDF_Deleter { void operator()(EVP_KDF *p) const; };
struct EVP_KDF_CTX_Deleter { void operator()(EVP_KDF_CTX *p) const; };

class nkCryptoToolBase {
private:
    std::filesystem::path key_base_directory;

protected:
    // --- Constants ---
    static constexpr int CHUNK_SIZE = 4096;
    static constexpr int GCM_IV_LEN = 12;
    static constexpr int GCM_TAG_LEN = 16;

    // --- Common Helper Functions ---
    void printOpenSSLErrors();
    void printProgress(double percentage);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> loadPublicKey(const std::filesystem::path& public_key_path);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> loadPrivateKey(const std::filesystem::path& private_key_path);
    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                          const std::string& salt, const std::string& info,
                                          const std::string& digest_algo);

    // --- Base State for Asynchronous Operations ---
    struct AsyncStateBase {
        asio::stream_file input_file;
        asio::stream_file output_file;
        std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> cipher_ctx;
        std::vector<unsigned char> input_buffer;
        std::vector<unsigned char> output_buffer;
        std::vector<unsigned char> tag;
        size_t bytes_read;
        uintmax_t total_bytes_processed;
        std::function<void(std::error_code)> completion_handler;

        AsyncStateBase(asio::io_context& io_context);
        virtual ~AsyncStateBase() = default;
    };


public:
    nkCryptoToolBase();
    virtual ~nkCryptoToolBase();

    void setKeyBaseDirectory(const std::filesystem::path& dir);
    std::filesystem::path getKeyBaseDirectory() const;

    // --- Pure Virtual Functions for Derived Classes ---
    virtual bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;

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
        const std::filesystem::path& sender_public_key_path,
        std::function<void(std::error_code)> completion_handler) = 0;

    virtual void decryptFileHybrid(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_private_key_path,
        const std::filesystem::path& recipient_ecdh_private_key_path,
        std::function<void(std::error_code)> completion_handler) = 0;

    virtual void signFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& signature_filepath,
        const std::filesystem::path& signing_private_key_path,
        const std::string& digest_algo,
        std::function<void(std::error_code)> completion_handler) = 0;

    virtual void verifySignature(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& signature_filepath,
        const std::filesystem::path& signing_public_key_path,
        std::function<void(std::error_code, bool)> completion_handler) = 0;

    virtual std::filesystem::path getEncryptionPrivateKeyPath() const = 0;
    virtual std::filesystem::path getSigningPrivateKeyPath() const = 0;
    virtual std::filesystem::path getEncryptionPublicKeyPath() const = 0;
    virtual std::filesystem::path getSigningPublicKeyPath() const = 0;
};

#endif
