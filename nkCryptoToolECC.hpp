// nkCryptoToolECC.hpp

#ifndef NKCRYPTOTOOL_ECC_HPP
#define NKCRYPTOTOOL_ECC_HPP

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
#include <memory> // For std::unique_ptr
#include <functional> // For std::function
#include <asio.hpp> // Asio main header
#include <asio/stream_file.hpp> // For asio::stream_file
#include <asio/buffer.hpp> // For asio::buffer

// External callback for PEM passphrase
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);
extern std::string global_passphrase_for_pem_cb;

// Custom deleters for OpenSSL unique_ptr
struct EVP_PKEY_Deleter {
  void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};

struct EVP_PKEY_CTX_Deleter {
  void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
};

struct EVP_CIPHER_CTX_Deleter {
  void operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
};

struct EVP_MD_CTX_Deleter {
  void operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
};


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

    // AES-GCM specific helper for streaming
    enum { CHUNK_SIZE = 4096 }; // Define a chunk size for streaming
    enum { GCM_IV_LEN = 12 };   // GCM IV length
    enum { GCM_TAG_LEN = 16 };  // GCM Authentication Tag length

    // --- Asynchronous Encryption State Management ---
    struct EncryptionState : std::enable_shared_from_this<EncryptionState> {
        asio::stream_file input_file;
        asio::stream_file output_file;
        std::vector<unsigned char> shared_secret;
        std::vector<unsigned char> encryption_key;
        std::vector<unsigned char> iv;
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx;
        std::vector<unsigned char> input_buffer;
        std::vector<unsigned char> output_buffer;
        std::vector<unsigned char> tag; // GCM tag
        size_t bytes_read;
        size_t current_input_offset; // Not strictly used for async_read_some but for context
        std::function<void(std::error_code)> completion_handler;

        // Constructor
        EncryptionState(asio::io_context& io_context)
            : input_file(io_context),
              output_file(io_context),
              cipher_ctx(nullptr, EVP_CIPHER_CTX_free),
              input_buffer(CHUNK_SIZE),
              output_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH), // Output can be slightly larger than input
              tag(GCM_TAG_LEN),
              bytes_read(0),
              current_input_offset(0) {}
    };

    // Asynchronous encryption process helper functions
    void startEncryptionAsync(std::shared_ptr<EncryptionState> state,
                              const std::filesystem::path& input_filepath,
                              const std::filesystem::path& output_filepath,
                              EVP_PKEY* private_key, // Ephemeral private key for key exchange
                              EVP_PKEY* recipient_public_key); // Recipient's long-term public key

    void handleFileReadForEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec);

    // --- Asynchronous Decryption State Management ---
    struct DecryptionState : std::enable_shared_from_this<DecryptionState> {
        asio::stream_file input_file;
        asio::stream_file output_file;
        std::vector<unsigned char> shared_secret;
        std::vector<unsigned char> decryption_key;
        std::vector<unsigned char> iv;
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx;
        std::vector<unsigned char> input_buffer;
        std::vector<unsigned char> output_buffer;
        std::vector<unsigned char> tag; // GCM tag
        size_t bytes_read;
        size_t total_input_size;
        size_t current_input_offset; // Not strictly used for async_read_some but for context
        std::function<void(std::error_code)> completion_handler;
        std::filesystem::path input_filepath_orig; // Store the original path for std::filesystem::file_size

        // Constructor
        DecryptionState(asio::io_context& io_context, const std::filesystem::path& input_path_orig)
            : input_file(io_context),
              output_file(io_context),
              cipher_ctx(nullptr, EVP_CIPHER_CTX_free),
              input_buffer(CHUNK_SIZE),
              output_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH),
              tag(GCM_TAG_LEN),
              bytes_read(0),
              total_input_size(0),
              current_input_offset(0),
              input_filepath_orig(input_path_orig) {}
    };

    // Asynchronous decryption process helper functions
    void startDecryptionAsync(std::shared_ptr<DecryptionState> state,
                              const std::filesystem::path& input_filepath,
                              const std::filesystem::path& output_filepath,
                              EVP_PKEY* user_private_key); // User's long-term private key

    void handleFileReadForDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec);


public:
    nkCryptoToolECC();
    virtual ~nkCryptoToolECC();

        // 鍵生成メソッドをオーバーライド (同期のまま)
    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    // Override asynchronous encryption/decryption methods to match base class
    void encryptFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_public_key_path,
        std::function<void(std::error_code)> completion_handler) override;

     void encryptFileHybrid(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_public_key_path,
        const std::filesystem::path& recipient_ecdh_public_key_path,
        std::function<void(std::error_code)> completion_handler) override;

    void decryptFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& user_private_key_path,
        const std::filesystem::path& sender_public_key_path, // This is a placeholder, ephemeral key is read from file.
        std::function<void(std::error_code)> completion_handler) override;

    void decryptFileHybrid(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_private_key_path,
        const std::filesystem::path& recipient_ecdh_private_key_path,
        std::function<void(std::error_code)> completion_handler) override;

    // Override signing/verification methods (these can remain synchronous as they are not bottlenecked by file I/O on large scale)
    bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) override;
    bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) override;

    // Override methods for default key paths
    virtual std::filesystem::path getEncryptionPrivateKeyPath() const override;
    virtual std::filesystem::path getSigningPrivateKeyPath() const override;
    virtual std::filesystem::path getEncryptionPublicKeyPath() const override;
    virtual std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOL_ECC_HPP
