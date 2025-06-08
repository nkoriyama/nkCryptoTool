// nkCryptoToolPQC.hpp

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/provider.h>
#include <memory>
#include <functional>
#include <asio.hpp>
#include <asio/stream_file.hpp>
#include <asio/buffer.hpp>

class nkCryptoToolPQC : public nkCryptoToolBase {
private:
    void printOpenSSLErrors();
    void printProgress(double percentage); // Progress bar helper
    EVP_PKEY* loadPublicKey(const std::filesystem::path& public_key_path);
    EVP_PKEY* loadPrivateKey(const std::filesystem::path& private_key_path);
    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                          const std::string& salt, const std::string& info,
                                          const std::string& digest_algo);
    bool aesGcmEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext,
                       std::vector<unsigned char>& tag);
    bool aesGcmDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag,
                       std::vector<unsigned char>& plaintext);

    enum { CHUNK_SIZE = 4096 };
    enum { GCM_IV_LEN = 12 };
    enum { GCM_TAG_LEN = 16 };

    struct EncryptionState : std::enable_shared_from_this<EncryptionState> {
        asio::stream_file input_file;
        asio::stream_file output_file;
        std::vector<unsigned char> encryption_key;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> salt;
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx;
        std::vector<unsigned char> input_buffer;
        std::vector<unsigned char> output_buffer;
        std::vector<unsigned char> tag;
        size_t bytes_read;
        std::function<void(std::error_code)> completion_handler;
        std::vector<unsigned char> kem_ciphertext;
        std::vector<unsigned char> ecdh_sender_pub_key;
        std::vector<std::shared_ptr<uint32_t>> len_storage;
        uintmax_t total_input_size;
        uintmax_t total_bytes_processed;

        EncryptionState(asio::io_context& io_context)
            : input_file(io_context),
              output_file(io_context),
              cipher_ctx(nullptr, EVP_CIPHER_CTX_free),
              input_buffer(CHUNK_SIZE),
              output_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH),
              tag(GCM_TAG_LEN),
              bytes_read(0),
              total_input_size(0),
              total_bytes_processed(0) {}
    };

    void startPQCEncryptionAsync(std::shared_ptr<EncryptionState> state,
                                 const std::filesystem::path& input_filepath,
                                 const std::filesystem::path& output_filepath,
                                 EVP_PKEY* recipient_kem_public_key,
                                 EVP_PKEY* recipient_ecdh_public_key);
    void write_header(std::shared_ptr<EncryptionState> state, bool is_hybrid, std::function<void(const asio::error_code&)> on_all_written);
    void write_salt_and_iv(std::shared_ptr<EncryptionState> state, std::function<void(const asio::error_code&)> on_complete);
    void handleFileReadForPQCEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterPQCEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishPQCEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec);

    struct DecryptionState : std::enable_shared_from_this<DecryptionState> {
        asio::stream_file input_file;
        asio::stream_file output_file;
        std::vector<unsigned char> decryption_key;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> salt;
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx;
        std::vector<unsigned char> input_buffer;
        std::vector<unsigned char> output_buffer;
        std::vector<unsigned char> tag;
        size_t bytes_read;
        std::function<void(std::error_code)> completion_handler;
        std::filesystem::path input_filepath_orig;
        std::vector<unsigned char> kem_ciphertext_read;
        std::vector<unsigned char> ecdh_sender_pub_key_read;
        uintmax_t total_ciphertext_size;
        uintmax_t total_bytes_processed;

        DecryptionState(asio::io_context& io_context, const std::filesystem::path& input_path_orig)
            : input_file(io_context),
              output_file(io_context),
              cipher_ctx(nullptr, EVP_CIPHER_CTX_free),
              input_buffer(CHUNK_SIZE),
              output_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH),
              tag(GCM_TAG_LEN),
              bytes_read(0),
              input_filepath_orig(input_path_orig),
              total_ciphertext_size(0),
              total_bytes_processed(0) {}
    };

    void startPQCDecryptionAsync(std::shared_ptr<DecryptionState> state,
                                 const std::filesystem::path& input_filepath,
                                 const std::filesystem::path& output_filepath,
                                 EVP_PKEY* user_kem_private_key,
                                 EVP_PKEY* user_ecdh_private_key);
    void handleFileReadForPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);

public:
    nkCryptoToolPQC();
    ~nkCryptoToolPQC();

    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

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
        const std::filesystem::path& sender_public_key_path_unused,
        std::function<void(std::error_code)> completion_handler) override;

    void decryptFileHybrid(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_private_key_path,
        const std::filesystem::path& recipient_ecdh_private_key_path,
        std::function<void(std::error_code)> completion_handler) override;

    bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) override;
    bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) override;

    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOLPQC_HPP