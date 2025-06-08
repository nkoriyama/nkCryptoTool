// nkCryptoToolPQC.hpp (Refactored)

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"
#include <openssl/provider.h>

class nkCryptoToolPQC : public nkCryptoToolBase {
private:
    // --- State structures for async operations ---
    struct EncryptionState : public AsyncStateBase, public std::enable_shared_from_this<EncryptionState> {
        std::vector<unsigned char> encryption_key;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> salt;
        std::vector<unsigned char> kem_ciphertext;
        std::vector<unsigned char> ecdh_sender_pub_key; // For hybrid
        std::vector<std::shared_ptr<uint32_t>> len_storage;
        uintmax_t total_input_size;

        EncryptionState(asio::io_context& io_context)
            : AsyncStateBase(io_context), total_input_size(0) {
                iv.resize(GCM_IV_LEN);
                salt.resize(16); // Default salt size
            }
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

    struct DecryptionState : public AsyncStateBase, public std::enable_shared_from_this<DecryptionState> {
        std::vector<unsigned char> decryption_key;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> salt;
        std::filesystem::path input_filepath_orig;
        std::vector<unsigned char> kem_ciphertext_read;
        std::vector<unsigned char> ecdh_sender_pub_key_read; // For hybrid
        uintmax_t total_ciphertext_size;

        DecryptionState(asio::io_context& io_context, const std::filesystem::path& input_path_orig)
            : AsyncStateBase(io_context),
              input_filepath_orig(input_path_orig),
              total_ciphertext_size(0) {}
    };

    void startPQCDecryptionAsync(std::shared_ptr<DecryptionState> state,
                                 const std::filesystem::path& input_filepath,
                                 const std::filesystem::path& output_filepath,
                                 EVP_PKEY* user_kem_private_key,
                                 EVP_PKEY* user_ecdh_private_key);
    void handleFileReadForPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec);

    // --- State for PQC one-shot signing/verification ---
    // Note: PQC signing reads the whole file due to OpenSSL API limitations for streaming ML-DSA.
    struct SigningState : public std::enable_shared_from_this<SigningState> {
        asio::stream_file input_file;
        asio::stream_file output_file;
        std::vector<unsigned char> file_content;
        std::function<void(std::error_code)> completion_handler;

        SigningState(asio::io_context& io_context)
            : input_file(io_context), output_file(io_context) {}
    };
    
    struct VerificationState : public std::enable_shared_from_this<VerificationState> {
        asio::stream_file input_file;
        asio::stream_file signature_file;
        std::vector<unsigned char> file_content;
        std::vector<unsigned char> signature;
        std::function<void(std::error_code, bool)> verification_completion_handler;

        VerificationState(asio::io_context& io_context)
            : input_file(io_context), signature_file(io_context) {}
    };
    
public:
    nkCryptoToolPQC();
    ~nkCryptoToolPQC();

    // --- Override virtual functions ---
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

    void signFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& signature_filepath,
        const std::filesystem::path& signing_private_key_path,
        const std::string& digest_algo,
        std::function<void(std::error_code)> completion_handler) override;

    void verifySignature(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& signature_filepath,
        const std::filesystem::path& signing_public_key_path,
        std::function<void(std::error_code, bool)> completion_handler) override;

    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOLPQC_HPP
