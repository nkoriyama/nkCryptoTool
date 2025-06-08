// nkCryptoToolECC.hpp

#ifndef NKCRYPTOTOOL_ECC_HPP
#define NKCRYPTOTOOL_ECC_HPP

#include "nkCryptoToolBase.hpp"
#include <openssl/ec.h>
#include <openssl/rand.h>

class nkCryptoToolECC : public nkCryptoToolBase {
private:
    std::vector<unsigned char> generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);

    // --- State structures for async operations ---
    struct EncryptionState : public AsyncStateBase, public std::enable_shared_from_this<EncryptionState> {
        std::vector<unsigned char> encryption_key;
        std::vector<unsigned char> iv;
        uintmax_t total_input_size;

        EncryptionState(asio::io_context& io_context)
            : AsyncStateBase(io_context), total_input_size(0) {
            iv.resize(GCM_IV_LEN);
        }
    };

    void handleFileReadForEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec);

    struct DecryptionState : public AsyncStateBase, public std::enable_shared_from_this<DecryptionState> {
        std::vector<unsigned char> shared_secret;
        std::vector<unsigned char> decryption_key;
        std::vector<unsigned char> iv;
        std::filesystem::path input_filepath_orig;
        uint32_t ephemeral_key_len;
        uintmax_t total_ciphertext_size;

        DecryptionState(asio::io_context& io_context, const std::filesystem::path& input_path_orig)
            : AsyncStateBase(io_context),
              input_filepath_orig(input_path_orig),
              ephemeral_key_len(0),
              total_ciphertext_size(0) {}
    };

    void handleFileReadForDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void handleFileWriteAfterDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec);

    // --- State structures for async signing/verification ---
    struct SigningState : public AsyncStateBase, public std::enable_shared_from_this<SigningState> {
        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx;
        uintmax_t total_input_size;

        SigningState(asio::io_context& io_context)
            : AsyncStateBase(io_context), md_ctx(EVP_MD_CTX_new()), total_input_size(0) {}
    };

    void handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishSigning(std::shared_ptr<SigningState> state);

    struct VerificationState : public AsyncStateBase, public std::enable_shared_from_this<VerificationState> {
        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx;
        asio::stream_file signature_file;
        std::vector<unsigned char> signature;
        uintmax_t total_input_size;
        std::function<void(std::error_code, bool)> verification_completion_handler; // bool for result

        VerificationState(asio::io_context& io_context)
            : AsyncStateBase(io_context),
              md_ctx(EVP_MD_CTX_new()),
              signature_file(io_context),
              total_input_size(0) {}
    };

    void handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishVerification(std::shared_ptr<VerificationState> state);

public:
    nkCryptoToolECC();
    virtual ~nkCryptoToolECC();

    // --- Override virtual functions ---
    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    void encryptFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_public_key_path,
        std::function<void(std::error_code)> completion_handler) override;

    void decryptFile(
        asio::io_context& io_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& user_private_key_path,
        const std::filesystem::path& sender_public_key_path,
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


    // --- Hybrid methods (not implemented for pure ECC) ---
    void encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;
    void decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;

    // --- Key path getters ---
    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOL_ECC_HPP
