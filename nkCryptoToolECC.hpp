// nkCryptoToolECC.hpp

#ifndef NKCRYPTOTOOL_ECC_HPP
#define NKCRYPTOTOOL_ECC_HPP

#include "nkCryptoToolBase.hpp"
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <asio/awaitable.hpp> // asio::awaitable を使うために必要


class nkCryptoToolECC : public nkCryptoToolBase {
private:
    std::vector<unsigned char> generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);
    struct SigningState;
    struct VerificationState;
    void handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishSigning(std::shared_ptr<SigningState> state);
    void handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred);
    void finishVerification(std::shared_ptr<VerificationState> state);

public:
    nkCryptoToolECC();
    virtual ~nkCryptoToolECC();

    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    void encryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) override;
    void decryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;
    
    void encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) override;
    void decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;

    void signFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::string&, std::function<void(std::error_code)>) override;
    void verifySignature(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code, bool)>) override;

    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;

        // --- 【新規追加】C++20コルーチンベースの並列処理インターフェース ---
    /**
     * @brief ファイルを並列に暗号化する
     * @param worker_context CPUバウンドな処理を実行するワーカースレッドのio_context
     * @param input_filepath 入力ファイルパス
     * @param output_filepath 出力ファイルパス
     * @param recipient_public_key_path 受信者の公開鍵パス
     * @param algo 使用する圧縮アルゴリズム
     * @return asio::awaitable<void> 完了を待機可能なタスク
     */
    asio::awaitable<void> encryptFileParallel(
        asio::io_context& worker_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_public_key_path,
        CompressionAlgorithm algo
    ) override;

    /**
     * @brief ファイルを並列に復号する
     * @param worker_context CPUバウンドな処理を実行するワーカースレッドのio_context
     * @param input_filepath 入力ファイルパス
     * @param output_filepath 出力ファイルパス
     * @param user_private_key_path 自身の秘密鍵パス
     * @return asio::awaitable<void> 完了を待機可能なタスク
     */
    asio::awaitable<void> decryptFileParallel(
        asio::io_context& worker_context,
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& user_private_key_path
    ) override;
};

#endif
