// nkCryptoToolPQC.hpp

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"

class nkCryptoToolPQC : public nkCryptoToolBase {
private:
    struct SigningState;
    struct VerificationState;

public:
    nkCryptoToolPQC();
    ~nkCryptoToolPQC();

    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    void encryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) override;
    void encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) override;
    void decryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;
    void decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) override;

    void signFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::string&, std::function<void(std::error_code)>) override;
    void verifySignature(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code, bool)>) override;

    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;

    // --- 並列処理インターフェース：引数を string に変更 ---
    asio::awaitable<void> encryptFileParallel(
        asio::io_context& worker_context,
        std::string input_filepath,
        std::string output_filepath,
        std::string recipient_public_key_path,
        CompressionAlgorithm algo
    ) override;

    asio::awaitable<void> decryptFileParallel(
        asio::io_context& worker_context,
        std::string input_filepath,
        std::string output_filepath,
        std::string user_private_key_path
    ) override;

    // --- ★ 新しいパイプライン処理インターフェースの実装宣言 ---
    void encryptFileWithPipeline(
        asio::io_context& io_context,
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler
    ) override;

    void decryptFileWithPipeline(
        asio::io_context& io_context,
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler
    ) override;
};
#endif // NKCRYPTOTOOLPQC_HPP
