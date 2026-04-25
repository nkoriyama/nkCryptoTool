/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef NKCRYPTOTOOL_BASE_HPP
#define NKCRYPTOTOOL_BASE_HPP

#include <vector>
#include <string>
#include <map>
#include <functional>
#include <system_error>
#include <filesystem>
#include "ICryptoStrategy.hpp"
#include "KeyProvider.hpp"
#include "SecureMemory.hpp"
#include "async_file_types.hpp"
#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/write.hpp>
#include <memory>

class nkCryptoToolBase {
public:
    using ProgressCallback = std::function<void(double)>;
    using CompletionHandler = std::function<void(std::error_code, const std::string&)>;
    static constexpr size_t CHUNK_SIZE = 64 * 1024;

    explicit nkCryptoToolBase(std::shared_ptr<ICryptoStrategy> strategy);
    virtual ~nkCryptoToolBase();

    void setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider);
    void setKeyBaseDirectory(std::filesystem::path dir);
    std::filesystem::path getKeyBaseDirectory() const;

    // 非同期パイプラインによる暗号化・復号
    void encryptFileWithPipeline(
        asio::io_context& io_context,
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        CompletionHandler completion_handler,
        ProgressCallback progress_callback = nullptr
    );

    void decryptFileWithPipeline(
        asio::io_context& io_context,
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        SecureString& passphrase,
        CompletionHandler completion_handler,
        ProgressCallback progress_callback = nullptr
    );

    // 署名・検証
    asio::awaitable<void> signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, SecureString& passphrase, ProgressCallback progress_callback = nullptr);
    asio::awaitable<std::expected<void, CryptoError>> verifySignature(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_public_key_path, std::string digest_algo, ProgressCallback progress_callback = nullptr);

    // ファイル情報のインスペクト
    asio::awaitable<std::expected<std::map<std::string, std::string>, CryptoError>> inspectFile(asio::io_context& io_context, std::filesystem::path input_filepath, ProgressCallback progress_callback = nullptr);

    // 鍵管理ユーティリティ (バックエンド非依存)
    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase);
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase);
    std::expected<void, CryptoError> regeneratePublicKey(std::filesystem::path priv, std::filesystem::path pub, SecureString& pass);
    std::expected<void, CryptoError> wrapPrivateKey(std::filesystem::path raw_priv, std::filesystem::path wrapped_priv, SecureString& pass);
    std::expected<void, CryptoError> unwrapPrivateKey(std::filesystem::path wrapped_priv, std::filesystem::path raw_priv, SecureString& pass);

    // 静的ユーティリティ
    static std::expected<StrategyType, CryptoError> detectStrategyType(const std::filesystem::path& path);
    static bool isPrivateKeyEncrypted(const std::filesystem::path& path);
    static void printErrors();

    // 秘密鍵のロード (DER形式を返す)
    std::expected<std::vector<uint8_t>, CryptoError> loadPrivateKey(std::filesystem::path path, SecureString& passphrase);

protected:
    std::shared_ptr<ICryptoStrategy> strategy_;
    nk::KeyProvider key_provider_;
    std::filesystem::path key_base_directory = "keys";
};

#endif
