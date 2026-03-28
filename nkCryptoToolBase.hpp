/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef NKCRYPTOTOOLBASE_HPP
#define NKCRYPTOTOOLBASE_HPP

#include <string>
#include <vector>
#include <filesystem>
#include <functional>
#include <system_error>
#include <memory>
#include <map>
#include <expected>
#include "CryptoError.hpp"
#include "async_file_types.hpp"
#include "nkcrypto_ffi.hpp" 
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>

#include "ICryptoStrategy.hpp"

namespace asio { class io_context; }

class nkCryptoToolBase : public std::enable_shared_from_this<nkCryptoToolBase> {
public:
    explicit nkCryptoToolBase(std::shared_ptr<ICryptoStrategy> strategy);
    virtual ~nkCryptoToolBase();

    void setKeyBaseDirectory(std::filesystem::path dir);
    std::filesystem::path getKeyBaseDirectory() const;

    void encryptFileWithPipeline(
        asio::io_context& io_context,
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler,
        ProgressCallback progress_callback = nullptr
    );

    void decryptFileWithPipeline(
        asio::io_context& io_context,
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::string& passphrase,
        std::function<void(std::error_code)> completion_handler,
        ProgressCallback progress_callback = nullptr
    );

    virtual asio::awaitable<void> signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, std::string& passphrase, ProgressCallback progress_callback = nullptr);
    virtual asio::awaitable<std::expected<void, CryptoError>> verifySignature(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_public_key_path, std::string digest_algo, ProgressCallback progress_callback = nullptr);

    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase);
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase);

    std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> loadPublicKey(std::filesystem::path public_key_path);
    std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> loadPrivateKey(std::filesystem::path private_key_path, std::string& passphrase);
    std::expected<void, CryptoError> regeneratePublicKey(std::filesystem::path private_key_path, std::filesystem::path public_key_path, std::string& passphrase);
    std::expected<void, CryptoError> wrapPrivateKey(std::filesystem::path raw_priv_path, std::filesystem::path wrapped_priv_path, std::string& passphrase);
    std::expected<void, CryptoError> unwrapPrivateKey(std::filesystem::path wrapped_priv_path, std::filesystem::path raw_priv_path, std::string& passphrase);
    static bool isPrivateKeyEncrypted(const std::filesystem::path& path);
    static std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len, const std::string& salt, const std::string& info, const std::string& digest_algo);
    static void printOpenSSLErrors();

protected:
    std::shared_ptr<ICryptoStrategy> strategy_;
    std::filesystem::path key_base_directory;
    static constexpr int CHUNK_SIZE = 65536;
};

#endif // NKCRYPTOTOOLBASE_HPP
