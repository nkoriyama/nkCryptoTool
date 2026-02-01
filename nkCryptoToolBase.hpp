// nkCryptoToolBase.hpp
/*
 * Copyright (c) 2024-2025 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * nkCryptoTool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nkCryptoTool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nkCryptoTool. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef NKCRYPTOTOOLBASE_HPP
#define NKCRYPTOTOOLBASE_HPP

#include <string>
#include <vector>
#include <stdexcept>
#include <filesystem>
#include <functional>
#include <system_error>
#include <memory>
#include <map>
#include <expected>
#include "CryptoError.hpp"
#include "async_file_types.hpp"
#include "nkcrypto_ffi.hpp" // For ProgressCallback
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>

namespace asio { class io_context; }

struct EVP_PKEY_Deleter { void operator()(EVP_PKEY *p) const; };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX *p) const; };
struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX *p) const; };
struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX *p) const; };
struct BIO_Deleter { void operator()(BIO *b) const; };
struct EVP_KDF_Deleter { void operator()(EVP_KDF *p) const; };
struct EVP_KDF_CTX_Deleter { void operator()(EVP_KDF_CTX *p) const; };

class nkCryptoToolBase {
public:
protected:
    static constexpr int CHUNK_SIZE = 4096;
    static constexpr int GCM_IV_LEN = 12;
    static constexpr int GCM_TAG_LEN = 16;
    static constexpr char MAGIC[4] = {'N', 'K', 'C', '1'};

    #pragma pack(push, 1)
    struct FileHeader {
        char magic[4];
        uint8_t version;
        uint16_t reserved;
    };
    #pragma pack(pop)

    std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> loadPublicKey(const std::filesystem::path& public_key_path);
    std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> loadPrivateKey(const std::filesystem::path& private_key_path, const char* key_description);

    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                          const std::string& salt, const std::string& info,
                                          const std::string& digest_algo);
    
    struct AsyncStateBase {
        async_file_t input_file;
        async_file_t output_file;
        std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> cipher_ctx;
        std::vector<unsigned char> input_buffer;
        std::vector<unsigned char> output_buffer;
        std::vector<unsigned char> tag;
        size_t bytes_read;
        uintmax_t total_bytes_processed;
        std::function<void(std::error_code)> completion_handler;

        AsyncStateBase(asio::io_context& io_context);
        virtual ~AsyncStateBase();
    };
    
public:
    nkCryptoToolBase();
    virtual ~nkCryptoToolBase();

    void setKeyBaseDirectory(const std::filesystem::path& dir);
    std::filesystem::path getKeyBaseDirectory() const;

    virtual std::expected<void, CryptoError> generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual std::expected<void, CryptoError> generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual asio::awaitable<void> signFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::string&) = 0;
    virtual asio::awaitable<std::expected<void, CryptoError>> verifySignature(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&) = 0;
    virtual std::filesystem::path getEncryptionPrivateKeyPath() const = 0;
    virtual std::filesystem::path getSigningPrivateKeyPath() const = 0;
    virtual std::filesystem::path getEncryptionPublicKeyPath() const = 0;
    virtual std::filesystem::path getSigningPublicKeyPath() const = 0;

    // --- パイプライン処理インターフェース ---
    virtual void encryptFileWithPipeline(
        asio::io_context& io_context,
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler,
        ProgressCallback progress_callback = nullptr
    ) = 0;

    virtual void decryptFileWithPipeline(
        asio::io_context& io_context,
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler,
        ProgressCallback progress_callback = nullptr
    ) = 0;

    virtual void encryptFileWithSync(
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths
    ) = 0;

    virtual void decryptFileWithSync(
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths
    ) = 0;


private:
    std::filesystem::path key_base_directory;

public:
    static void printOpenSSLErrors();
    // Corrected regeneratePublicKey declaration
    std::expected<void, CryptoError> regeneratePublicKey(const std::filesystem::path& private_key_path, const std::filesystem::path& public_key_path, const std::string& passphrase);

    // Helper functions for ECDH key generation and shared secret derivation
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> generate_ephemeral_ec_key();
    std::vector<unsigned char> ecdh_generate_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key);
};
#endif // NKCRYPTOTOOLBASE_HPP
