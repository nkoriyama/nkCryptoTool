// nkCryptoToolBase.hpp (並列処理対応版)
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
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/buffer.hpp>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <lz4.h>

#ifdef _WIN32
#include <asio/stream_file.hpp>
// Windowsではstream_fileをそのまま使う
using async_file_t = asio::stream_file;
#else // For Linux/macOS
#include <asio/posix/stream_descriptor.hpp>
#include <fcntl.h> // For open()
#include <unistd.h> // For close()
// Linux/macOSではposix::stream_descriptorを使う
using async_file_t = asio::posix::stream_descriptor;
#endif

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
    enum class CompressionAlgorithm : uint8_t {
        NONE = 0,
        LZ4  = 1,
        ZSTD = 2,
    };

protected:
    static constexpr int CHUNK_SIZE = 4096;
    static constexpr int GCM_IV_LEN = 12;
    static constexpr int GCM_TAG_LEN = 16;
    static constexpr char MAGIC[4] = {'N', 'K', 'C', '1'};

    #pragma pack(push, 1)
    struct FileHeader {
        char magic[4];
        uint8_t version;
        CompressionAlgorithm compression_algo;
        uint16_t reserved;
    };
    #pragma pack(pop)

    void printOpenSSLErrors();
    void printProgress(double percentage);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> loadPublicKey(const std::filesystem::path& public_key_path);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> loadPrivateKey(const std::filesystem::path& private_key_path, const char* key_description);

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
        CompressionAlgorithm compression_algo = CompressionAlgorithm::NONE;
        void* compression_stream = nullptr;
        void* decompression_stream = nullptr;
        std::vector<unsigned char> compression_buffer;
        std::vector<unsigned char> compression_frame_buffer;
        std::vector<unsigned char> decryption_buffer;
        uint32_t expected_frame_size;
        AsyncStateBase(asio::io_context& io_context);
        virtual ~AsyncStateBase();
    };
    
    void startEncryptionPipeline(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size);
    void startDecryptionPipeline(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size);

public:
    nkCryptoToolBase();
    virtual ~nkCryptoToolBase();

    void setKeyBaseDirectory(const std::filesystem::path& dir);
    std::filesystem::path getKeyBaseDirectory() const;

    virtual bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) = 0;
    virtual void signFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::string&, std::function<void(std::error_code)>) = 0;
    virtual void verifySignature(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code, bool)>) = 0;
    virtual std::filesystem::path getEncryptionPrivateKeyPath() const = 0;
    virtual std::filesystem::path getSigningPrivateKeyPath() const = 0;
    virtual std::filesystem::path getEncryptionPublicKeyPath() const = 0;
    virtual std::filesystem::path getSigningPublicKeyPath() const = 0;

    virtual void encryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) = 0;
    virtual void encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)>) = 0;
    virtual void decryptFile(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) = 0;
    virtual void decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)>) = 0;

    // --- 並列処理インターフェース：引数を値渡しに変更 ---
    virtual asio::awaitable<void> encryptFileParallel(
        asio::io_context& worker_context,
        std::string input_filepath,
        std::string output_filepath,
        std::string recipient_public_key_path,
        CompressionAlgorithm algo
    ) = 0;

    virtual asio::awaitable<void> decryptFileParallel(
        asio::io_context& worker_context,
        std::string input_filepath,
        std::string output_filepath,
        std::string user_private_key_path
    ) = 0;

    // --- ★ 新しいパイプライン処理インターフェース ---
    virtual void encryptFileWithPipeline(
        asio::io_context& io_context,
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler
    ) = 0;

    virtual void decryptFileWithPipeline(
        asio::io_context& io_context,
        const std::string& input_filepath,
        const std::string& output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler
    ) = 0;


private:
    std::filesystem::path key_base_directory;
    void handleReadForEncryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size, const std::error_code& ec, size_t bytes_transferred);
    void handleWriteForEncryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size, const std::error_code& ec, size_t);
    void finishEncryptionPipeline(std::shared_ptr<AsyncStateBase> state);
    void processDecryptionBuffer(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, bool finished_reading);
    void handleReadForDecryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, const std::error_code& ec, size_t bytes_transferred);
    void handleWriteForDecryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, const std::error_code& ec, size_t);
    void finishDecryptionPipeline(std::shared_ptr<AsyncStateBase> state);
};
#endif // NKCRYPTOTOOLBASE_HPP
