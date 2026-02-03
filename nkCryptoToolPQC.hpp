// nkCryptoToolPQC.hpp
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

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"

class nkCryptoToolPQC : public nkCryptoToolBase {
public:
    struct SigningState : public nkCryptoToolBase::AsyncStateBase, public std::enable_shared_from_this<SigningState> {
        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx;
        uintmax_t total_input_size;
        std::vector<unsigned char> final_hash;
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> private_key;
        SigningState(asio::io_context& io_context) : AsyncStateBase(io_context), md_ctx(EVP_MD_CTX_new()), total_input_size(0) {}
    };

    struct VerificationState : public nkCryptoToolBase::AsyncStateBase, public std::enable_shared_from_this<VerificationState> {
        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx;
        async_file_t signature_file;
        std::vector<unsigned char> signature;
        uintmax_t total_input_size;
        std::vector<unsigned char> final_hash;
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> public_key;
        VerificationState(asio::io_context& io_context) : AsyncStateBase(io_context), md_ctx(EVP_MD_CTX_new()), signature_file(io_context), total_input_size(0) {}
    };

    nkCryptoToolPQC();
    ~nkCryptoToolPQC();

    std::expected<void, CryptoError> generateEncryptionKeyPair(std::filesystem::path public_key_path, std::filesystem::path private_key_path, std::string passphrase) override;
    std::expected<void, CryptoError> generateSigningKeyPair(std::filesystem::path public_key_path, std::filesystem::path private_key_path, std::string passphrase) override;

    asio::awaitable<void> signFile(asio::io_context&, std::filesystem::path, std::filesystem::path, std::filesystem::path, std::string, std::string) override;
    asio::awaitable<std::expected<void, CryptoError>> verifySignature(asio::io_context&, std::filesystem::path, std::filesystem::path, std::filesystem::path, std::string) override;

    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;

    void encryptFileWithPipeline(
        asio::io_context& io_context,
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::function<void(std::error_code)> completion_handler,
        ProgressCallback progress_callback = nullptr
    ) override;

    void decryptFileWithPipeline(
        asio::io_context& io_context,
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::string passphrase,
        std::function<void(std::error_code)> completion_handler,
        ProgressCallback progress_callback = nullptr
    ) override;

    void encryptFileWithSync(
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths
    ) override;

    void decryptFileWithSync(
        std::string input_filepath,
        std::string output_filepath,
        const std::map<std::string, std::string>& key_paths,
        std::string passphrase
    ) override;

private:
    asio::awaitable<void> handleFileReadForSigning(std::shared_ptr<SigningState> state);
    asio::awaitable<void> finishSigning(std::shared_ptr<SigningState> state);
    asio::awaitable<void> handleFileReadForVerification(std::shared_ptr<VerificationState> state);
};
#endif // NKCRYPTOTOOLPQC_HPP
