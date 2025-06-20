// nkCryptoToolBase.cpp
/*
 * Copyright (c) 2024-2025 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 * * nkCryptoTool is free software: you can redistribute it and/or modify
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

#include "nkCryptoToolBase.hpp"
#include <fstream>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <functional>

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

void EVP_PKEY_Deleter::operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
void EVP_PKEY_CTX_Deleter::operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
void EVP_CIPHER_CTX_Deleter::operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
void EVP_MD_CTX_Deleter::operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
void BIO_Deleter::operator()(BIO *b) const { BIO_free_all(b); }
void EVP_KDF_Deleter::operator()(EVP_KDF *p) const { EVP_KDF_free(p); }
void EVP_KDF_CTX_Deleter::operator()(EVP_KDF_CTX *p) const { EVP_KDF_CTX_free(p); }

nkCryptoToolBase::nkCryptoToolBase() : key_base_directory("keys") {
    try {
        if (!std::filesystem::exists(key_base_directory)) {
            std::filesystem::create_directories(key_base_directory);
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating directory '" << key_base_directory.string() << "': " << e.what() << std::endl;
    }
}
nkCryptoToolBase::~nkCryptoToolBase() {}

nkCryptoToolBase::AsyncStateBase::AsyncStateBase(asio::io_context& io_context)
    : input_file(io_context),
      output_file(io_context),
      cipher_ctx(EVP_CIPHER_CTX_new()),
      input_buffer(CHUNK_SIZE),
      output_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH), // 暗号化時のバッファはブロックサイズ分余分に確保
      tag(GCM_TAG_LEN),
      bytes_read(0),
      total_bytes_processed(0) {
    // 圧縮関連の初期化を削除
}

nkCryptoToolBase::AsyncStateBase::~AsyncStateBase() {
    // 圧縮関連のクリーンアップを削除
}

void nkCryptoToolBase::setKeyBaseDirectory(const std::filesystem::path& dir) {
    key_base_directory = dir;
    try {
        if (!std::filesystem::exists(key_base_directory)) {
            std::filesystem::create_directories(key_base_directory);
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Error creating directory '" << key_base_directory.string() << "': " << e.what() << std::endl;
    }
}
std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const { return key_base_directory; }

void nkCryptoToolBase::printOpenSSLErrors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

void nkCryptoToolBase::printProgress(double percentage) {
    int barWidth = 50;
    std::cout << "[";
    int pos = static_cast<int>(barWidth * percentage);
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << static_cast<int>(percentage * 100.0) << " %\r";
    std::cout.flush();
}

std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> nkCryptoToolBase::loadPublicKey(const std::filesystem::path& public_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"));
    if (!pub_bio) {
        std::cerr << "Error loading public key: " << public_key_path << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) printOpenSSLErrors();
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> nkCryptoToolBase::loadPrivateKey(const std::filesystem::path& private_key_path, const char* key_description) {
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"));
    if (!priv_bio) {
        std::cerr << "Error loading private key: " << private_key_path << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, (void*)key_description);
    if (!pkey) printOpenSSLErrors();
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::vector<unsigned char> nkCryptoToolBase::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                                      const std::string& salt_str, const std::string& info_str,
                                                      const std::string& digest_algo) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) { printOpenSSLErrors(); return {}; }
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) { printOpenSSLErrors(); return {}; }
    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest_algo.c_str(), 0);
    params[p++] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());
    if (!salt_str.empty()) params[p++] = OSSL_PARAM_construct_octet_string("salt", (void*)salt_str.c_str(), salt_str.length());
    if (!info_str.empty()) params[p++] = OSSL_PARAM_construct_octet_string("info", (void*)info_str.c_str(), info_str.length());
    params[p] = OSSL_PARAM_construct_end();
    std::vector<unsigned char> derived_key(output_len);
    if (EVP_KDF_derive(kctx.get(), derived_key.data(), output_len, params) <= 0) {
        printOpenSSLErrors();
        return {};
    }
    return derived_key;
}

// --- 暗号化パイプライン（シンプル版） ---

void nkCryptoToolBase::startEncryptionPipeline(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size) {
    state->total_bytes_processed = 0;
    state->input_file.async_read_some(
        asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolBase::handleReadForEncryption, this, state, total_input_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::handleReadForEncryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size, const std::error_code& ec, size_t bytes_transferred) {
    if (ec == asio::error::eof) {
        finishEncryptionPipeline(state);
        return;
    }
    if (ec) { state->completion_handler(ec); return; }

    // 圧縮ロジックを削除し、直接暗号化処理へ
    const unsigned char* data_to_encrypt = state->input_buffer.data();
    int len_to_encrypt = bytes_transferred;

    int outlen = 0;
    if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, data_to_encrypt, len_to_encrypt) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }
    
    state->total_bytes_processed += bytes_transferred;

    asio::async_write(state->output_file, asio::buffer(state->output_buffer.data(), outlen),
        std::bind(&nkCryptoToolBase::handleWriteForEncryption, this, state, total_input_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::handleWriteForEncryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size, const std::error_code& ec, size_t) {
    if (ec) { state->completion_handler(ec); return; }
    if (total_input_size > 0) printProgress(static_cast<double>(state->total_bytes_processed) / total_input_size);
    state->input_file.async_read_some(
        asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolBase::handleReadForEncryption, this, state, total_input_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::finishEncryptionPipeline(std::shared_ptr<AsyncStateBase> state) {
    int outlen = 0;
    if (EVP_EncryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }
    
    std::error_code ec;
    asio::write(state->output_file, asio::buffer(state->output_buffer.data(), outlen), ec);
    if (ec) { state->completion_handler(ec); return; }

    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }

    asio::write(state->output_file, asio::buffer(state->tag), ec);
    printProgress(1.0);
    state->completion_handler(ec);
}

// --- 復号パイプライン（シンプル版） ---

void nkCryptoToolBase::startDecryptionPipeline(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size) {
    state->total_bytes_processed = 0;
    size_t to_read = std::min(static_cast<uintmax_t>(CHUNK_SIZE), total_ciphertext_size);
    if (to_read == 0) {
        finishDecryptionPipeline(state);
        return;
    }
    state->input_file.async_read_some(
        asio::buffer(state->input_buffer.data(), to_read),
        std::bind(&nkCryptoToolBase::handleReadForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::handleReadForDecryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, const std::error_code& ec, size_t bytes_transferred) {
    if (bytes_transferred == 0 && (ec == asio::error::eof || state->total_bytes_processed >= total_ciphertext_size)) {
        finishDecryptionPipeline(state);
        return;
    }
    if (ec && ec != asio::error::eof) {
        state->completion_handler(ec);
        return;
    }
    
    int outlen = 0;
    if (EVP_DecryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), bytes_transferred) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(std::make_error_code(std::errc::operation_not_permitted));
        return;
    }

    state->total_bytes_processed += bytes_transferred;

    // 伸長ロジックを削除し、直接書き込み
    if (outlen > 0) {
        asio::async_write(state->output_file, asio::buffer(state->output_buffer.data(), outlen),
            std::bind(&nkCryptoToolBase::handleWriteForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
    } else {
        // データが出力されなかった場合でも、次の読み込みをトリガー
        handleWriteForDecryption(state, total_ciphertext_size, {}, 0);
    }
}

void nkCryptoToolBase::handleWriteForDecryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, const std::error_code& ec, size_t) {
    if (ec) { state->completion_handler(ec); return; }
    
    if (total_ciphertext_size > 0) printProgress(static_cast<double>(state->total_bytes_processed) / total_ciphertext_size);

    if(state->total_bytes_processed >= total_ciphertext_size) {
        finishDecryptionPipeline(state);
        return;
    }

    size_t to_read = std::min(static_cast<uintmax_t>(CHUNK_SIZE), total_ciphertext_size - state->total_bytes_processed);
    state->input_file.async_read_some(
        asio::buffer(state->input_buffer.data(), to_read),
        std::bind(&nkCryptoToolBase::handleReadForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::finishDecryptionPipeline(std::shared_ptr<AsyncStateBase> state) {
    std::error_code ec;
    // GCMタグをファイルから読み込む
    asio::read(state->input_file, asio::buffer(state->tag), ec);
    if (ec && ec != asio::error::eof) {
        state->completion_handler(ec); return;
    }
    // ファイル終端に達してもタグ長に満たない場合はエラー
    if (ec == asio::error::eof && state->tag.size() < GCM_TAG_LEN) {
        state->completion_handler(std::make_error_code(std::errc::message_size)); return;
    }
    
    // 読み込んだタグをコンテキストに設定
    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        state->completion_handler(std::make_error_code(std::errc::operation_not_permitted));
        return;
    }

    // 最終ブロックの復号とタグの検証
    int outlen = 0;
    if (EVP_DecryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
        // タグが一致しない場合、この関数が失敗する
        printOpenSSLErrors();
        state->completion_handler(std::make_error_code(std::errc::operation_not_permitted));
        return;
    }

    // 最終ブロックがあれば書き込む
    if (outlen > 0) {
        asio::write(state->output_file, asio::buffer(state->output_buffer.data(), outlen), ec);
        if (ec) { state->completion_handler(ec); return; }
    }

    printProgress(1.0);
    state->completion_handler({});
}
