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
#include <format>
#include <zstd.h>

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
        std::cerr << std::format("Error creating directory '{}': {}\n", key_base_directory.string(), e.what());
    }
}
nkCryptoToolBase::~nkCryptoToolBase() {}

nkCryptoToolBase::AsyncStateBase::AsyncStateBase(asio::io_context& io_context)
    : input_file(io_context),
      output_file(io_context),
      cipher_ctx(EVP_CIPHER_CTX_new()),
      input_buffer(CHUNK_SIZE),
      output_buffer(ZSTD_compressBound(CHUNK_SIZE) + EVP_MAX_BLOCK_LENGTH),
      tag(GCM_TAG_LEN),
      bytes_read(0),
      total_bytes_processed(0),
      compression_algo(CompressionAlgorithm::NONE),
      cstream(nullptr),
      dstream(nullptr) {
}

nkCryptoToolBase::AsyncStateBase::~AsyncStateBase() {
    if (cstream) {
        ZSTD_freeCStream(cstream);
    }
    if (dstream) {
        ZSTD_freeDStream(dstream);
    }
}

void nkCryptoToolBase::setKeyBaseDirectory(const std::filesystem::path& dir) {
    key_base_directory = dir;
    try {
        if (!std::filesystem::exists(key_base_directory)) {
            std::filesystem::create_directories(key_base_directory);
        }
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << std::format("Error creating directory '{}': {}\n", key_base_directory.string(), e.what());
    }
}
std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const { return key_base_directory; }

void nkCryptoToolBase::printOpenSSLErrors() {
    std::string error_msg;
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        if (!error_msg.empty()) {
            error_msg += "; ";
        }
        error_msg += err_buf;
    }
    if (error_msg.empty()) {
        error_msg = "Unknown OpenSSL error.";
    }
    std::cerr << "OpenSSL Error: " << error_msg << std::endl;
}

std::expected<void, CryptoError> nkCryptoToolBase::regeneratePublicKey(const std::filesystem::path& private_key_path, const std::filesystem::path& public_key_path, const std::string& passphrase) {
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"));
    if (!priv_bio) {
        printOpenSSLErrors();
        return std::unexpected(CryptoError::FileReadError);
    }

    EVP_PKEY* pkey_raw = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, (void*)passphrase.c_str());
    if (!pkey_raw) {
        printOpenSSLErrors();
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(pkey_raw);

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        printOpenSSLErrors();
        return std::unexpected(CryptoError::FileCreationError);
    }

    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        printOpenSSLErrors();
        return std::unexpected(CryptoError::PublicKeyWriteError);
    }
    return {};
}

std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPublicKey(const std::filesystem::path& public_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"));
    if (!pub_bio) {
        return std::unexpected(CryptoError::FileReadError);
    }
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) { 
        ERR_clear_error(); 
        return std::unexpected(CryptoError::PublicKeyLoadError); 
    }
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPrivateKey(const std::filesystem::path& private_key_path, const char* key_description) {
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"));
    if (!priv_bio) {
        return std::unexpected(CryptoError::FileReadError);
    }
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, (void*)key_description);
    if (!pkey) { 
        ERR_clear_error(); 
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::vector<unsigned char> nkCryptoToolBase::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                                      const std::string& salt_str, const std::string& info_str,
                                                      const std::string& digest_algo) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) { throw std::runtime_error("OpenSSL Error: Failed to fetch HKDF."); }
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) { throw std::runtime_error("OpenSSL Error: Failed to create HKDF context."); }
    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest_algo.c_str(), 0);
    params[p++] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());
    if (!salt_str.empty()) params[p++] = OSSL_PARAM_construct_octet_string("salt", (void*)salt_str.c_str(), salt_str.length());
    if (!info_str.empty()) params[p++] = OSSL_PARAM_construct_octet_string("info", (void*)info_str.c_str(), info_str.length());
    params[p] = OSSL_PARAM_construct_end();
    std::vector<unsigned char> derived_key(output_len);
    if (EVP_KDF_derive(kctx.get(), derived_key.data(), output_len, params) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to derive key with HKDF.");
    }
    return derived_key;
}

void nkCryptoToolBase::startEncryptionPipeline(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size) {
    if (state->compression_algo == CompressionAlgorithm::ZSTD) {
        state->cstream = ZSTD_createCStream();
        if (!state->cstream) {
            state->completion_handler(std::make_error_code(std::errc::io_error));
            return;
        }
        ZSTD_initCStream(state->cstream, 1);
    }
    
    state->input_file.async_read_some(asio::buffer(state->input_buffer),
                                    std::bind(&nkCryptoToolBase::handleReadForEncryption, this, state, total_input_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::startDecryptionPipeline(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size) {
    if (state->compression_algo == CompressionAlgorithm::ZSTD) {
        state->dstream = ZSTD_createDStream();
        if (!state->dstream) {
            state->completion_handler(std::make_error_code(std::errc::io_error));
            return;
        }
        ZSTD_initDStream(state->dstream);
    }
    state->input_file.async_read_some(asio::buffer(state->input_buffer),
                                    std::bind(&nkCryptoToolBase::handleReadForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::handleReadForEncryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size, const std::error_code& ec, size_t bytes_transferred) {
    if (ec && ec != asio::error::eof) {
        state->completion_handler(ec);
        return;
    }

    state->bytes_read = bytes_transferred;
    state->total_bytes_processed += bytes_transferred;
    
    int outlen = 0;
    if (state->compression_algo == CompressionAlgorithm::ZSTD) {
        ZSTD_inBuffer in_buf = { state->input_buffer.data(), state->bytes_read, 0 };
        ZSTD_outBuffer out_buf = { state->output_buffer.data(), state->output_buffer.size(), 0 };
        ZSTD_compressStream(state->cstream, &out_buf, &in_buf);
        
        int encrypted_len = 0;
        if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &encrypted_len, (const unsigned char*)out_buf.dst, out_buf.pos) <= 0) {
            state->completion_handler(std::make_error_code(std::errc::io_error));
            return;
        }
        outlen = encrypted_len;
    } else {
        if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), state->bytes_read) <= 0) {
            state->completion_handler(std::make_error_code(std::errc::io_error));
            return;
        }
    }
    
    asio::async_write(state->output_file, asio::buffer(state->output_buffer, outlen),
                      std::bind(&nkCryptoToolBase::handleWriteForEncryption, this, state, total_input_size, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolBase::handleWriteForEncryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_input_size, const std::error_code& ec, size_t) {
    if (ec) {
        state->completion_handler(ec);
        return;
    }

    if (state->total_bytes_processed < total_input_size) {
        state->input_file.async_read_some(asio::buffer(state->input_buffer),
                                        std::bind(&nkCryptoToolBase::handleReadForEncryption, this, state, total_input_size, std::placeholders::_1, std::placeholders::_2));
    } else {
        finishEncryptionPipeline(state);
    }
}

void nkCryptoToolBase::finishEncryptionPipeline(std::shared_ptr<AsyncStateBase> state) {
    int outlen = 0;
    if (state->compression_algo == CompressionAlgorithm::ZSTD) {
        ZSTD_outBuffer out_buf = { state->output_buffer.data(), state->output_buffer.size(), 0 };
        ZSTD_endStream(state->cstream, &out_buf);

        int encrypted_len = 0;
        if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &encrypted_len, (const unsigned char*)out_buf.dst, out_buf.pos) <= 0) {
            state->completion_handler(std::make_error_code(std::errc::io_error));
            return;
        }
        outlen = encrypted_len;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data() + outlen, &final_len) <= 0) {
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }
    outlen += final_len;

    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }

    asio::write(state->output_file, asio::buffer(state->output_buffer, outlen));
    asio::write(state->output_file, asio::buffer(state->tag));
    
    state->completion_handler(std::error_code());
}

void nkCryptoToolBase::handleReadForDecryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, const std::error_code& ec, size_t bytes_transferred) {
    if (ec && ec != asio::error::eof) {
        state->completion_handler(ec);
        return;
    }

    state->bytes_read = bytes_transferred;
    state->total_bytes_processed += bytes_transferred;

    int outlen = 0;
    if (EVP_DecryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), state->bytes_read) <= 0) {
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }

    if (state->compression_algo == CompressionAlgorithm::ZSTD) {
        ZSTD_inBuffer in_buf = { state->output_buffer.data(), (size_t)outlen, 0 };
        while (in_buf.pos < in_buf.size) {
            ZSTD_outBuffer out_buf = { state->input_buffer.data(), state->input_buffer.size(), 0 };
            size_t ret = ZSTD_decompressStream(state->dstream, &out_buf, &in_buf);
            if (ZSTD_isError(ret)) {
                state->completion_handler(std::make_error_code(std::errc::io_error));
                return;
            }
            asio::async_write(state->output_file, asio::buffer(state->input_buffer, out_buf.pos),
                              std::bind(&nkCryptoToolBase::handleWriteForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
        }
    } else {
        asio::async_write(state->output_file, asio::buffer(state->output_buffer, outlen),
                          std::bind(&nkCryptoToolBase::handleWriteForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
    }
}

void nkCryptoToolBase::handleWriteForDecryption(std::shared_ptr<AsyncStateBase> state, uintmax_t total_ciphertext_size, const std::error_code& ec, size_t) {
    if (ec) {
        state->completion_handler(ec);
        return;
    }

    if (state->total_bytes_processed < total_ciphertext_size) {
        state->input_file.async_read_some(asio::buffer(state->input_buffer),
                                        std::bind(&nkCryptoToolBase::handleReadForDecryption, this, state, total_ciphertext_size, std::placeholders::_1, std::placeholders::_2));
    } else {
        finishDecryptionPipeline(state);
    }
}

void nkCryptoToolBase::finishDecryptionPipeline(std::shared_ptr<AsyncStateBase> state) {
    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }
    
    int outlen = 0;
    if (EVP_DecryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
        state->completion_handler(std::make_error_code(std::errc::io_error));
        return;
    }

    if (state->compression_algo == CompressionAlgorithm::ZSTD) {
        ZSTD_inBuffer in_buf = { state->output_buffer.data(), (size_t)outlen, 0 };
        while (in_buf.pos < in_buf.size) {
            ZSTD_outBuffer out_buf = { state->input_buffer.data(), state->input_buffer.size(), 0 };
            size_t ret = ZSTD_decompressStream(state->dstream, &out_buf, &in_buf);
            if (ZSTD_isError(ret)) {
                state->completion_handler(std::make_error_code(std::errc::io_error));
                return;
            }
            asio::write(state->output_file, asio::buffer(state->input_buffer, out_buf.pos));
        }
    } else {
        asio::write(state->output_file, asio::buffer(state->output_buffer, outlen));
    }
    
    state->completion_handler(std::error_code());
}
