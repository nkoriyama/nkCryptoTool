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
 #include "async_file_types.hpp"
#include <fstream>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <functional>
#include <format>

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

void EVP_PKEY_Deleter::operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
void EVP_PKEY_CTX_Deleter::operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
void EVP_CIPHER_CTX_Deleter::operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
void EVP_MD_CTX_Deleter::operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
void BIO_Deleter::operator()(BIO *b) const { BIO_free_all(b); }
void EVP_KDF_Deleter::operator()(EVP_KDF *p) const { EVP_KDF_free(p); }
void EVP_KDF_CTX_Deleter::operator()(EVP_KDF_CTX *p) const { EVP_KDF_CTX_free(p); }

nkCryptoToolBase::nkCryptoToolBase() {}
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

void nkCryptoToolBase::setKeyBaseDirectory(std::filesystem::path dir) {
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

std::expected<void, CryptoError> nkCryptoToolBase::regeneratePublicKey(std::filesystem::path private_key_path, std::filesystem::path public_key_path, std::string passphrase) {
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

std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPublicKey(std::filesystem::path public_key_path) {
//    std::cerr << "[DEBUG] Attempting to load public key from: " << public_key_path.string() << std::endl;
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"));
    if (!pub_bio) {
//        std::cerr << "[DEBUG] BIO_new_file failed for: " << public_key_path.string() << std::endl;
        printOpenSSLErrors();
        return std::unexpected(CryptoError::FileReadError);
    }
//    std::cerr << "[DEBUG] BIO_new_file succeeded for: " << public_key_path.string() << std::endl;
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) { 
        ERR_clear_error(); 
        return std::unexpected(CryptoError::PublicKeyLoadError); 
    }
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPrivateKey(std::filesystem::path private_key_path, std::string passphrase) {
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"));
    if (!priv_bio) {
        return std::unexpected(CryptoError::FileReadError);
    }

    EVP_PKEY* pkey = nullptr;
    if (passphrase.empty()) {
        // No passphrase, so no callback.
        pkey = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, nullptr, nullptr);
    } else {
        // Passphrase provided, use the callback.
        pkey = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, (void*)passphrase.c_str());
    }

    if (!pkey) { 
        printOpenSSLErrors();
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

// Helper functions for ECDH key generation and shared secret derivation
std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> nkCryptoToolBase::generate_ephemeral_ec_key() {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) throw std::runtime_error("OpenSSL Error: Failed to initialize ephemeral EC key generation context.");
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() };
    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) throw std::runtime_error("OpenSSL Error: Failed to set ephemeral EC group parameters.");
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) throw std::runtime_error("OpenSSL Error: Failed to generate ephemeral EC key pair.");
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::vector<unsigned char> nkCryptoToolBase::ecdh_generate_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) throw std::runtime_error("OpenSSL Error: Failed to initialize ECDH shared secret derivation.");
    size_t secret_len;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) throw std::runtime_error("OpenSSL Error: Failed to get ECDH shared secret length.");
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) throw std::runtime_error("OpenSSL Error: Failed to derive ECDH shared secret.");
    secret.resize(secret_len);
    return secret;
}

