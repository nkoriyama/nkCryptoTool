/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef NKCRYPTOTOOL_STRATEGY_HPP
#define NKCRYPTOTOOL_STRATEGY_HPP

#include <vector>
#include <string>
#include <map>
#include <expected>
#include <filesystem>
#include "CryptoError.hpp"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <asio/awaitable.hpp>
#include <memory>

// OpenSSL Deleters (Inline to avoid redefinition)
struct EVP_PKEY_Deleter { void operator()(EVP_PKEY *p) const { if(p) EVP_PKEY_free(p); } };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX *p) const { if(p) EVP_PKEY_CTX_free(p); } };
struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX *p) const { if(p) EVP_CIPHER_CTX_free(p); } };
struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX *p) const { if(p) EVP_MD_CTX_free(p); } };
struct BIO_Deleter { void operator()(BIO *b) const { if(b) BIO_free_all(b); } };
struct EVP_KDF_Deleter { void operator()(EVP_KDF *p) const { if(p) EVP_KDF_free(p); } };
struct EVP_KDF_CTX_Deleter { void operator()(EVP_KDF_CTX *p) const { if(p) EVP_KDF_CTX_free(p); } };

// ストラテジーのタイプ識別子
enum class StrategyType : uint8_t {
    ECC = 1,
    PQC = 2,
    Hybrid = 3
};

// 暗号化・署名のアルゴリズム固有ロジックを分離するインターフェース
class ICryptoStrategy {
public:
    virtual ~ICryptoStrategy() = default;

    // --- ストラテジーの種類 ---
    virtual StrategyType getStrategyType() const = 0;

    // --- 鍵生成 ---
    virtual std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) = 0;
    virtual std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) = 0;

    // --- 暗号化・復号のパイプライン処理用 ---
    virtual std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>& key_paths) = 0;
    virtual std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>& key_paths, std::string& passphrase) = 0;
    virtual std::vector<char> encryptTransform(const std::vector<char>& data) = 0;
    virtual std::vector<char> decryptTransform(const std::vector<char>& data) = 0;
    virtual std::expected<void, CryptoError> finalizeEncryption(std::vector<char>& out_final) = 0;
    virtual std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>& tag) = 0;

    // --- 署名・検証 ---
    virtual std::expected<void, CryptoError> prepareSigning(const std::filesystem::path& priv_key_path, std::string& passphrase, const std::string& digest_algo) = 0;
    virtual std::expected<void, CryptoError> prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) = 0;
    virtual void updateHash(const std::vector<char>& data) = 0;
    virtual std::expected<std::vector<char>, CryptoError> signHash() = 0;
    virtual std::expected<bool, CryptoError> verifyHash(const std::vector<char>& signature) = 0;
    
    // 署名ヘッダー情報
    virtual std::vector<char> serializeSignatureHeader() const = 0;
    virtual std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>& data) = 0;
    
    // ヘッダー情報
    virtual std::map<std::string, std::string> getMetadata() const = 0;
    virtual size_t getHeaderSize() const = 0;
    virtual std::vector<char> serializeHeader() const = 0;
    virtual std::expected<void, CryptoError> deserializeHeader(const std::vector<char>& data) = 0;
    virtual size_t getTagSize() const = 0;
};

#endif
