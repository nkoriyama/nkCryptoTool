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
#include <memory>
#include "SecureMemory.hpp"
#include "CryptoError.hpp"
#include "IKeyProvider.hpp"

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

    // --- 鍵プロバイダーの設定 ---
    virtual void setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider) = 0;

    // --- 鍵生成 ---
    virtual std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase, bool force) = 0;
    virtual std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase, bool force) = 0;
    virtual std::expected<void, CryptoError> regeneratePublicKey(const std::filesystem::path& priv_path, const std::filesystem::path& pub_path, SecureString& passphrase, bool force) = 0;

    // --- 暗号化・復号のパイプライン処理用 ---
    virtual std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>& key_paths) = 0;
    virtual std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) = 0;
    virtual std::vector<char> encryptTransform(const std::vector<char>& data) = 0;
    virtual std::vector<char> decryptTransform(const std::vector<char>& data) = 0;
    virtual std::expected<void, CryptoError> finalizeEncryption(std::vector<char>& out_final) = 0;
    virtual std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>& tag) = 0;

    // --- 署名・検証 ---
    virtual std::expected<void, CryptoError> prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) = 0;
    virtual std::expected<void, CryptoError> prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) = 0;
    virtual void updateHash(const std::vector<char>& data) = 0;
    virtual std::expected<std::vector<char>, CryptoError> signHash() = 0;
    virtual std::expected<bool, CryptoError> verifyHash(const std::vector<char>& signature) = 0;
    
    // 署名ヘッダー情報
    virtual std::vector<char> serializeSignatureHeader() const = 0;
    virtual std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>& data) = 0;
    
    // ヘッダー情報
    virtual std::map<std::string, std::string> getMetadata(const std::string& magic = "") const = 0;
    virtual size_t getHeaderSize() const = 0;
    virtual std::vector<char> serializeHeader() const = 0;
    virtual std::expected<size_t, CryptoError> deserializeHeader(const std::vector<char>& data) = 0;
    virtual size_t getTagSize() const = 0;

    // --- NKCT v3 (ChunkedAead) 用の鍵材料アクセス ---
    // 書き込みは常に v3。読み込みは v1/v2 (レガシー・ストリーム AEAD) と v3 の
    // 両対応で、deserializeHeader が解析したバージョンを formatVersion() が返す。
    // v3 のとき prepare{Encryption,Decryption} は v3Key()/v3NoncePrefix() を導出し、
    // レガシーの単一 AEAD コンテキストは作らない。
    virtual uint16_t formatVersion() const { return 3; }
    virtual uint32_t v3ChunkSize() const { return 0; }
    virtual std::vector<unsigned char> v3Key() const { return {}; }
    virtual std::vector<unsigned char> v3NoncePrefix() const { return {}; }
    virtual std::string aeadAlgoName() const { return "AES-256-GCM"; }
};

#endif
