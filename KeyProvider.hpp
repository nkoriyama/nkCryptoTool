/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef NKCRYPTOTOOL_KEY_PROVIDER_HPP
#define NKCRYPTOTOOL_KEY_PROVIDER_HPP

#include "IKeyProvider.hpp"
#include <memory>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <expected>
#include <optional>

namespace nk {

/**
 * 鍵プロバイダーのフロントエンドクラス
 */
class KeyProvider {
public:
    KeyProvider() = default;

    void set(std::shared_ptr<IKeyProvider> provider) { provider_ = provider; }
    void setProvider(std::shared_ptr<IKeyProvider> provider) { set(provider); }

    std::expected<SecureString, CryptoError> wrap(const std::vector<uint8_t>& raw_key, const SecureString& passphrase) {
        if (!provider_) return std::unexpected(CryptoError::ProviderNotAvailable);
        return provider_->wrapKey(raw_key, passphrase);
    }

    std::expected<std::vector<uint8_t>, CryptoError> unwrap(const SecureString& wrapped_pem, const SecureString& passphrase) {
        if (!provider_) return std::unexpected(CryptoError::ProviderNotAvailable);
        return provider_->unwrapKey(wrapped_pem, passphrase);
    }

    // ファイルベースの便宜メソッド
    std::expected<void, CryptoError> wrapPrivateKey(const std::filesystem::path& raw_path, const std::filesystem::path& wrapped_path, const SecureString& passphrase) {
        auto raw = loadRawFile(raw_path);
        if (!raw) return std::unexpected(CryptoError::FileReadError);
        auto wrapped = wrap(*raw, passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        
        std::ofstream ofs(wrapped_path);
        if (!ofs) return std::unexpected(CryptoError::FileWriteError);
        ofs << std::string(wrapped->begin(), wrapped->end());
        return {};
    }

    std::expected<void, CryptoError> unwrapPrivateKey(const std::filesystem::path& wrapped_path, const std::filesystem::path& raw_path, const SecureString& passphrase) {
        std::ifstream ifs(wrapped_path);
        if (!ifs) return std::unexpected(CryptoError::FileReadError);
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        
        auto raw = unwrap(SecureString(content.begin(), content.end()), passphrase);
        if (!raw) return std::unexpected(raw.error());
        
        std::ofstream ofs(raw_path, std::ios::binary);
        if (!ofs) return std::unexpected(CryptoError::FileWriteError);
        ofs.write(reinterpret_cast<const char*>(raw->data()), raw->size());
        return {};
    }

    std::expected<std::vector<uint8_t>, CryptoError> loadPrivateKey(const std::filesystem::path& path, const SecureString& passphrase) {
        std::ifstream ifs(path);
        if (!ifs) return std::unexpected(CryptoError::FileReadError);
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        
        // PEMかどうか判定
        if (content.find("-----BEGIN") != std::string::npos) {
            return unwrap(SecureString(content.begin(), content.end()), passphrase);
        }
        
        // 生のDERとして読み込む (fallback)
        std::ifstream ifs_bin(path, std::ios::binary);
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs_bin)), std::istreambuf_iterator<char>());
    }

private:
    std::shared_ptr<IKeyProvider> provider_;

    static std::optional<std::vector<uint8_t>> loadRawFile(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs) return std::nullopt;
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }
};

} // namespace nk

#endif // NKCRYPTOTOOL_KEY_PROVIDER_HPP
