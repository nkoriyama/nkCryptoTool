#ifndef NKCRYPTOTOOL_UTILS_HPP
#define NKCRYPTOTOOL_UTILS_HPP

#include "CryptoError.hpp"
#include "SecureMemory.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <expected>
#include <asio/io_context.hpp>

// エンディアン非依存の数値読み書きヘルパー
inline void write_u16_le(std::vector<char>& out, uint16_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

inline void write_u32_le(std::vector<char>& out, uint32_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
}

inline bool read_u16_le(const std::vector<char>& data, size_t& pos, uint16_t& out) {
    if (pos > data.size() || data.size() - pos < 2) return false;
    out = static_cast<uint8_t>(data[pos]) | (static_cast<uint8_t>(data[pos+1]) << 8);
    pos += 2;
    return true;
}

inline bool read_u32_le(const std::vector<char>& data, size_t& pos, uint32_t& out) {
    if (pos > data.size() || data.size() - pos < 4) return false;
    out = static_cast<uint8_t>(data[pos]) | 
          (static_cast<uint8_t>(data[pos+1]) << 8) |
          (static_cast<uint8_t>(data[pos+2]) << 16) |
          (static_cast<uint8_t>(data[pos+3]) << 24);
    pos += 4;
    return true;
}

// Function to process a directory recursively
void processDirectory(
    asio::io_context& io_context,
    const std::filesystem::path& input_dir,
    const std::filesystem::path& output_dir,
    const std::function<void(const std::filesystem::path&, const std::filesystem::path&)>& file_operation
);


// パスフレーズをコンソールから安全に入力するための関数
SecureString get_masked_passphrase();

// パスフレーズを2回入力させ、一致を確認する関数
SecureString get_and_verify_passphrase(const std::string& prompt);

// 秘密鍵のパスフレーズを要求する際に呼び出すコールバック関数 (レガシー)
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

namespace nkCryptoToolUtils {

// PEM 形式へのラップ
std::string wrapToPem(const std::vector<uint8_t>& der, const std::string& label);

// PEM 形式からのアンラップ (DERを返す)
std::expected<std::vector<uint8_t>, CryptoError> unwrapFromPem(const std::string& pem, const std::string& label);

} // namespace nkCryptoToolUtils

#endif // NKCRYPTOTOOL_UTILS_HPP
