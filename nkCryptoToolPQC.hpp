// nkCryptoToolPQC.hpp

#ifndef NKCRYPTOTOOLPQC_HPP
#define NKCRYPTOTOOLPQC_HPP

#include "nkCryptoToolBase.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/evp.h> // EVP_PKEYやその他のOpenSSL型に必要
#include <openssl/bio.h> // BIOに必要

// OpenSSL PQC型のための前方宣言（必要な場合）
// ただし、一般的にはPQCアルゴリズムはEVP_PKEYとEVP_CIPHER/EVP_MDを介して統合されます。

// OpenSSL unique_ptrのためのカスタムデリータ（必要な場合の前方宣言、しかし.cppの方が良い）
// これらは通常、使用される.cppファイル、または共通のユーティリティヘッダーで定義されます。
// 現時点では、厳密に必要でない限り、ヘッダーの依存関係を避けるために.cppに保持されています。

class nkCryptoToolPQC : public nkCryptoToolBase {
private:
    // OpenSSLエラーを出力するヘルパー関数（PQCプリミティブにOpenSSLを使用する場合）
    void printOpenSSLErrors();

    // PQC操作のためのヘルパー関数（nkCryptoToolECC.hppから移動、共通ユーティリティのため）
    EVP_PKEY* loadPublicKey(const std::filesystem::path& public_key_path);
    EVP_PKEY* loadPrivateKey(const std::filesystem::path& private_key_path);

    // HKDF導出のためのヘルパー関数
    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                          const std::string& salt, const std::string& info,
                                          const std::string& digest_algo);

    // AES-GCM暗号化/複合のためのヘルパー関数
    bool aesGcmEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext,
                       std::vector<unsigned char>& tag);
    bool aesGcmDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key,
                       const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag,
                       std::vector<unsigned char>& plaintext);

public:
    nkCryptoToolPQC();
    ~nkCryptoToolPQC();

    // 鍵生成メソッドをオーバーライド
    bool generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override; // ベースクラスと完全に一致するように確認
    bool generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) override;

    // 暗号化/複合メソッドをオーバーライド
    bool encryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path) override;
    bool encryptFileHybrid(
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_public_key_path,
        const std::filesystem::path& recipient_ecdh_public_key_path) override;
    bool decryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) override;
    bool decryptFileHybrid(
        const std::filesystem::path& input_filepath,
        const std::filesystem::path& output_filepath,
        const std::filesystem::path& recipient_mlkem_private_key_path,
        const std::filesystem::path& recipient_ecdh_private_key_path) override;
    // 署名/検証メソッドをオーバーライド
    bool signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) override;
    bool verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) override;

    // デフォルトの鍵パスのメソッドをオーバーライド
    std::filesystem::path getEncryptionPrivateKeyPath() const override;
    std::filesystem::path getSigningPrivateKeyPath() const override;
    std::filesystem::path getEncryptionPublicKeyPath() const override;
    std::filesystem::path getSigningPublicKeyPath() const override;
};

#endif // NKCRYPTOTOOLPQC_HPP
