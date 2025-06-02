// nkCryptoToolPQC.cpp

#include "nkCryptoToolPQC.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/kdf.h> // For EVP_KDF (HKDF)
#include <string>
#include <algorithm>

// External callback for PEM passphrase
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);
extern std::string global_passphrase_for_pem_cb;

// Custom deleters for OpenSSL unique_ptr
struct EVP_PKEY_Deleter {
  void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};

struct EVP_PKEY_CTX_Deleter {
  void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
};

struct EVP_CIPHER_CTX_Deleter {
  void operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
};

struct EVP_MD_CTX_Deleter {
  void operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
};

struct EVP_KDF_Deleter {
  void operator()(EVP_KDF *p) const { EVP_KDF_free(p); }
};

struct EVP_KDF_CTX_Deleter {
  void operator()(EVP_KDF_CTX *p) const { EVP_KDF_CTX_free(p); }
};

struct BIO_Deleter {
    void operator()(BIO *b) const { BIO_free_all(b); }
};

struct OpenSSLFreeDeleter {
    void operator()(void* p) const {
        OPENSSL_free(p);
    }
};

// OpenSSLエラーを出力するヘルパー関数
void nkCryptoToolPQC::printOpenSSLErrors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error (PQC): " << err_buf << std::endl;
    }
}

// 公開鍵を読み込むヘルパー関数
EVP_PKEY* nkCryptoToolPQC::loadPublicKey(const std::filesystem::path& public_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"));
    if (!pub_bio) {
        std::cerr << "Error: Could not open public key file for reading: " << public_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, pem_passwd_cb, nullptr);
    if (!pub_key) {
        std::cerr << "Error: Could not read public key from file: " << public_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    return pub_key;
}

// 秘密鍵を読み込むヘルパー関数
EVP_PKEY* nkCryptoToolPQC::loadPrivateKey(const std::filesystem::path& private_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"));
    if (!priv_bio) {
        std::cerr << "Error: Could not open private key file for reading: " << private_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    EVP_PKEY* priv_key = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, nullptr);
    if (!priv_key) {
        std::cerr << "Error: Could not read private key from file: " << private_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    return priv_key;
}

// HKDF導出のヘルパー関数
std::vector<unsigned char> nkCryptoToolPQC::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                                  const std::string& salt_str, const std::string& info_str,
                                                  const std::string& digest_algo_name) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        std::cerr << "Error: EVP_KDF_fetch failed for HKDF." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        std::cerr << "Error: EVP_KDF_CTX_new failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    OSSL_PARAM params[5];
    int p = 0;

    params[p++] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest_algo_name.c_str(), 0);
    params[p++] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());

    if (!salt_str.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string("salt", (void*)salt_str.c_str(), salt_str.length());
    }

    if (!info_str.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string("info", (void*)info_str.c_str(), info_str.length());
    }

    params[p++] = OSSL_PARAM_construct_end();

    std::vector<unsigned char> derived_key(output_len);
    if (EVP_KDF_derive(kctx.get(), derived_key.data(), output_len, params) <= 0) {
        std::cerr << "Error: EVP_KDF_derive failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    return derived_key;
}

// AES-GCM暗号化のヘルパー関数
bool nkCryptoToolPQC::aesGcmEncrypt(const std::vector<unsigned char>& plaintext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                std::vector<unsigned char>& ciphertext,
                                std::vector<unsigned char>& tag) {
    if (key.size() != 32) { // AES-256鍵サイズ
        std::cerr << "Error: Invalid key size for AES-GCM encryption." << std::endl;
        return false;
    }
    if (iv.size() != 12) { // GCM推奨IVサイズ
        std::cerr << "Error: Invalid IV size for AES-GCM encryption." << std::endl;
        return false;
    }

    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        std::cerr << "Error: EVP_CIPHER_CTX_new failed (AES-GCM encrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        std::cerr << "Error: EVP_EncryptInit_ex failed (AES-GCM encrypt init)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (iv.size() != 12) {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)) {
            std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set IV len) failed (AES-GCM encrypt)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
    }

    if (1 != EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data())) {
        std::cerr << "Error: EVP_EncryptInit_ex (set key/IV) failed (AES-GCM encrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    ciphertext.resize(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx.get()));
    int len;
    if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size()))) {
        std::cerr << "Error: EVP_EncryptUpdate failed (AES-GCM encrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    size_t ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len)) {
        std::cerr << "Error: EVP_EncryptFinal_ex failed (AES-GCM encrypt final)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    tag.resize(EVP_GCM_TLS_TAG_LEN); // GCM推奨タグサイズ (通常16バイト)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data())) {
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (get tag) failed (AES-GCM encrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

// AES-GCM複合のヘルパー関数
bool nkCryptoToolPQC::aesGcmDecrypt(const std::vector<unsigned char>& ciphertext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                const std::vector<unsigned char>& tag,
                                std::vector<unsigned char>& plaintext) {
    if (key.size() != 32) { // AES-256鍵サイズ
        std::cerr << "Error: Invalid key size for AES-GCM decryption." << std::endl;
        return false;
    }
    if (iv.size() != 12) { // GCM推奨IVサイズ
        std::cerr << "Error: Invalid IV size for AES-GCM decryption." << std::endl;
        return false;
    }
    if (tag.size() != EVP_GCM_TLS_TAG_LEN) { // GCM推奨タグサイズ
        std::cerr << "Error: Invalid tag size for AES-GCM decryption." << std::endl;
        return false;
    }

    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        std::cerr << "Error: EVP_CIPHER_CTX_new failed (AES-GCM decrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        std::cerr << "Error: EVP_DecryptInit_ex failed (AES-GCM decrypt init)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (iv.size() != 12) {
        if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr)) {
            std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set IV len) failed (AES-GCM decrypt)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
    }

    if (1 != EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data())) {
        std::cerr << "Error: EVP_DecryptInit_ex (set key/IV) failed (AES-GCM decrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    plaintext.resize(ciphertext.size());
    int len;
    if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size()))) {
        std::cerr << "Error: EVP_DecryptUpdate failed (AES-GCM decrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    int plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data())) {
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (set tag) failed (AES-GCM decrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) {
        std::cerr << "Error: EVP_DecryptFinal_ex failed or tag mismatch." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return true;
}

// 暗号化鍵ペアを生成
bool nkCryptoToolPQC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    // 暗号化鍵生成にはML-KEM-1024を使用します。
    // OpenSSL 3.5はML-KEM-1024をサポートしています。
    // 'ML-KEM.retain_seed' や 'ML-KEM.prefer_seed' のようなパラメータは、
    // 鍵のインポート/エクスポート時や、明示的なフォーマット制御を伴う 'openssl genpkey' を使用する際に、
    // 特定の鍵フォーマット（例：FIPS 203 'dk' フォーマット vs. シードフォーマット）を扱う場合に使用されます。
    // 直接 EVP_PKEY_keygen を使用する場合、OpenSSL は通常、完全な鍵を生成します。
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
    if (!pctx) {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_name failed for ML-KEM-1024." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: EVP_PKEY_keygen_init failed for ML-KEM-1024." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) {
        std::cerr << "Error: EVP_PKEY_keygen failed for ML-KEM-1024." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(raw_pkey);

    // 秘密鍵をファイルに書き込む
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) {
        std::cerr << "Error: Could not open private key file for writing: " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(),
                                      (char*)passphrase.c_str(), (int)passphrase.length(),
                                      pem_passwd_cb, nullptr) <= 0) {
        std::cerr << "Error: PEM_write_bio_PKCS8PrivateKey failed (ML-KEM-1024 private key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // 公開鍵をファイルに書き込む
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        std::cerr << "Error: Could not open public key file for writing: " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        std::cerr << "Error: PEM_write_bio_PUBKEY failed (ML-KEM-1024 public key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

// 署名鍵ペアを生成
bool nkCryptoToolPQC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    // OpenSSL 3.5でサポートされているML-DSA (Dilithium) のバリアント:
    // ML-DSA-44 (セキュリティカテゴリ2、128ビット強度)
    // ML-DSA-65 (セキュリティカテゴリ3、192ビット強度) - ML-DSA-87に対応
    // ML-DSA-87 (セキュリティカテゴリ5、256ビット強度)
    // この実装では、デフォルトでML-DSA-87 (ML-DSA-65) を使用します。
    // 'ml-dsa.retain_seed' や 'ml-dsa.prefer_seed' のようなパラメータは、
    // 鍵のインポート/エクスポート時や、明示的なフォーマット制御を伴う 'openssl genpkey' を使用する際に、
    // 特定の鍵フォーマット（例：FIPS 203 'dk' フォーマット vs. シードフォーマット）を扱う場合に使用されます。
    // 直接 EVP_PKEY_keygen を使用する場合、OpenSSL は通常、完全な鍵を生成します。
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
    if (!pctx) {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_name failed for ML-DSA-87." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: EVP_PKEY_keygen_init failed for ML-DSA-87." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) {
        std::cerr << "Error: EVP_PKEY_keygen failed for ML-DSA-87." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(raw_pkey);

    // 秘密鍵をファイルに書き込む
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) {
        std::cerr << "Error: Could not open private key file for writing: " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(),
                                      (char*)passphrase.c_str(), (int)passphrase.length(),
                                      pem_passwd_cb, nullptr) <= 0) {
        std::cerr << "Error: PEM_write_bio_PKCS8PrivateKey failed (ML-DSA-87 private key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // 公開鍵をファイルに書き込む
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        std::cerr << "Error: Could not open public key file for writing: " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        std::cerr << "Error: PEM_write_bio_PUBKEY failed (ML-DSA-87 public key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

// ファイルを暗号化
bool nkCryptoToolPQC::encryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path) {
    try {
        std::vector<unsigned char> plaintext = readFile(input_filepath);

        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_pub_key(loadPublicKey(recipient_public_key_path));
        if (!recipient_pub_key) {
            std::cerr << "Error: Failed to load recipient public key." << std::endl;
            return false;
        }

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new(recipient_pub_key.get(), nullptr));
        if (!pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed (KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // カプセル化のために初期化
        // 修正: params引数にnullptrを渡す
        if (1 != EVP_PKEY_encapsulate_init(pctx.get(), nullptr)) {
            std::cerr << "Error: EVP_PKEY_encapsulate_init failed (KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        size_t enc_key_len; // カプセル化された鍵の長さ (KEMの暗号文)
        size_t shared_secret_len; // 共有シークレットの長さ (導出された対称鍵)

        // カプセル化された鍵と共有シークレットのバッファ長を決定
        // EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx, unsigned char *wrappedkey, size_t *wrappedkeylen, unsigned char *ss, size_t *sslen)
        // 最初にnullバッファで呼び出して長さを取得
        if (1 != EVP_PKEY_encapsulate(pctx.get(), nullptr, &enc_key_len, nullptr, &shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_encapsulate failed to get lengths (KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> enc_key(enc_key_len); // カプセル化された鍵 (KEM暗号文)
        std::vector<unsigned char> shared_secret(shared_secret_len); // 共有シークレット (対称鍵)

        // カプセル化を実行
        if (1 != EVP_PKEY_encapsulate(pctx.get(), enc_key.data(), &enc_key_len, shared_secret.data(), &shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_encapsulate failed (KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // HKDFを使用して共有シークレットからAES鍵とIVを導出
        std::vector<unsigned char> salt(16); // HKDF用の16バイトのソルト
        if (RAND_bytes(salt.data(), (int)salt.size()) <= 0) {
            std::cerr << "Error: RAND_bytes failed to generate salt." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> hkdf_output = hkdfDerive(shared_secret, 32 + 12, // 鍵に32バイト、IVに12バイト
                                                            std::string(salt.begin(), salt.end()),
                                                            "aes-gcm-encryption-key-iv", "SHA256");
        if (hkdf_output.empty()) {
            std::cerr << "Error: HKDF derivation failed for encryption." << std::endl;
            return false;
        }

        std::vector<unsigned char> aes_key(hkdf_output.begin(), hkdf_output.begin() + 32);
        std::vector<unsigned char> aes_iv(hkdf_output.begin() + 32, hkdf_output.begin() + 32 + 12);

        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> tag;

        if (!aesGcmEncrypt(plaintext, aes_key, aes_iv, ciphertext, tag)) {
            std::cerr << "Error: AES-GCM encryption failed." << std::endl;
            return false;
        }

        // 出力データを準備: enc_key_len | enc_key | salt_len | salt | iv_len | iv | tag_len | tag | ciphertext
        std::vector<unsigned char> encrypted_output_data;

        auto add_len_to_buffer = [](std::vector<unsigned char>& buffer, size_t len) {
            for (int i = 0; i < 4; ++i) {
                buffer.push_back(static_cast<unsigned char>((len >> (i * 8)) & 0xFF));
            }
        };

        add_len_to_buffer(encrypted_output_data, enc_key.size());
        encrypted_output_data.insert(encrypted_output_data.end(), enc_key.begin(), enc_key.end());

        add_len_to_buffer(encrypted_output_data, salt.size());
        encrypted_output_data.insert(encrypted_output_data.end(), salt.begin(), salt.end());

        add_len_to_buffer(encrypted_output_data, aes_iv.size());
        encrypted_output_data.insert(encrypted_output_data.end(), aes_iv.begin(), aes_iv.end());

        add_len_to_buffer(encrypted_output_data, tag.size());
        encrypted_output_data.insert(encrypted_output_data.end(), tag.begin(), tag.end());

        encrypted_output_data.insert(encrypted_output_data.end(), ciphertext.begin(), ciphertext.end());

        if (!writeFile(output_filepath, encrypted_output_data)) {
            std::cerr << "Error: Writing encrypted output file failed." << std::endl;
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during PQC encryption: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

// ファイルをハイブリッド暗号化
bool nkCryptoToolPQC::encryptFileHybrid(
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_mlkem_public_key_path,
    const std::filesystem::path& recipient_ecdh_public_key_path) {
    try {
        std::vector<unsigned char> plaintext = readFile(input_filepath);

        // 1. ML-KEM鍵カプセル化
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> mlkem_pub_key(loadPublicKey(recipient_mlkem_public_key_path));
        if (!mlkem_pub_key) {
            std::cerr << "Error: Failed to load recipient ML-KEM public key." << std::endl;
            return false;
        }

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> mlkem_pctx(EVP_PKEY_CTX_new(mlkem_pub_key.get(), nullptr));
        if (!mlkem_pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed (ML-KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        if (1 != EVP_PKEY_encapsulate_init(mlkem_pctx.get(), nullptr)) {
            std::cerr << "Error: EVP_PKEY_encapsulate_init failed (ML-KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        size_t mlkem_enc_key_len;
        size_t mlkem_shared_secret_len;
        if (1 != EVP_PKEY_encapsulate(mlkem_pctx.get(), nullptr, &mlkem_enc_key_len, nullptr, &mlkem_shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_encapsulate failed to get lengths (ML-KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> mlkem_enc_key(mlkem_enc_key_len);
        std::vector<unsigned char> mlkem_shared_secret(mlkem_shared_secret_len);
        if (1 != EVP_PKEY_encapsulate(mlkem_pctx.get(), mlkem_enc_key.data(), &mlkem_enc_key_len, mlkem_shared_secret.data(), &mlkem_shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_encapsulate failed (ML-KEM encapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // 2. ECDH鍵共有
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ecdh_pub_key(loadPublicKey(recipient_ecdh_public_key_path));
        if (!ecdh_pub_key) {
            std::cerr << "Error: Failed to load recipient ECDH public key." << std::endl;
            return false;
        }

        // 送信者側で一時的なECDH鍵ペアを生成
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_gen_pctx(EVP_PKEY_CTX_new_from_name(nullptr, "prime256v1", nullptr));
        if (!ecdh_gen_pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new_from_name failed for prime256v1 (ECDH key gen)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (EVP_PKEY_keygen_init(ecdh_gen_pctx.get()) <= 0) {
            std::cerr << "Error: EVP_PKEY_keygen_init failed (ECDH key gen)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        EVP_PKEY* raw_sender_ecdh_priv_key = nullptr;
        if (EVP_PKEY_keygen(ecdh_gen_pctx.get(), &raw_sender_ecdh_priv_key) <= 0) {
            std::cerr << "Error: EVP_PKEY_keygen failed (ECDH key gen)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_ecdh_priv_key(raw_sender_ecdh_priv_key);

        // 送信者の公開鍵を抽出
        std::unique_ptr<BIO, BIO_Deleter> sender_ecdh_pub_bio(BIO_new(BIO_s_mem()));
        if (!sender_ecdh_pub_bio || PEM_write_bio_PUBKEY(sender_ecdh_pub_bio.get(), sender_ecdh_priv_key.get()) <= 0) {
            std::cerr << "Error: Failed to write sender ECDH public key to BIO." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        BUF_MEM *bptr;
        BIO_get_mem_ptr(sender_ecdh_pub_bio.get(), &bptr);
        std::vector<unsigned char> sender_ecdh_pub_key_bytes(bptr->data, bptr->data + bptr->length);

        // ECDH共有シークレットを導出
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_derive_pctx(EVP_PKEY_CTX_new(sender_ecdh_priv_key.get(), nullptr));
        if (!ecdh_derive_pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (1 != EVP_PKEY_derive_init(ecdh_derive_pctx.get())) {
            std::cerr << "Error: EVP_PKEY_derive_init failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (1 != EVP_PKEY_derive_set_peer(ecdh_derive_pctx.get(), ecdh_pub_key.get())) {
            std::cerr << "Error: EVP_PKEY_derive_set_peer failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        size_t ecdh_shared_secret_len;
        if (1 != EVP_PKEY_derive(ecdh_derive_pctx.get(), nullptr, &ecdh_shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_derive failed to get length (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        std::vector<unsigned char> ecdh_shared_secret(ecdh_shared_secret_len);
        if (1 != EVP_PKEY_derive(ecdh_derive_pctx.get(), ecdh_shared_secret.data(), &ecdh_shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_derive failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // 3. 共通鍵の導出 (ML-KEMとECDHの共有シークレットを連結)
        std::vector<unsigned char> combined_secret;
        combined_secret.insert(combined_secret.end(), mlkem_shared_secret.begin(), mlkem_shared_secret.end());
        combined_secret.insert(combined_secret.end(), ecdh_shared_secret.begin(), ecdh_shared_secret.end());

        std::vector<unsigned char> salt(16); // HKDF用の16バイトのソルト
        if (RAND_bytes(salt.data(), (int)salt.size()) <= 0) {
            std::cerr << "Error: RAND_bytes failed to generate salt." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> hkdf_output = hkdfDerive(combined_secret, 32 + 12, // 鍵に32バイト、IVに12バイト
                                                            std::string(salt.begin(), salt.end()),
                                                            "hybrid-encryption-key-iv", "SHA256");
        if (hkdf_output.empty()) {
            std::cerr << "Error: HKDF derivation failed for hybrid encryption." << std::endl;
            return false;
        }

        std::vector<unsigned char> aes_key(hkdf_output.begin(), hkdf_output.begin() + 32);
        std::vector<unsigned char> aes_iv(hkdf_output.begin() + 32, hkdf_output.begin() + 32 + 12);

        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> tag;

        if (!aesGcmEncrypt(plaintext, aes_key, aes_iv, ciphertext, tag)) {
            std::cerr << "Error: AES-GCM encryption failed for hybrid encryption." << std::endl;
            return false;
        }

        // 出力データを準備: mlkem_enc_key_len | mlkem_enc_key | sender_ecdh_pub_key_len | sender_ecdh_pub_key | salt_len | salt | iv_len | iv | tag_len | tag | ciphertext
        std::vector<unsigned char> encrypted_output_data;

        auto add_len_to_buffer = [](std::vector<unsigned char>& buffer, size_t len) {
            for (int i = 0; i < 4; ++i) {
                buffer.push_back(static_cast<unsigned char>((len >> (i * 8)) & 0xFF));
            }
        };

        add_len_to_buffer(encrypted_output_data, mlkem_enc_key.size());
        encrypted_output_data.insert(encrypted_output_data.end(), mlkem_enc_key.begin(), mlkem_enc_key.end());

        add_len_to_buffer(encrypted_output_data, sender_ecdh_pub_key_bytes.size());
        encrypted_output_data.insert(encrypted_output_data.end(), sender_ecdh_pub_key_bytes.begin(), sender_ecdh_pub_key_bytes.end());

        add_len_to_buffer(encrypted_output_data, salt.size());
        encrypted_output_data.insert(encrypted_output_data.end(), salt.begin(), salt.end());

        add_len_to_buffer(encrypted_output_data, aes_iv.size());
        encrypted_output_data.insert(encrypted_output_data.end(), aes_iv.begin(), aes_iv.end());

        add_len_to_buffer(encrypted_output_data, tag.size());
        encrypted_output_data.insert(encrypted_output_data.end(), tag.begin(), tag.end());

        encrypted_output_data.insert(encrypted_output_data.end(), ciphertext.begin(), ciphertext.end());

        if (!writeFile(output_filepath, encrypted_output_data)) {
            std::cerr << "Error: Writing encrypted output file failed for hybrid encryption." << std::endl;
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during PQC hybrid encryption: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

// ファイルを複合
bool nkCryptoToolPQC::decryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) {
    try {
        std::vector<unsigned char> encrypted_input_data = readFile(input_filepath);

        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> user_priv_key(loadPrivateKey(user_private_key_path));
        if (!user_priv_key) {
            std::cerr << "Error: Failed to load user private key." << std::endl;
            return false;
        }

        size_t offset = 0;
        auto get_len_from_buffer = [](const std::vector<unsigned char>& buffer, size_t& current_offset) {
            size_t len = 0;
            if (current_offset + 4 > buffer.size()) {
                throw std::runtime_error("Buffer too short to read length.");
            }
            for (int i = 0; i < 4; ++i) {
                len |= (static_cast<size_t>(buffer[current_offset++]) << (i * 8));
            }
            return len;
        };

        size_t enc_key_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + enc_key_len > encrypted_input_data.size()) {
            std::cerr << "Error: Encapsulated key data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> enc_key(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + enc_key_len);
        offset += enc_key_len;

        size_t salt_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + salt_len > encrypted_input_data.size()) {
            std::cerr << "Error: Salt data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> salt(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + salt_len);
        offset += salt_len;

        size_t iv_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + iv_len > encrypted_input_data.size()) {
            std::cerr << "Error: IV data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> aes_iv(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + iv_len);
        offset += iv_len;

        size_t tag_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + tag_len > encrypted_input_data.size()) {
            std::cerr << "Error: Tag data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> tag(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + tag_len);
        offset += tag_len;

        std::vector<unsigned char> ciphertext(encrypted_input_data.begin() + offset, encrypted_input_data.end());

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new(user_priv_key.get(), nullptr));
        if (!pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed (KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // デカプセル化のために初期化
        // 修正: params引数にnullptrを渡す
        if (1 != EVP_PKEY_decapsulate_init(pctx.get(), nullptr)) {
            std::cerr << "Error: EVP_PKEY_decapsulate_init failed (KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        size_t shared_secret_len;
        // 共有シークレットのバッファ長を決定
        // EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx, unsigned char *ss, size_t *sslen, const unsigned char *wrappedkey, size_t wrappedkeylen)
        // 最初にnullバッファで呼び出して長さを取得
        if (1 != EVP_PKEY_decapsulate(pctx.get(), nullptr, &shared_secret_len, enc_key.data(), enc_key.size())) {
            std::cerr << "Error: EVP_PKEY_decapsulate failed to get length (KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> shared_secret(shared_secret_len);
        // デカプセル化を実行
        if (1 != EVP_PKEY_decapsulate(pctx.get(), shared_secret.data(), &shared_secret_len, enc_key.data(), enc_key.size())) {
            std::cerr << "Error: EVP_PKEY_decapsulate failed (KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // HKDFを使用してAES鍵とIVを導出
        std::string salt_str(salt.begin(), salt.end());
        std::vector<unsigned char> hkdf_output = hkdfDerive(shared_secret, 32 + 12,
                                                            salt_str,
                                                            "aes-gcm-encryption-key-iv", "SHA256");
        if (hkdf_output.empty()) {
            std::cerr << "Error: HKDF derivation failed for decryption." << std::endl;
            return false;
        }

        std::vector<unsigned char> aes_key(hkdf_output.begin(), hkdf_output.begin() + 32);
        std::vector<unsigned char> aes_iv_derived(hkdf_output.begin() + 32, hkdf_output.begin() + 32 + 12);

        if (aes_iv_derived != aes_iv) {
            std::cerr << "Warning: Derived IV does not match stored IV. Decryption might fail." << std::endl;
        }

        std::vector<unsigned char> plaintext;
        if (!aesGcmDecrypt(ciphertext, aes_key, aes_iv, tag, plaintext)) {
            std::cerr << "Error: AES-GCM decryption failed." << std::endl;
            return false;
        }

        if (!writeFile(output_filepath, plaintext)) {
            std::cerr << "Error: Writing decrypted output file failed at writeFile step." << std::endl;
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during PQC decryption: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

// ファイルをハイブリッド複合
bool nkCryptoToolPQC::decryptFileHybrid(
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_mlkem_private_key_path,
    const std::filesystem::path& recipient_ecdh_private_key_path) {
    try {
        std::vector<unsigned char> encrypted_input_data = readFile(input_filepath);

        size_t offset = 0;
        auto get_len_from_buffer = [](const std::vector<unsigned char>& buffer, size_t& current_offset) {
            size_t len = 0;
            if (current_offset + 4 > buffer.size()) {
                throw std::runtime_error("Buffer too short to read length.");
            }
            for (int i = 0; i < 4; ++i) {
                len |= (static_cast<size_t>(buffer[current_offset++]) << (i * 8));
            }
            return len;
        };

        size_t mlkem_enc_key_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + mlkem_enc_key_len > encrypted_input_data.size()) {
            std::cerr << "Error: ML-KEM encapsulated key data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> mlkem_enc_key(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + mlkem_enc_key_len);
        offset += mlkem_enc_key_len;

        size_t sender_ecdh_pub_key_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + sender_ecdh_pub_key_len > encrypted_input_data.size()) {
            std::cerr << "Error: Sender ECDH public key data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> sender_ecdh_pub_key_bytes(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + sender_ecdh_pub_key_len);
        offset += sender_ecdh_pub_key_len;

        size_t salt_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + salt_len > encrypted_input_data.size()) {
            std::cerr << "Error: Salt data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> salt(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + salt_len);
        offset += salt_len;

        size_t iv_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + iv_len > encrypted_input_data.size()) {
            std::cerr << "Error: IV data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> aes_iv(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + iv_len);
        offset += iv_len;

        size_t tag_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + tag_len > encrypted_input_data.size()) {
            std::cerr << "Error: Tag data out of bounds." << std::endl;
            return false;
        }
        std::vector<unsigned char> tag(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + tag_len);
        offset += tag_len;

        std::vector<unsigned char> ciphertext(encrypted_input_data.begin() + offset, encrypted_input_data.end());

        // 1. ML-KEM鍵デカプセル化
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> mlkem_priv_key(loadPrivateKey(recipient_mlkem_private_key_path));
        if (!mlkem_priv_key) {
            std::cerr << "Error: Failed to load recipient ML-KEM private key." << std::endl;
            return false;
        }

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> mlkem_pctx(EVP_PKEY_CTX_new(mlkem_priv_key.get(), nullptr));
        if (!mlkem_pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed (ML-KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        if (1 != EVP_PKEY_decapsulate_init(mlkem_pctx.get(), nullptr)) {
            std::cerr << "Error: EVP_PKEY_decapsulate_init failed (ML-KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        size_t mlkem_shared_secret_len;
        if (1 != EVP_PKEY_decapsulate(mlkem_pctx.get(), nullptr, &mlkem_shared_secret_len, mlkem_enc_key.data(), mlkem_enc_key.size())) {
            std::cerr << "Error: EVP_PKEY_decapsulate failed to get length (ML-KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> mlkem_shared_secret(mlkem_shared_secret_len);
        if (1 != EVP_PKEY_decapsulate(mlkem_pctx.get(), mlkem_shared_secret.data(), &mlkem_shared_secret_len, mlkem_enc_key.data(), mlkem_enc_key.size())) {
            std::cerr << "Error: EVP_PKEY_decapsulate failed (ML-KEM decapsulate)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // 2. ECDH鍵共有
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ecdh_priv_key(loadPrivateKey(recipient_ecdh_private_key_path));
        if (!ecdh_priv_key) {
            std::cerr << "Error: Failed to load recipient ECDH private key." << std::endl;
            return false;
        }

        std::unique_ptr<BIO, BIO_Deleter> sender_ecdh_pub_bio(BIO_new_mem_buf(sender_ecdh_pub_key_bytes.data(), (int)sender_ecdh_pub_key_bytes.size()));
        if (!sender_ecdh_pub_bio) {
            std::cerr << "Error: Failed to create BIO from sender ECDH public key bytes." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_ecdh_pub_key(PEM_read_bio_PUBKEY(sender_ecdh_pub_bio.get(), nullptr, nullptr, nullptr));
        if (!sender_ecdh_pub_key) {
            std::cerr << "Error: Failed to read sender ECDH public key from bytes." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_derive_pctx(EVP_PKEY_CTX_new(ecdh_priv_key.get(), nullptr));
        if (!ecdh_derive_pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (1 != EVP_PKEY_derive_init(ecdh_derive_pctx.get())) {
            std::cerr << "Error: EVP_PKEY_derive_init failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (1 != EVP_PKEY_derive_set_peer(ecdh_derive_pctx.get(), sender_ecdh_pub_key.get())) {
            std::cerr << "Error: EVP_PKEY_derive_set_peer failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        size_t ecdh_shared_secret_len;
        if (1 != EVP_PKEY_derive(ecdh_derive_pctx.get(), nullptr, &ecdh_shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_derive failed to get length (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        std::vector<unsigned char> ecdh_shared_secret(ecdh_shared_secret_len);
        if (1 != EVP_PKEY_derive(ecdh_derive_pctx.get(), ecdh_shared_secret.data(), &ecdh_shared_secret_len)) {
            std::cerr << "Error: EVP_PKEY_derive failed (ECDH derive)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // 3. 共通鍵の導出 (ML-KEMとECDHの共有シークレットを連結)
        std::vector<unsigned char> combined_secret;
        combined_secret.insert(combined_secret.end(), mlkem_shared_secret.begin(), mlkem_shared_secret.end());
        combined_secret.insert(combined_secret.end(), ecdh_shared_secret.begin(), ecdh_shared_secret.end());

        std::string salt_str(salt.begin(), salt.end());
        std::vector<unsigned char> hkdf_output = hkdfDerive(combined_secret, 32 + 12,
                                                            salt_str,
                                                            "hybrid-encryption-key-iv", "SHA256");
        if (hkdf_output.empty()) {
            std::cerr << "Error: HKDF derivation failed for hybrid decryption." << std::endl;
            return false;
        }

        std::vector<unsigned char> aes_key(hkdf_output.begin(), hkdf_output.begin() + 32);
        std::vector<unsigned char> aes_iv_derived(hkdf_output.begin() + 32, hkdf_output.begin() + 32 + 12);

        if (aes_iv_derived != aes_iv) {
            std::cerr << "Warning: Derived IV does not match stored IV. Decryption might fail." << std::endl;
        }

        std::vector<unsigned char> plaintext;
        if (!aesGcmDecrypt(ciphertext, aes_key, aes_iv, tag, plaintext)) {
            std::cerr << "Error: AES-GCM decryption failed for hybrid decryption." << std::endl;
            return false;
        }

        if (!writeFile(output_filepath, plaintext)) {
            std::cerr << "Error: Writing decrypted output file failed at writeFile step." << std::endl;
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during PQC hybrid decryption: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

// ファイルに署名
bool nkCryptoToolPQC::signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, 
                           const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) {
    EVP_PKEY_CTX* sctx = nullptr;
    EVP_SIGNATURE* sig_alg = nullptr;

    try {
        // ファイル内容を読み込み
        std::vector<unsigned char> file_content = readFile(input_filepath);

        // 秘密鍵をロード
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> priv_key(loadPrivateKey(signing_private_key_path));
        if (!priv_key) {
            std::cerr << "エラー: 秘密鍵の読み込みに失敗しました。" << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // EVP_PKEY_CTX を作成
        sctx = EVP_PKEY_CTX_new_from_pkey(nullptr, priv_key.get(), nullptr);
        if (!sctx) {
            std::cerr << "エラー: EVP_PKEY_CTX_new_from_pkey に失敗しました。" << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // ML-DSA-87 の署名アルゴリズムをフェッチ
        sig_alg = EVP_SIGNATURE_fetch(nullptr, "ML-DSA-87", nullptr);
        if (!sig_alg) {
            std::cerr << "エラー: EVP_SIGNATURE_fetch（ML-DSA-87）に失敗しました。" << std::endl;
            printOpenSSLErrors();
            EVP_PKEY_CTX_free(sctx);
            return false;
        }

        // コンテキスト文字列（オプション）
        const OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string("context-string", (unsigned char*)"A context string", 16),
            OSSL_PARAM_END
        };

        // 署名プロセスを初期化
        if (1 != EVP_PKEY_sign_message_init(sctx, sig_alg, params)) {
            std::cerr << "エラー: EVP_PKEY_sign_message_init に失敗しました。" << std::endl;
            printOpenSSLErrors();
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(sctx);
            return false;
        }

        // 署名のサイズを計算
        size_t sig_len;
        if (1 != EVP_PKEY_sign(sctx, nullptr, &sig_len, file_content.data(), file_content.size())) {
            std::cerr << "エラー: 署名の長さ取得に失敗しました。" << std::endl;
            printOpenSSLErrors();
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(sctx);
            return false;
        }

        // 署名バッファを確保
        std::vector<unsigned char> signature(sig_len);
        if (1 != EVP_PKEY_sign(sctx, signature.data(), &sig_len, file_content.data(), file_content.size())) {
            std::cerr << "エラー: 署名生成に失敗しました。" << std::endl;
            printOpenSSLErrors();
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(sctx);
            return false;
        }
        signature.resize(sig_len);

        // 署名をファイルに書き込み
        if (!writeFile(signature_filepath, signature)) {
            std::cerr << "エラー: 署名ファイルの書き込みに失敗しました。" << std::endl;
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(sctx);
            return false;
        }

        // クリーンアップ
        EVP_SIGNATURE_free(sig_alg);
        EVP_PKEY_CTX_free(sctx);
        return true;

    } catch (const std::exception& e) {
        std::cerr << "PQC署名中のエラー: " << e.what() << std::endl;
        printOpenSSLErrors();
        if (sig_alg) EVP_SIGNATURE_free(sig_alg);
        if (sctx) EVP_PKEY_CTX_free(sctx);
        return false;
    }
}

// 署名を検証
bool nkCryptoToolPQC::verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) {
    EVP_PKEY_CTX* vctx = nullptr;
    EVP_SIGNATURE* sig_alg = nullptr;

    try {
        // ファイル内容と署名を読み込み
        std::vector<unsigned char> file_content = readFile(input_filepath);
        std::vector<unsigned char> signature = readFile(signature_filepath);

        // 公開鍵をロード
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pub_key(loadPublicKey(signing_public_key_path));
        if (!pub_key) {
            std::cerr << "エラー: 公開鍵の読み込みに失敗しました。" << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // EVP_PKEY_CTX を作成
        vctx = EVP_PKEY_CTX_new_from_pkey(nullptr, pub_key.get(), nullptr);
        if (!vctx) {
            std::cerr << "エラー: EVP_PKEY_CTX_new_from_pkey に失敗しました。" << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // ML-DSA-87 の署名アルゴリズムをフェッチ
        sig_alg = EVP_SIGNATURE_fetch(nullptr, "ML-DSA-87", nullptr);
        if (!sig_alg) {
            std::cerr << "エラー: EVP_SIGNATURE_fetch（ML-DSA-87）に失敗しました。" << std::endl;
            printOpenSSLErrors();
            EVP_PKEY_CTX_free(vctx);
            return false;
        }

        // コンテキスト文字列（署名時と同じものを指定）
        const OSSL_PARAM params[] = {
            OSSL_PARAM_octet_string("context-string", (unsigned char*)"A context string", 16),
            OSSL_PARAM_END
        };

        // 検証プロセスを初期化
        if (1 != EVP_PKEY_verify_message_init(vctx, sig_alg, params)) {
            std::cerr << "エラー: EVP_PKEY_verify_message_init に失敗しました。" << std::endl;
            printOpenSSLErrors();
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(vctx);
            return false;
        }

        // 署名の検証
        int result = EVP_PKEY_verify(vctx, signature.data(), signature.size(), file_content.data(), file_content.size());
        if (result == 1) {
            // 署名が有効
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(vctx);
            return true;
        } else if (result == 0) {
            std::cerr << "エラー: 署名検証に失敗しました。署名がファイルまたは公開鍵と一致しません。" << std::endl;
            printOpenSSLErrors();
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(vctx);
            return false;
        } else {
            std::cerr << "エラー: 署名検証中にエラーが発生しました。" << std::endl;
            printOpenSSLErrors();
            EVP_SIGNATURE_free(sig_alg);
            EVP_PKEY_CTX_free(vctx);
            return false;
        }

    } catch (const std::exception& e) {
        std::cerr << "PQC署名検証中のエラー: " << e.what() << std::endl;
        printOpenSSLErrors();
        if (sig_alg) EVP_SIGNATURE_free(sig_alg);
        if (vctx) EVP_PKEY_CTX_free(vctx);
        return false;
    }
}

// デフォルトの鍵パスの仮想メソッドを実装
std::filesystem::path nkCryptoToolPQC::getEncryptionPrivateKeyPath() const {
    return getKeyBaseDirectory() / "private_enc_pqc.key";
}

std::filesystem::path nkCryptoToolPQC::getSigningPrivateKeyPath() const {
    return getKeyBaseDirectory() / "private_sign_pqc.key";
}

std::filesystem::path nkCryptoToolPQC::getEncryptionPublicKeyPath() const {
    return getKeyBaseDirectory() / "public_enc_pqc.key";
}

std::filesystem::path nkCryptoToolPQC::getSigningPublicKeyPath() const {
    return getKeyBaseDirectory() / "public_sign_pqc.key";
}

// コンストラクタとデストラクタ
nkCryptoToolPQC::nkCryptoToolPQC() {
    //
}

nkCryptoToolPQC::~nkCryptoToolPQC() {
    //
}
