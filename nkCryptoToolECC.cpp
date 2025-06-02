// nkCryptoToolECC.cpp

#include "nkCryptoToolECC.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/kdf.h> // For EVP_KDF (HKDF)
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h> // For BIGNUM functions
#include <openssl/crypto.h> // For OPENSSL_free - IMPORTANT for decltype(&OPENSSL_free)
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

struct BIGNUM_Deleter {
    void operator()(BIGNUM *b) const { BN_free(b); }
};

// Helper for OPENSSL_free with unique_ptr
// This is a common pattern when using unique_ptr with C functions that return allocated memory
// and require a specific free function (like OPENSSL_free for BN_bn2hex).
// The decltype(&OPENSSL_free) requires OPENSSL_free to be visible.
// If it's still not found, a lambda or a custom struct might be more robust.
struct OpenSSLFreeDeleter {
    void operator()(void* p) const {
        OPENSSL_free(p);
    }
};


// Helper function to print OpenSSL errors
void nkCryptoToolECC::printOpenSSLErrors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

// Helper function to load public key
EVP_PKEY* nkCryptoToolECC::loadPublicKey(const std::filesystem::path& public_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"));
    if (!pub_bio) {
        std::cerr << "Error: Could not open public key file for reading: " << public_key_path << std::endl;
        printOpenSSLErrors(); // In case BIO_new_file sets an OpenSSL error
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

// Helper function to load private key
EVP_PKEY* nkCryptoToolECC::loadPrivateKey(const std::filesystem::path& private_key_path) {
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

// Implement virtual methods
bool nkCryptoToolECC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!pctx) {
        std::cerr << "Error: EVP_PKEY_CTX_new_id failed (encryption key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: EVP_PKEY_keygen_init failed (encryption key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // Set the EC curve (NID_X9_62_prime256v1 is NIST P-256)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) {
        std::cerr << "Error: EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed (encryption key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* raw_pkey = nullptr; // Temporary raw pointer
    if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) { // Fixed: Pass address of raw pointer
        std::cerr << "Error: EVP_PKEY_keygen failed (encryption key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(raw_pkey); // Transfer ownership

    // Write private key to file
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) {
        std::cerr << "Error: Could not open private key file for writing: " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    // Fixed: Correct function name PEM_write_bio_PKCS8PrivateKey
    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(),
                                      (char*)passphrase.c_str(), (int)passphrase.length(),
                                      pem_passwd_cb, nullptr) <= 0) {
        std::cerr << "Error: PEM_write_bio_PKCS8PrivateKey failed (encryption private key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // Write public key to file
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        std::cerr << "Error: Could not open public key file for writing: " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        std::cerr << "Error: PEM_write_bio_PUBKEY failed (encryption public key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

bool nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!pctx) {
        std::cerr << "Error: EVP_PKEY_CTX_new_id failed (signing key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: EVP_PKEY_keygen_init failed (signing key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // Set the EC curve (NID_X9_62_prime256v1 is NIST P-256)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) {
        std::cerr << "Error: EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed (signing key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* raw_pkey = nullptr; // Temporary raw pointer
    if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) { // Fixed: Pass address of raw pointer
        std::cerr << "Error: EVP_PKEY_keygen failed (signing key generation)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(raw_pkey); // Transfer ownership

    // Write private key to file
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) {
        std::cerr << "Error: Could not open private key file for writing: " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    // Fixed: Correct function name PEM_write_bio_PKCS8PrivateKey
    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(),
                                      (char*)passphrase.c_str(), (int)passphrase.length(),
                                      pem_passwd_cb, nullptr) <= 0) {
        std::cerr << "Error: PEM_write_bio_PKCS8PrivateKey failed (signing private key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    // Write public key to file
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        std::cerr << "Error: Could not open public key file for writing: " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        std::cerr << "Error: PEM_write_bio_PUBKEY failed (signing public key)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}


std::vector<unsigned char> nkCryptoToolECC::generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pkey_ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!pkey_ctx) {
        std::cerr << "Error: EVP_PKEY_CTX_new failed (shared secret)." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    if (1 != EVP_PKEY_derive_init(pkey_ctx.get())) {
        std::cerr << "Error: EVP_PKEY_derive_init failed (shared secret)." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    if (1 != EVP_PKEY_derive_set_peer(pkey_ctx.get(), peer_public_key)) {
        std::cerr << "Error: EVP_PKEY_derive_set_peer failed (shared secret)." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    size_t secret_len;
    // Determine buffer length for shared secret
    if (1 != EVP_PKEY_derive(pkey_ctx.get(), nullptr, &secret_len)) {
        std::cerr << "Error: EVP_PKEY_derive failed to get secret length (shared secret)." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    std::vector<unsigned char> secret(secret_len);
    if (1 != EVP_PKEY_derive(pkey_ctx.get(), secret.data(), &secret_len)) {
        std::cerr << "Error: EVP_PKEY_derive failed (shared secret)." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    secret.resize(secret_len); // Adjust size to actual data
    return secret;
}

std::vector<unsigned char> nkCryptoToolECC::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                                  const std::string& salt_str, const std::string& info_str,
                                                  const std::string& digest_algo_name) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        std::cerr << "Error: EVP_KDF_fetch failed for HKDF." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    // Fixed: Use EVP_KDF_CTX_Deleter
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        std::cerr << "Error: EVP_KDF_CTX_new failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    OSSL_PARAM params[5];
    int p = 0;

    // Digest algorithm for HKDF (e.g., "SHA256")
    params[p++] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest_algo_name.c_str(), 0);

    // Initial Key Material (IKM)
    params[p++] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());

    // Salt (optional, can be empty or random)
    if (!salt_str.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string("salt", (void*)salt_str.c_str(), salt_str.length());
    }

    // Info (optional, context-specific information)
    if (!info_str.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string("info", (void*)info_str.c_str(), info_str.length());
    }

    params[p++] = OSSL_PARAM_construct_end();

    std::vector<unsigned char> derived_key(output_len);
    // Fixed: kctx.get() is now correctly of type EVP_KDF_CTX*
    if (EVP_KDF_derive(kctx.get(), derived_key.data(), output_len, params) <= 0) {
        std::cerr << "Error: EVP_KDF_derive failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    return derived_key;
}

bool nkCryptoToolECC::aesGcmEncrypt(const std::vector<unsigned char>& plaintext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                std::vector<unsigned char>& ciphertext,
                                std::vector<unsigned char>& tag) {
    if (key.size() != 32) { // AES-256 key size
        std::cerr << "Error: Invalid key size for AES-GCM encryption." << std::endl;
        return false;
    }
    if (iv.size() != 12) { // GCM recommended IV size
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

    if (iv.size() != 12) { // OpenSSL default is 12 bytes. Only set if different.
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

    // No AAD for now. If there were, it would go here.
    // if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size())) { ... }

    // Encrypt plaintext.
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

    tag.resize(EVP_GCM_TLS_TAG_LEN); // GCM recommended tag size (16 bytes generally)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data())) {
        std::cerr << "Error: EVP_CIPHER_CTX_ctrl (get tag) failed (AES-GCM encrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

bool nkCryptoToolECC::aesGcmDecrypt(const std::vector<unsigned char>& ciphertext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                const std::vector<unsigned char>& tag,
                                std::vector<unsigned char>& plaintext) {
    if (key.size() != 32) { // AES-256 key size
        std::cerr << "Error: Invalid key size for AES-GCM decryption." << std::endl;
        return false;
    }
    if (iv.size() != 12) { // GCM recommended IV size
        std::cerr << "Error: Invalid IV size for AES-GCM decryption." << std::endl;
        return false;
    }
    if (tag.size() != EVP_GCM_TLS_TAG_LEN) { // GCM recommended tag size
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

    if (iv.size() != 12) { // OpenSSL default is 12 bytes. Only set if different.
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

    // No AAD for now. If there were, it would go here.
    // if (1 != EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), (int)aad.size())) { ... }

    plaintext.resize(ciphertext.size());
    int len;
    if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size()))) {
        std::cerr << "Error: EVP_DecryptUpdate failed (AES-GCM decrypt)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    int plaintext_len = len;

    // Fixed: Cast tag.data() to void*
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
    plaintext.resize(plaintext_len); // Adjust size to actual data

    return true;
}

bool nkCryptoToolECC::encryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path) {
    try {
        std::vector<unsigned char> plaintext = readFile(input_filepath);

        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_pub_key(loadPublicKey(recipient_public_key_path));
        if (!recipient_pub_key) {
            std::cerr << "Error: Failed to load recipient public key." << std::endl;
            return false;
        }

        // Generate an ephemeral EC key pair for ECDH
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!pctx) {
            std::cerr << "Error: EVP_PKEY_CTX_new_id failed (ephemeral key generation)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
            std::cerr << "Error: EVP_PKEY_keygen_init failed (ephemeral key generation)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) {
            std::cerr << "Error: EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed (ephemeral key generation)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        EVP_PKEY* raw_ephemeral_private_key = nullptr; // Temporary raw pointer
        if (EVP_PKEY_keygen(pctx.get(), &raw_ephemeral_private_key) <= 0) { // Fixed: Pass address of raw pointer
            std::cerr << "Error: EVP_PKEY_keygen failed (ephemeral key generation)." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_private_key(raw_ephemeral_private_key); // Transfer ownership

        // Derive shared secret
        std::vector<unsigned char> shared_secret = generateSharedSecret(ephemeral_private_key.get(), recipient_pub_key.get());
        if (shared_secret.empty()) {
            std::cerr << "Error: Failed to generate shared secret for encryption." << std::endl;
            return false;
        }

        // HKDF to derive AES key and IV
        std::vector<unsigned char> salt(16); // 16-byte salt for HKDF
        if (RAND_bytes(salt.data(), (int)salt.size()) <= 0) {
            std::cerr << "Error: RAND_bytes failed to generate salt." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> hkdf_output = hkdfDerive(shared_secret, 32 + 12, // 32 bytes for key, 12 bytes for IV
                                                            std::string(salt.begin(), salt.end()), // Convert salt to string for HKDF info
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
            // aesGcmEncrypt already prints specific errors
            return false;
        }

        // Get the ephemeral public key coordinates as hex strings
        // Deprecated functions will be used as they are available in OpenSSL 1.1.x and OpenSSL 3.0 via compatibility
        // For OpenSSL 3.0+ proper migration would involve OSSL_PARAM for EC key parameters
        const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(ephemeral_private_key.get()); // Warning: Deprecated
        if (!ec_key) {
            std::cerr << "Error: Could not get EC_KEY from ephemeral private key." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::unique_ptr<BIGNUM, BIGNUM_Deleter> x(BN_new());
        std::unique_ptr<BIGNUM, BIGNUM_Deleter> y(BN_new());
        if (!x || !y) {
            std::cerr << "Error: Failed to allocate BIGNUMs." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key); // Warning: Deprecated
        const EC_GROUP* group = EC_KEY_get0_group(ec_key); // Warning: Deprecated

        if (!EC_POINT_get_affine_coordinates_GFp(group, pub_point, x.get(), y.get(), nullptr)) { // Warning: Deprecated
            std::cerr << "Error: Failed to get affine coordinates of ephemeral public key." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // BN_bn2hex returns a char* which must be freed with OPENSSL_free
        // Fixed: Use the custom OpenSSLFreeDeleter
        std::unique_ptr<char, OpenSSLFreeDeleter> x_hex(BN_bn2hex(x.get()));
        std::unique_ptr<char, OpenSSLFreeDeleter> y_hex(BN_bn2hex(y.get()));

        if (!x_hex || !y_hex) {
            std::cerr << "Error: Failed to convert BIGNUM to hex string." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // Fixed: Use .get() on the unique_ptr to access the raw char*
        std::string ephemeral_pub_x_str(x_hex.get());
        std::string ephemeral_pub_y_str(y_hex.get());

        // Prepare output data: ephemeral_pub_x_len | ephemeral_pub_x | ephemeral_pub_y_len | ephemeral_pub_y | salt_len | salt | iv_len | iv | tag_len | tag | ciphertext
        std::vector<unsigned char> encrypted_output_data;

        auto add_len_to_buffer = [](std::vector<unsigned char>& buffer, size_t len) {
            // Using 4 bytes for length, assuming lengths won't exceed 2^32-1
            // This is a simple conversion; proper byte order isn't strictly enforced for these internal lengths.
            // However, it's safer to convert to fixed-size integer and then to byte array.
            for (int i = 0; i < 4; ++i) {
                buffer.push_back(static_cast<unsigned char>((len >> (i * 8)) & 0xFF));
            }
        };

        add_len_to_buffer(encrypted_output_data, ephemeral_pub_x_str.length());
        encrypted_output_data.insert(encrypted_output_data.end(), ephemeral_pub_x_str.begin(), ephemeral_pub_x_str.end());

        add_len_to_buffer(encrypted_output_data, ephemeral_pub_y_str.length());
        encrypted_output_data.insert(encrypted_output_data.end(), ephemeral_pub_y_str.begin(), ephemeral_pub_y_str.end());

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
        std::cerr << "Error during encryption: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

bool nkCryptoToolECC::encryptFileHybrid(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_ecdh_public_key_path, const std::filesystem::path& recipient_public_key_path) {
    // This function is not implemented in the original code, so we will return false.
    std::cerr << "Error: Hybrid encryption is not implemented." << std::endl;
    return false;
}

bool nkCryptoToolECC::decryptFile(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) {
    try {
        std::vector<unsigned char> encrypted_input_data = readFile(input_filepath);

        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> user_priv_key(loadPrivateKey(user_private_key_path));
        if (!user_priv_key) {
            std::cerr << "Error: Failed to load user private key." << std::endl;
            return false;
        }

        // This argument is for signature verification, not for decryption.
        // As per the requirement, we are using the sender's public key (the one used to encrypt the file, which is recipient_public_key in encryptFile)
        // to derive the shared secret. So, load sender's public key.
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_pub_key(loadPublicKey(sender_public_key_path));
        if (!sender_pub_key) {
            std::cerr << "Error: Failed to load sender public key for shared secret derivation." << std::endl;
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

        size_t ephemeral_pub_x_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + ephemeral_pub_x_len > encrypted_input_data.size()) {
            std::cerr << "Error: Ephemeral public X data out of bounds." << std::endl;
            return false;
        }
        std::string ephemeral_pub_x_str(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + ephemeral_pub_x_len);
        offset += ephemeral_pub_x_len;

        size_t ephemeral_pub_y_len = get_len_from_buffer(encrypted_input_data, offset);
        if (offset + ephemeral_pub_y_len > encrypted_input_data.size()) {
            std::cerr << "Error: Ephemeral public Y data out of bounds." << std::endl;
            return false;
        }
        std::string ephemeral_pub_y_str(encrypted_input_data.begin() + offset, encrypted_input_data.begin() + offset + ephemeral_pub_y_len);
        offset += ephemeral_pub_y_len;

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


        // Reconstruct ephemeral public key from coordinates
        std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ephemeral_ec_pub_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free); // Warnings: Deprecated functions
        if (!ephemeral_ec_pub_key) {
            std::cerr << "Error: EC_KEY_new_by_curve_name failed." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::unique_ptr<BIGNUM, BIGNUM_Deleter> x_bn(BN_new());
        std::unique_ptr<BIGNUM, BIGNUM_Deleter> y_bn(BN_new());
        if (!x_bn || !y_bn) {
            std::cerr << "Error: Failed to allocate BIGNUMs for ephemeral public key." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // BN_hex2bn needs BIGNUM** so we need to get the raw pointer and pass its address.
        // It allocates a new BIGNUM if the first argument is nullptr, or uses the provided one.
        // To ensure unique_ptr manages the memory, we should let it allocate if it's nullptr,
        // or ensure it takes ownership of the one we provide.
        // The current pattern with raw_x_bn and raw_y_bn and then release/reset is correct for this.
        BIGNUM* raw_x_bn = x_bn.release(); // Release ownership temporarily
        BIGNUM* raw_y_bn = y_bn.release(); // Release ownership temporarily

        if (!BN_hex2bn(&raw_x_bn, ephemeral_pub_x_str.c_str()) || !BN_hex2bn(&raw_y_bn, ephemeral_pub_y_str.c_str())) {
            std::cerr << "Error: Failed to convert ephemeral public key hex strings to BIGNUMs." << std::endl;
            printOpenSSLErrors();
            // Free raw_x_bn, raw_y_bn if they were allocated by BN_hex2bn before returning
            BN_free(raw_x_bn);
            BN_free(raw_y_bn);
            return false;
        }
        x_bn.reset(raw_x_bn); // Re-acquire ownership of the potentially new BIGNUMs
        y_bn.reset(raw_y_bn); // Re-acquire ownership


        if (!EC_KEY_set_public_key_affine_coordinates(ephemeral_ec_pub_key.get(), x_bn.get(), y_bn.get())) { // Warning: Deprecated
            std::cerr << "Error: Failed to set public key affine coordinates for ephemeral key." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // Convert EC_KEY to EVP_PKEY
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_pub_key_obj(EVP_PKEY_new());
        if (!ephemeral_pub_key_obj || !EVP_PKEY_set1_EC_KEY(ephemeral_pub_key_obj.get(), ephemeral_ec_pub_key.get())) { // Warning: Deprecated
            std::cerr << "Error: Failed to convert ephemeral EC_KEY to EVP_PKEY." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // Derive shared secret using user's private key and ephemeral public key
        std::vector<unsigned char> shared_secret = generateSharedSecret(user_priv_key.get(), ephemeral_pub_key_obj.get());
        if (shared_secret.empty()) {
            std::cerr << "Error: Failed to generate shared secret for decryption." << std::endl;
            return false;
        }

        // HKDF to derive AES key and IV
        std::string salt_str(salt.begin(), salt.end()); // Convert salt to string for HKDF info
        std::vector<unsigned char> hkdf_output = hkdfDerive(shared_secret, 32 + 12,
                                                            salt_str,
                                                            "aes-gcm-encryption-key-iv", "SHA256");
        if (hkdf_output.empty()) {
            std::cerr << "Error: HKDF derivation failed for decryption." << std::endl;
            return false;
        }

        std::vector<unsigned char> aes_key(hkdf_output.begin(), hkdf_output.begin() + 32);
        std::vector<unsigned char> aes_iv_derived(hkdf_output.begin() + 32, hkdf_output.begin() + 32 + 12);

        // Ensure the derived IV matches the IV from the file for consistency (though it should)
        if (aes_iv_derived != aes_iv) {
            std::cerr << "Warning: Derived IV does not match stored IV. Decryption might fail." << std::endl;
            // Depending on strictness, you might return false here.
            // For now, we proceed with the IV read from the file, as it's the one used for encryption.
        }

        std::vector<unsigned char> plaintext;
        if (!aesGcmDecrypt(ciphertext, aes_key, aes_iv, tag, plaintext)) {
            std::cerr << "Error: AES-GCM decryption failed." << std::endl;
            // Error already printed by aesGcmDecrypt
            return false;
        }

        // Write output file
        if (!writeFile(output_filepath, plaintext)) {
            std::cerr << "Error: Writing decrypted output file failed at writeFile step." << std::endl;
            // writeFile already prints its own error message
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during decryption: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

bool nkCryptoToolECC::decryptFileHybrid(const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path& sender_public_key_path) {
    // This function is not implemented in the original code, so we will return false.
    std::cerr << "Error: Hybrid decryption is not implemented." << std::endl;
    return false;
}

bool nkCryptoToolECC::signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) {
    try {
        std::vector<unsigned char> file_content = readFile(input_filepath);

        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> priv_key(loadPrivateKey(signing_private_key_path));
        if (!priv_key) {
            std::cerr << "Error: Failed to load signing private key." << std::endl;
            return false;
        }

        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx(EVP_MD_CTX_new());
        if (!mdctx) {
            std::cerr << "Error: EVP_MD_CTX_new failed (signing)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        const EVP_MD* md = EVP_get_digestbyname(digest_algo.c_str());
        if (!md) {
            std::cerr << "Error: Unknown digest algorithm: " << digest_algo << std::endl;
            printOpenSSLErrors();
            return false;
        }

        if (1 != EVP_DigestSignInit(mdctx.get(), nullptr, md, nullptr, priv_key.get())) {
            std::cerr << "Error: EVP_DigestSignInit failed." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        // For ECC, you might need to set the signature algorithm explicitly, e.g., ECDSA with SHA256
        // This is often handled implicitly by EVP_PKEY_EC type and the digest.
        // For simplicity, ECDSA often uses SHA256 or SHA384. If the signature doesn't
        // work, this might be a place to add specific parameters.

        if (1 != EVP_DigestSignUpdate(mdctx.get(), file_content.data(), file_content.size())) {
            std::cerr << "Error: EVP_DigestSignUpdate failed." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        size_t signature_len;
        if (1 != EVP_DigestSignFinal(mdctx.get(), nullptr, &signature_len)) {
            std::cerr << "Error: EVP_DigestSignFinal failed to get signature length." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        std::vector<unsigned char> signature(signature_len);
        if (1 != EVP_DigestSignFinal(mdctx.get(), signature.data(), &signature_len)) {
            std::cerr << "Error: EVP_DigestSignFinal failed." << std::endl;
            printOpenSSLErrors();
            return false;
        }
        signature.resize(signature_len); // Adjust size to actual data

        if (!writeFile(signature_filepath, signature)) {
            std::cerr << "Error: Writing signature file failed." << std::endl;
            return false;
        }

        return true;

    } catch (const std::exception& e) {
        std::cerr << "Error during signing: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

bool nkCryptoToolECC::verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) {
    try {
        std::vector<unsigned char> file_content = readFile(input_filepath);
        std::vector<unsigned char> signature = readFile(signature_filepath);

        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pub_key(loadPublicKey(signing_public_key_path));
        if (!pub_key) {
            std::cerr << "Error: Failed to load signing public key for verification." << std::endl;
            return false;
        }

        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx(EVP_MD_CTX_new());
        if (!mdctx) {
            std::cerr << "Error: EVP_MD_CTX_new failed (verification)." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        const EVP_MD* md = EVP_get_digestbyname("SHA256"); // Assuming SHA256 as default for verification for now
        if (!md) {
            std::cerr << "Error: Unknown digest algorithm (SHA256) for verification." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        if (1 != EVP_DigestVerifyInit(mdctx.get(), nullptr, md, nullptr, pub_key.get())) {
            std::cerr << "Error: EVP_DigestVerifyInit failed." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        if (1 != EVP_DigestVerifyUpdate(mdctx.get(), file_content.data(), file_content.size())) {
            std::cerr << "Error: EVP_DigestVerifyUpdate failed." << std::endl;
            printOpenSSLErrors();
            return false;
        }

        int result = EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size());
        if (result == 1) {
            // Signature is valid
            return true;
        } else if (result == 0) {
            std::cerr << "Error: Signature verification failed. The signature does not match the file or public key." << std::endl;
            printOpenSSLErrors();
            return false;
        } else {
            // Error occurred during verification
            std::cerr << "Error: An error occurred during signature verification." << std::endl;
            printOpenSSLErrors();
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error during signature verification: " << e.what() << std::endl;
        printOpenSSLErrors();
        return false;
    }
}

// Implement virtual methods for default key paths
std::filesystem::path nkCryptoToolECC::getEncryptionPrivateKeyPath() const {
    return getKeyBaseDirectory() / "private_enc_ecc.key";
}

std::filesystem::path nkCryptoToolECC::getSigningPrivateKeyPath() const {
    return getKeyBaseDirectory() / "private_sign_ecc.key";
}

std::filesystem::path nkCryptoToolECC::getEncryptionPublicKeyPath() const {
    return getKeyBaseDirectory() / "public_enc_ecc.key";
}

std::filesystem::path nkCryptoToolECC::getSigningPublicKeyPath() const {
    return getKeyBaseDirectory() / "public_sign_ecc.key";
}

// Constructor and Destructor
nkCryptoToolECC::nkCryptoToolECC() {
    //
}

nkCryptoToolECC::~nkCryptoToolECC() {
    //
}
