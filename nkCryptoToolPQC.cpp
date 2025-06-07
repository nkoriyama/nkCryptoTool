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
#include <openssl/obj_mac.h> // For NID_X9_62_prime256v1 (used in ECDH parts of hybrid)
#include <stdexcept> // For std::runtime_error
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/stream_file.hpp>

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
    EVP_PKEY* priv_key = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, &global_passphrase_for_pem_cb);
    if (!priv_key) {
        std::cerr << "Error: Could not read private key from file: " << private_key_path << std::endl;
        printOpenSSLErrors();
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

// Constructor and Destructor
nkCryptoToolPQC::nkCryptoToolPQC() {}
nkCryptoToolPQC::~nkCryptoToolPQC() {}

// Implement virtual methods for default key paths
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

// Key generation methods
bool nkCryptoToolPQC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: Failed to initialize ML-KEM-1024 key generation." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) {
        std::cerr << "Error: ML-KEM-1024 key generation failed." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(raw_pkey);

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio || PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(), passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()), static_cast<int>(passphrase.length()), pem_passwd_cb, nullptr) <= 0) {
        std::cerr << "Error: Failed to write ML-KEM-1024 private key." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        std::cerr << "Error: Failed to write ML-KEM-1024 public key." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    return true;
}

bool nkCryptoToolPQC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: Failed to initialize ML-DSA-87 key generation." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    EVP_PKEY* raw_pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &raw_pkey) <= 0) {
        std::cerr << "Error: ML-DSA-87 key generation failed." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey(raw_pkey);

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio || PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pkey.get(), EVP_aes_256_cbc(), passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()), static_cast<int>(passphrase.length()), pem_passwd_cb, nullptr) <= 0) {
        std::cerr << "Error: Failed to write ML-DSA-87 private key." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), pkey.get()) <= 0) {
        std::cerr << "Error: Failed to write ML-DSA-87 public key." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    return true;
}

// Asynchronous Encryption Wrappers
void nkCryptoToolPQC::encryptFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_public_key_path, std::function<void(std::error_code)> completion_handler) {
    auto state = std::make_shared<EncryptionState>(io_context);
    state->completion_handler = completion_handler;

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_kem_public_key(loadPublicKey(recipient_public_key_path));
    if (!recipient_kem_public_key) {
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    startPQCEncryptionAsync(state, input_filepath, output_filepath, recipient_kem_public_key.release(), nullptr);
}

void nkCryptoToolPQC::encryptFileHybrid(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_mlkem_public_key_path, const std::filesystem::path& recipient_ecdh_public_key_path, std::function<void(std::error_code)> completion_handler) {
    auto state = std::make_shared<EncryptionState>(io_context);
    state->completion_handler = completion_handler;

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_mlkem_public_key(loadPublicKey(recipient_mlkem_public_key_path));
    if (!recipient_mlkem_public_key) {
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_ecdh_public_key(loadPublicKey(recipient_ecdh_public_key_path));
    if (!recipient_ecdh_public_key) {
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    startPQCEncryptionAsync(state, input_filepath, output_filepath, recipient_mlkem_public_key.release(), recipient_ecdh_public_key.release());
}

// Core Encryption Logic
void nkCryptoToolPQC::startPQCEncryptionAsync(std::shared_ptr<EncryptionState> state, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, EVP_PKEY* recipient_kem_public_key_raw, EVP_PKEY* recipient_ecdh_public_key_raw) {
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_kem_public_key(recipient_kem_public_key_raw);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_ecdh_public_key(recipient_ecdh_public_key_raw);

    // Wrap original completion handler to add success message
    auto original_completion_handler = state->completion_handler;
    state->completion_handler = [output_filepath, original_completion_handler](std::error_code ec) {
        if (!ec) {
            std::cout << "PQC Encryption to '" << output_filepath.string() << "' completed successfully." << std::endl;
        }
        original_completion_handler(ec);
    };

    std::vector<unsigned char> current_shared_secret;
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_pctx(EVP_PKEY_CTX_new(recipient_kem_public_key.get(), nullptr));
    if (!kem_pctx || 1 != EVP_PKEY_encapsulate_init(kem_pctx.get(), nullptr)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    size_t enc_key_len_kem, shared_secret_len_kem;
    if (1 != EVP_PKEY_encapsulate(kem_pctx.get(), nullptr, &enc_key_len_kem, nullptr, &shared_secret_len_kem)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    state->kem_ciphertext.resize(enc_key_len_kem);
    current_shared_secret.resize(shared_secret_len_kem);
    if (1 != EVP_PKEY_encapsulate(kem_pctx.get(), state->kem_ciphertext.data(), &enc_key_len_kem, current_shared_secret.data(), &shared_secret_len_kem)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    if (recipient_ecdh_public_key) {
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_gen_pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ecdh_gen_pctx || EVP_PKEY_keygen_init(ecdh_gen_pctx.get()) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ecdh_gen_pctx.get(), NID_X9_62_prime256v1) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        EVP_PKEY* sender_ecdh_priv_key_raw = nullptr;
        if (EVP_PKEY_keygen(ecdh_gen_pctx.get(), &sender_ecdh_priv_key_raw) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_ecdh_priv_key(sender_ecdh_priv_key_raw);
        std::unique_ptr<BIO, BIO_Deleter> sender_ecdh_pub_bio(BIO_new(BIO_s_mem()));
        if (!sender_ecdh_pub_bio || PEM_write_bio_PUBKEY(sender_ecdh_pub_bio.get(), sender_ecdh_priv_key.get()) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        BUF_MEM *bptr; BIO_get_mem_ptr(sender_ecdh_pub_bio.get(), &bptr); state->ecdh_sender_pub_key.assign(bptr->data, bptr->data + bptr->length);
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_derive_pctx(EVP_PKEY_CTX_new(sender_ecdh_priv_key.get(), nullptr));
        if (!ecdh_derive_pctx || 1 != EVP_PKEY_derive_init(ecdh_derive_pctx.get()) || 1 != EVP_PKEY_derive_set_peer(ecdh_derive_pctx.get(), recipient_ecdh_public_key.get())) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        size_t shared_secret_len_ecdh;
        if (1 != EVP_PKEY_derive(ecdh_derive_pctx.get(), nullptr, &shared_secret_len_ecdh)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        std::vector<unsigned char> shared_secret_ecdh(shared_secret_len_ecdh);
        if (1 != EVP_PKEY_derive(ecdh_derive_pctx.get(), shared_secret_ecdh.data(), &shared_secret_len_ecdh)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        current_shared_secret.insert(current_shared_secret.end(), shared_secret_ecdh.begin(), shared_secret_ecdh.end());
    }
    state->salt.resize(16);
    state->iv.resize(GCM_IV_LEN);
    if (RAND_bytes(state->salt.data(), 16) <= 0 || RAND_bytes(state->iv.data(), GCM_IV_LEN) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    std::string info_str = recipient_ecdh_public_key ? "hybrid-encryption-key-iv" : "aes-gcm-encryption-key-iv";
    state->encryption_key = hkdfDerive(current_shared_secret, 32, std::string(state->salt.begin(), state->salt.end()), info_str, "SHA256");
    if (state->encryption_key.empty()) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    state->cipher_ctx.reset(EVP_CIPHER_CTX_new());
    if (!state->cipher_ctx || EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 || EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) <= 0 || EVP_EncryptInit_ex(state->cipher_ctx.get(), nullptr, nullptr, state->encryption_key.data(), state->iv.data()) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }

    asio::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) { state->completion_handler(ec); return; }
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) { state->completion_handler(ec); return; }

    // Symmetric header writing logic
    auto write_len_and_data = [this, state, is_hybrid = (recipient_ecdh_public_key != nullptr)](std::function<void(const asio::error_code&)> on_complete) {
        state->len_storage.push_back(std::make_shared<uint32_t>(state->kem_ciphertext.size()));
        asio::async_write(state->output_file, asio::buffer(state->len_storage.back().get(), sizeof(uint32_t)),
            [this, state, is_hybrid, on_complete](const asio::error_code& ec, size_t) {
                if (ec) { on_complete(ec); return; }
                asio::async_write(state->output_file, asio::buffer(state->kem_ciphertext),
                    [this, state, is_hybrid, on_complete](const asio::error_code& ec, size_t) {
                        if (ec) { on_complete(ec); return; }
                        if (is_hybrid) {
                            state->len_storage.push_back(std::make_shared<uint32_t>(state->ecdh_sender_pub_key.size()));
                            asio::async_write(state->output_file, asio::buffer(state->len_storage.back().get(), sizeof(uint32_t)),
                                [this, state, on_complete](const asio::error_code& ec, size_t) {
                                    if (ec) { on_complete(ec); return; }
                                    asio::async_write(state->output_file, asio::buffer(state->ecdh_sender_pub_key),
                                        [this, state, on_complete](const asio::error_code& ec, size_t) {
                                            if (ec) { on_complete(ec); return; }
                                            write_salt_and_iv(state, on_complete);
                                        });
                                });
                        } else {
                            write_salt_and_iv(state, on_complete);
                        }
                    });
            });
    };

    write_len_and_data([this, state](const asio::error_code& ec) {
        if (ec) {
            state->completion_handler(ec);
        } else {
            // Start reading the file to encrypt
            state->input_file.async_read_some(asio::buffer(state->input_buffer),
                asio::bind_executor(state->input_file.get_executor(),
                    std::bind(&nkCryptoToolPQC::handleFileReadForPQCEncryption, this, state,
                              std::placeholders::_1, std::placeholders::_2)));
        }
    });
}

void nkCryptoToolPQC::write_salt_and_iv(std::shared_ptr<EncryptionState> state, std::function<void(const asio::error_code&)> on_complete) {
    state->len_storage.push_back(std::make_shared<uint32_t>(state->salt.size()));
    asio::async_write(state->output_file, asio::buffer(state->len_storage.back().get(), sizeof(uint32_t)),
        [state, on_complete](const asio::error_code& ec, size_t) {
            if (ec) { on_complete(ec); return; }
            asio::async_write(state->output_file, asio::buffer(state->salt),
                [state, on_complete](const asio::error_code& ec, size_t) {
                    if (ec) { on_complete(ec); return; }
                    state->len_storage.push_back(std::make_shared<uint32_t>(state->iv.size()));
                    asio::async_write(state->output_file, asio::buffer(state->len_storage.back().get(), sizeof(uint32_t)),
                        [state, on_complete](const asio::error_code& ec, size_t) {
                            if (ec) { on_complete(ec); return; }
                            asio::async_write(state->output_file, asio::buffer(state->iv), 
                                [on_complete](const asio::error_code& ec, size_t) {
                                    on_complete(ec);
                                });
                        });
                });
        });
}


void nkCryptoToolPQC::handleFileReadForPQCEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (!ec) {
        int outlen = 0;
        if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), bytes_transferred) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        asio::async_write(state->output_file, asio::buffer(state->output_buffer, outlen), [this, state](const asio::error_code& ec, size_t){
            if(ec) {
                state->completion_handler(ec);
            } else {
                state->input_file.async_read_some(asio::buffer(state->input_buffer), asio::bind_executor(state->input_file.get_executor(), std::bind(&nkCryptoToolPQC::handleFileReadForPQCEncryption, this, state, std::placeholders::_1, std::placeholders::_2)));
            }
        });
    } else if (ec == asio::error::eof) {
        finishPQCEncryption(state, {});
    } else {
        state->completion_handler(ec);
    }
}

void nkCryptoToolPQC::finishPQCEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code&) {
    int outlen = 0;
    if (EVP_EncryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    if (outlen > 0) {
        asio::error_code ec;
        asio::write(state->output_file, asio::buffer(state->output_buffer, outlen), ec);
        if(ec) { state->completion_handler(ec); return; }
    }
    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
    asio::error_code ec;
    asio::write(state->output_file, asio::buffer(state->tag), ec);
    state->completion_handler(ec);
}

// Asynchronous Decryption Wrappers
void nkCryptoToolPQC::decryptFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& user_private_key_path, const std::filesystem::path&, std::function<void(std::error_code)> completion_handler) {
    auto state = std::make_shared<DecryptionState>(io_context, input_filepath);
    state->completion_handler = completion_handler;

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> user_kem_private_key(loadPrivateKey(user_private_key_path));
    if (!user_kem_private_key) { 
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); 
        return; 
    }
    startPQCDecryptionAsync(state, input_filepath, output_filepath, user_kem_private_key.release(), nullptr);
}

void nkCryptoToolPQC::decryptFileHybrid(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_mlkem_private_key_path, const std::filesystem::path& recipient_ecdh_private_key_path, std::function<void(std::error_code)> completion_handler) {
    auto state = std::make_shared<DecryptionState>(io_context, input_filepath);
    state->completion_handler = completion_handler;

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> user_mlkem_private_key(loadPrivateKey(recipient_mlkem_private_key_path));
    if (!user_mlkem_private_key) { 
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); 
        return; 
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> user_ecdh_private_key(loadPrivateKey(recipient_ecdh_private_key_path));
    if (!user_ecdh_private_key) { 
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); 
        return; 
    }
    startPQCDecryptionAsync(state, input_filepath, output_filepath, user_mlkem_private_key.release(), user_ecdh_private_key.release());
}

// Core Decryption Logic
void nkCryptoToolPQC::startPQCDecryptionAsync(std::shared_ptr<DecryptionState> state, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, EVP_PKEY* user_kem_private_key_raw, EVP_PKEY* user_ecdh_private_key_raw) {
    std::shared_ptr<EVP_PKEY> user_kem_private_key(user_kem_private_key_raw, EVP_PKEY_Deleter());
    std::shared_ptr<EVP_PKEY> user_ecdh_private_key(user_ecdh_private_key_raw, EVP_PKEY_Deleter());

    asio::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) { state->completion_handler(ec); return; }
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) { state->completion_handler(ec); return; }

    auto on_header_read_complete = [this, state, user_kem_private_key, user_ecdh_private_key]() {
        std::vector<unsigned char> current_shared_secret;
        // Decapsulate KEM part
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kem_pctx_decap(EVP_PKEY_CTX_new(user_kem_private_key.get(), nullptr), EVP_PKEY_CTX_free);
        if (!kem_pctx_decap || 1 != EVP_PKEY_decapsulate_init(kem_pctx_decap.get(), nullptr)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        size_t shared_secret_len_kem;
        if (1 != EVP_PKEY_decapsulate(kem_pctx_decap.get(), nullptr, &shared_secret_len_kem, state->kem_ciphertext_read.data(), state->kem_ciphertext_read.size())) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        current_shared_secret.resize(shared_secret_len_kem);
        if (1 != EVP_PKEY_decapsulate(kem_pctx_decap.get(), current_shared_secret.data(), &shared_secret_len_kem, state->kem_ciphertext_read.data(), state->kem_ciphertext_read.size())) {
            printOpenSSLErrors();
            state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return;
        }

        // Handle ECDH part for hybrid mode
        if (user_ecdh_private_key && !state->ecdh_sender_pub_key_read.empty()) {
            std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(BIO_new_mem_buf(state->ecdh_sender_pub_key_read.data(), state->ecdh_sender_pub_key_read.size()), BIO_free_all);
            std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> sender_pub_key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
            if (!sender_pub_key) { state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument)); return; }
            std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ecdh_ctx(EVP_PKEY_CTX_new(user_ecdh_private_key.get(), nullptr), EVP_PKEY_CTX_free);
            if (!ecdh_ctx || 1 != EVP_PKEY_derive_init(ecdh_ctx.get()) || 1 != EVP_PKEY_derive_set_peer(ecdh_ctx.get(), sender_pub_key.get())) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
            size_t ecdh_secret_len;
            if (1 != EVP_PKEY_derive(ecdh_ctx.get(), nullptr, &ecdh_secret_len)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
            std::vector<unsigned char> ecdh_secret(ecdh_secret_len);
            if (1 != EVP_PKEY_derive(ecdh_ctx.get(), ecdh_secret.data(), &ecdh_secret_len)) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
            current_shared_secret.insert(current_shared_secret.end(), ecdh_secret.begin(), ecdh_secret.end());
        }

        // Derive decryption key and initialize cipher
        std::string info_str = (user_ecdh_private_key && !state->ecdh_sender_pub_key_read.empty()) ? "hybrid-encryption-key-iv" : "aes-gcm-encryption-key-iv";
        state->decryption_key = hkdfDerive(current_shared_secret, 32, std::string(state->salt.begin(), state->salt.end()), info_str, "SHA256");
        if (state->decryption_key.empty()) { state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return; }
        state->cipher_ctx.reset(EVP_CIPHER_CTX_new());
        if (!state->cipher_ctx || EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 || EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) <= 0 || EVP_DecryptInit_ex(state->cipher_ctx.get(), nullptr, nullptr, state->decryption_key.data(), state->iv.data()) <= 0) {
             printOpenSSLErrors();
             state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return;
        }

        // Calculate ciphertext size and start decryption loop
        std::error_code fs_ec;
        uintmax_t total_file_size = std::filesystem::file_size(state->input_filepath_orig, fs_ec);
        if (fs_ec) { state->completion_handler(fs_ec); return; }
        size_t header_size = 4 + state->kem_ciphertext_read.size() + 4 + state->salt.size() + 4 + state->iv.size();
        if(user_ecdh_private_key && !state->ecdh_sender_pub_key_read.empty()) {
            header_size += 4 + state->ecdh_sender_pub_key_read.size();
        }
        if (total_file_size < header_size + GCM_TAG_LEN) { state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument)); return; }
        state->ciphertext_size_to_read = total_file_size - header_size - GCM_TAG_LEN;
        state->total_bytes_read = 0;

        // Start the decryption loop by reading the first chunk
        size_t next_read_size = std::min((size_t)CHUNK_SIZE, state->ciphertext_size_to_read);
        if (next_read_size > 0) {
             state->input_file.async_read_some(asio::buffer(state->input_buffer.data(), next_read_size),
                asio::bind_executor(state->input_file.get_executor(),
                    std::bind(&nkCryptoToolPQC::handleFileReadForPQCDecryption, this, state,
                                std::placeholders::_1, std::placeholders::_2)));
        } else { // Handle empty ciphertext case
            state->tag.resize(GCM_TAG_LEN);
            asio::async_read(state->input_file, asio::buffer(state->tag),
                asio::bind_executor(state->input_file.get_executor(),
                    [this, state](const asio::error_code& tag_ec, size_t tag_bytes) {
                        this->finishPQCDecryption(state, tag_ec, tag_bytes);
                    }));
        }
    };

    auto read_len_and_data = [state](std::vector<unsigned char>& target, std::function<void(const asio::error_code&, size_t)> next) {
        auto len_buf = std::make_shared<std::vector<unsigned char>>(4);
        asio::async_read(state->input_file, asio::buffer(*len_buf), [state, len_buf, &target, next](const asio::error_code& ec, size_t) {
            if (ec) { next(ec, 0); return; }
            uint32_t data_len;
            memcpy(&data_len, len_buf->data(), sizeof(data_len));
            if (data_len > 8192) { // Sanity check
                 next(asio::error::make_error_code(asio::error::invalid_argument), 0); return;
            }
            target.resize(data_len);
            asio::async_read(state->input_file, asio::buffer(target), next);
        });
    };

    read_len_and_data(state->kem_ciphertext_read, [this, state, user_ecdh_private_key, read_len_and_data, on_header_read_complete](const asio::error_code& ec, size_t){
        if (ec) { state->completion_handler(ec); return; }
        if (user_ecdh_private_key) {
            read_len_and_data(state->ecdh_sender_pub_key_read, [this, state, read_len_and_data, on_header_read_complete](const asio::error_code& ec, size_t) {
                if (ec) { state->completion_handler(ec); return; }
                read_len_and_data(state->salt, [this, state, read_len_and_data, on_header_read_complete](const asio::error_code& ec, size_t) {
                    if (ec) { state->completion_handler(ec); return; }
                    read_len_and_data(state->iv, [state, on_header_read_complete](const asio::error_code& ec, size_t size) {
                        if (ec) { state->completion_handler(ec); } else { on_header_read_complete(); }
                    });
                });
            });
        } else {
            read_len_and_data(state->salt, [this, state, read_len_and_data, on_header_read_complete](const asio::error_code& ec, size_t) {
                if (ec) { state->completion_handler(ec); return; }
                read_len_and_data(state->iv, [state, on_header_read_complete](const asio::error_code& ec, size_t size) {
                     if (ec) { state->completion_handler(ec); } else { on_header_read_complete(); }
                });
            });
        }
    });
}

void nkCryptoToolPQC::handleFileReadForPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec && ec != asio::error::eof) {
        std::cerr << "Error reading input file during decryption: " << ec.message() << std::endl;
        state->completion_handler(ec);
        return;
    }

    if (bytes_transferred > 0) {
        state->output_buffer.resize(bytes_transferred + EVP_MAX_BLOCK_LENGTH);
        int outlen = 0;
        if (EVP_DecryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), bytes_transferred) <= 0) {
            std::cerr << "Error during PQC decryption update." << std::endl;
            printOpenSSLErrors();
            state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
            return;
        }
        state->total_bytes_read += bytes_transferred;

        asio::async_write(state->output_file, asio::buffer(state->output_buffer, outlen),
            asio::bind_executor(state->output_file.get_executor(),
                std::bind(&nkCryptoToolPQC::handleFileWriteAfterPQCDecryption, this, state,
                            std::placeholders::_1, std::placeholders::_2)));
    } else if (ec == asio::error::eof) {
        handleFileWriteAfterPQCDecryption(state, {}, 0);
    }
}

void nkCryptoToolPQC::handleFileWriteAfterPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t) {
    if (ec) {
        std::cerr << "Error writing decrypted data to output file: " << ec.message() << std::endl;
        state->completion_handler(ec);
        return;
    }

    if (state->total_bytes_read >= state->ciphertext_size_to_read) {
        // All ciphertext has been processed, now read the GCM tag.
        state->tag.resize(GCM_TAG_LEN);
        asio::async_read(state->input_file, asio::buffer(state->tag),
            asio::bind_executor(state->input_file.get_executor(),
                [this, state](const asio::error_code& tag_ec, size_t tag_bytes) {
                    this->finishPQCDecryption(state, tag_ec, tag_bytes);
                }));
    } else {
        // Not done yet, read the next chunk of ciphertext.
        size_t next_read_size = std::min((size_t)CHUNK_SIZE, state->ciphertext_size_to_read - state->total_bytes_read);
        state->input_file.async_read_some(asio::buffer(state->input_buffer.data(), next_read_size),
            asio::bind_executor(state->input_file.get_executor(),
                std::bind(&nkCryptoToolPQC::handleFileReadForPQCDecryption, this, state,
                            std::placeholders::_1, std::placeholders::_2)));
    }
}

void nkCryptoToolPQC::finishPQCDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec && ec != asio::error::eof) { 
        state->completion_handler(ec);
        return;
    }
    if (bytes_transferred != GCM_TAG_LEN) {
        std::cerr << "Error: Incorrect GCM tag length read from file (" << bytes_transferred << " bytes)." << std::endl;
        state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return;
    }

    int outlen = 0;
    state->output_buffer.resize(EVP_MAX_BLOCK_LENGTH);
    if (EVP_DecryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
        std::cerr << "Error: GCM tag mismatch or finalization error." << std::endl;
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported)); return;
    }
    state->output_buffer.resize(outlen);

    if(outlen > 0) {
        asio::error_code write_ec;
        asio::write(state->output_file, asio::buffer(state->output_buffer), write_ec);
        if(write_ec) {
            state->completion_handler(write_ec);
            return;
        }
    }

    state->completion_handler({});
}

// Dummy implementations for non-streaming methods if they exist
bool nkCryptoToolPQC::aesGcmEncrypt(const std::vector<unsigned char>&, const std::vector<unsigned char>&, const std::vector<unsigned char>&, std::vector<unsigned char>&, std::vector<unsigned char>&) { return true; }
bool nkCryptoToolPQC::aesGcmDecrypt(const std::vector<unsigned char>&, const std::vector<unsigned char>&, const std::vector<unsigned char>&, const std::vector<unsigned char>&, std::vector<unsigned char>&) { return true; }

bool nkCryptoToolPQC::signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string&) {
    std::vector<unsigned char> file_content;
    try {
        file_content = readFile(input_filepath);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error reading input file for signing: " << e.what() << std::endl;
        return false;
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> priv_key(loadPrivateKey(signing_private_key_path));
    if(!priv_key) return false;

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> sctx(EVP_PKEY_CTX_new_from_pkey(nullptr, priv_key.get(), nullptr));
    if (!sctx || 1 != EVP_PKEY_sign_init(sctx.get())) {
        std::cerr << "Error: EVP_PKEY_sign_init failed." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    size_t sig_len;
    if (1 != EVP_PKEY_sign(sctx.get(), nullptr, &sig_len, file_content.data(), file_content.size())) {
        std::cerr << "Error: EVP_PKEY_sign failed (to get length)." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    std::vector<unsigned char> signature(sig_len);
    if (1 != EVP_PKEY_sign(sctx.get(), signature.data(), &sig_len, file_content.data(), file_content.size())) {
        std::cerr << "Error: EVP_PKEY_sign failed (to sign)." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    signature.resize(sig_len);

    return writeFile(signature_filepath, signature);
}

bool nkCryptoToolPQC::verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) {
    std::vector<unsigned char> file_content;
     try {
        file_content = readFile(input_filepath);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error reading input file for verification: " << e.what() << std::endl;
        return false;
    }
    
    std::vector<unsigned char> signature;
    try {
        signature = readFile(signature_filepath);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error reading signature file: " << e.what() << std::endl;
        return false;
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pub_key(loadPublicKey(signing_public_key_path));
    if(!pub_key) return false;

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> vctx(EVP_PKEY_CTX_new_from_pkey(nullptr, pub_key.get(), nullptr));
    if (!vctx || 1 != EVP_PKEY_verify_init(vctx.get())) {
        std::cerr << "Error: EVP_PKEY_verify_init failed." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    
    return EVP_PKEY_verify(vctx.get(), signature.data(), signature.size(), file_content.data(), file_content.size()) == 1;
}
