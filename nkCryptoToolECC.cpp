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
#include <openssl/crypto.h> // For OPENSSL_free
#include <string>
#include <algorithm>
#include <stdexcept> // For std::runtime_error
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/stream_file.hpp>

// External callback for PEM passphrase
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);
extern std::string global_passphrase_for_pem_cb; // Assumed to be set by main for synchronous key ops

// Helper function to print OpenSSL errors
void nkCryptoToolECC::printOpenSSLErrors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

// Helper function to load public key
EVP_PKEY* nkCryptoToolECC::loadPublicKey(const std::filesystem::path& public_key_path) {
    std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"), BIO_free);
    if (!pub_bio) {
        std::cerr << "Error loading public key: Could not open file " << public_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, pem_passwd_cb, &global_passphrase_for_pem_cb);
    if (!public_key) {
        std::cerr << "Error loading public key: PEM_read_bio_PUBKEY failed for " << public_key_path << std::endl;
        printOpenSSLErrors();
    }
    return public_key;
}

// Helper function to load private key
EVP_PKEY* nkCryptoToolECC::loadPrivateKey(const std::filesystem::path& private_key_path) {
    std::unique_ptr<BIO, decltype(&BIO_free)> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"), BIO_free);
    if (!priv_bio) {
        std::cerr << "Error loading private key: Could not open file " << private_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, &global_passphrase_for_pem_cb);
    if (!private_key) {
        std::cerr << "Error loading private key: PEM_read_bio_PrivateKey failed for " << private_key_path << std::endl;
        printOpenSSLErrors();
    }
    return private_key;
}

// Helper function to generate a shared secret using ECDH
std::vector<unsigned char> nkCryptoToolECC::generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new(private_key, nullptr), EVP_PKEY_CTX_free);
    if (!pctx || EVP_PKEY_derive_init(pctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(pctx.get(), peer_public_key) <= 0) {
        std::cerr << "Error: Failed to initialize key derivation." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    size_t secret_len;
    if (EVP_PKEY_derive(pctx.get(), nullptr, &secret_len) <= 0) {
        std::cerr << "Error: Failed to get shared secret length." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    std::vector<unsigned char> shared_secret(secret_len);
    if (EVP_PKEY_derive(pctx.get(), shared_secret.data(), &secret_len) <= 0) {
        std::cerr << "Error: Failed to derive shared secret." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    return shared_secret;
}

// Helper function for HKDF derivation
std::vector<unsigned char> nkCryptoToolECC::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                                      const std::string& salt_str, const std::string& info_str,
                                                      const std::string& digest_algo) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        std::cerr << "Error: EVP_KDF_fetch failed for HKDF." << std::endl;
        printOpenSSLErrors();
        return {};
    }
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf_ptr(kdf, EVP_KDF_free);
    std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> kctx(EVP_KDF_CTX_new(kdf), EVP_KDF_CTX_free);
    if (!kctx) {
        std::cerr << "Error: EVP_KDF_CTX_new failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    const EVP_MD* digest = EVP_get_digestbyname(digest_algo.c_str());
    if (!digest) {
        std::cerr << "Error: Unknown digest algorithm: " << digest_algo << std::endl;
        return {};
    }

    OSSL_PARAM params[5];
    int i = 0;
    params[i++] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest_algo.c_str()), 0);
    // *** FIX: Use "key" instead of "ikm" for the input key material parameter name ***
    params[i++] = OSSL_PARAM_construct_octet_string("key", const_cast<unsigned char*>(ikm.data()), ikm.size());
    if (!salt_str.empty()) {
        params[i++] = OSSL_PARAM_construct_octet_string("salt", const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(salt_str.data())), salt_str.size());
    }
    if (!info_str.empty()) {
        params[i++] = OSSL_PARAM_construct_octet_string("info", const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(info_str.data())), info_str.size());
    }
    params[i++] = OSSL_PARAM_construct_end();

    std::vector<unsigned char> derived_key(output_len);
    if (EVP_KDF_derive(kctx.get(), derived_key.data(), output_len, params) <= 0) {
        std::cerr << "Error: HKDF derivation failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }
    return derived_key;
}

// Constructor
nkCryptoToolECC::nkCryptoToolECC() {}

// Destructor
nkCryptoToolECC::~nkCryptoToolECC() {}

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

// Key generation methods (synchronous as before)
bool nkCryptoToolECC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: Failed to initialize EC key generation." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", const_cast<char*>("prime256v1"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) {
        std::cerr << "Error: Failed to set EC group." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
        std::cerr << "Error: Failed to generate EC key pair." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ec_key(pkey);

    std::unique_ptr<BIO, decltype(&BIO_free)> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"), BIO_free);
    if (!priv_bio || PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(),
                                                 passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()),
                                                 passphrase.length(), pem_passwd_cb, &global_passphrase_for_pem_cb) <= 0) {
        std::cerr << "Error: Failed to write private key to " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"), BIO_free);
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) {
        std::cerr << "Error: Failed to write public key to " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

bool nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        std::cerr << "Error: Failed to initialize EC key generation for signing." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", const_cast<char*>("prime256v1"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) {
        std::cerr << "Error: Failed to set EC group for signing." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
        std::cerr << "Error: Failed to generate EC signing key pair." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ec_key(pkey);

    std::unique_ptr<BIO, decltype(&BIO_free)> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"), BIO_free);
    if (!priv_bio || PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(),
                                                 passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()),
                                                 passphrase.length(), pem_passwd_cb, &global_passphrase_for_pem_cb) <= 0) {
        std::cerr << "Error: Failed to write signing private key to " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"), BIO_free);
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) {
        std::cerr << "Error: Failed to write signing public key to " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    return true;
}

// Asynchronous Encryption Implementation
void nkCryptoToolECC::encryptFile(
    asio::io_context& io_context,
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_public_key_path,
    std::function<void(std::error_code)> completion_handler)
{
    // Load recipient's public key
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_public_key(loadPublicKey(recipient_public_key_path));
    if (!recipient_public_key) {
        std::cerr << "Error: Failed to load recipient public key for encryption." << std::endl;
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    // Generate ephemeral EC key pair for sender
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pctx_ephemeral(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
    if (!pctx_ephemeral || EVP_PKEY_keygen_init(pctx_ephemeral.get()) <= 0) {
        std::cerr << "Error: Failed to initialize ephemeral EC key generation." << std::endl;
        printOpenSSLErrors();
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", const_cast<char*>("prime256v1"), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx_ephemeral.get(), params) <= 0) {
        std::cerr << "Error: Failed to set EC group for ephemeral key." << std::endl;
        printOpenSSLErrors();
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    EVP_PKEY* ephemeral_pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx_ephemeral.get(), &ephemeral_pkey_raw) <= 0) {
        std::cerr << "Error: Failed to generate ephemeral EC key pair." << std::endl;
        printOpenSSLErrors();
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_private_key(ephemeral_pkey_raw);

    std::vector<unsigned char> shared_secret = generateSharedSecret(ephemeral_private_key.get(), recipient_public_key.get());
    if (shared_secret.empty()) {
        std::cerr << "Error: Failed to derive shared secret for encryption." << std::endl;
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::vector<unsigned char> encryption_key = hkdfDerive(shared_secret, 32, "", "aes-256-gcm-key", "SHA256");
    if (encryption_key.empty()) {
        std::cerr << "Error: Failed to derive encryption key." << std::endl;
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::vector<unsigned char> iv(GCM_IV_LEN);
    if (RAND_bytes(iv.data(), GCM_IV_LEN) <= 0) {
        std::cerr << "Error: Failed to generate random IV." << std::endl;
        printOpenSSLErrors();
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!cipher_ctx || EVP_EncryptInit_ex(cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) <= 0 ||
        EVP_EncryptInit_ex(cipher_ctx.get(), nullptr, nullptr, encryption_key.data(), iv.data()) <= 0) {
        std::cerr << "Error: Failed to initialize AES-GCM encryption." << std::endl;
        printOpenSSLErrors();
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    auto state = std::make_shared<EncryptionState>(io_context);
    state->encryption_key = encryption_key;
    state->iv = iv;
    state->cipher_ctx = std::move(cipher_ctx);
    state->completion_handler = completion_handler;

    std::error_code ec_in;
    state->input_file.open(input_filepath.string().c_str(), asio::stream_file::read_only, ec_in);
    if (ec_in) {
        std::cerr << "Error opening input file for encryption: " << ec_in.message() << std::endl;
        state->completion_handler(ec_in);
        return;
    }

    std::error_code ec_out;
    state->output_file.open(output_filepath.string().c_str(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec_out);
    if (ec_out) {
        std::cerr << "Error opening output file for encryption: " << ec_out.message() << std::endl;
        state->completion_handler(ec_out);
        return;
    }

    std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_private_key.get()) <= 0) {
        std::cerr << "Error: Failed to write ephemeral public key to memory BIO." << std::endl;
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
    std::vector<unsigned char> ephemeral_pub_key_bytes(bio_buf->data, bio_buf->data + bio_buf->length);

    std::vector<unsigned char> header_data;
    uint32_t key_len = static_cast<uint32_t>(ephemeral_pub_key_bytes.size());
    header_data.resize(4 + key_len + GCM_IV_LEN);
    memcpy(header_data.data(), &key_len, 4);
    memcpy(header_data.data() + 4, ephemeral_pub_key_bytes.data(), key_len);
    memcpy(header_data.data() + 4 + key_len, state->iv.data(), GCM_IV_LEN);


    asio::async_write(state->output_file, asio::buffer(header_data),
        [state, this](const asio::error_code& ec, size_t) {
            if (ec) {
                std::cerr << "Error writing header to output file: " << ec.message() << std::endl;
                state->completion_handler(ec);
                return;
            }
            state->input_file.async_read_some(asio::buffer(state->input_buffer),
                std::bind(&nkCryptoToolECC::handleFileReadForEncryption, this, state,
                            std::placeholders::_1, std::placeholders::_2));
        });
}

void nkCryptoToolECC::handleFileReadForEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec == asio::error::eof) {
        finishEncryption(state, std::error_code());
        return;
    }
    if (ec) {
        std::cerr << "Error reading input file during encryption: " << ec.message() << std::endl;
        state->completion_handler(ec);
        return;
    }

    state->bytes_read = bytes_transferred;
    int outlen = 0;
    if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), state->bytes_read) <= 0) {
        std::cerr << "Error during encryption update." << std::endl;
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    
    if (outlen > 0) {
        asio::async_write(state->output_file, asio::buffer(state->output_buffer.data(), outlen),
            std::bind(&nkCryptoToolECC::handleFileWriteAfterEncryption, this, state,
                        std::placeholders::_1, std::placeholders::_2));
    } else {
        state->input_file.async_read_some(
            asio::buffer(state->input_buffer),
            std::bind(&nkCryptoToolECC::handleFileReadForEncryption, this, state,
                        std::placeholders::_1, std::placeholders::_2)
        );
    }
}

void nkCryptoToolECC::handleFileWriteAfterEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec, size_t) {
    if (ec) {
        std::cerr << "Error writing encrypted data to output file: " << ec.message() << std::endl;
        state->completion_handler(ec);
        return;
    }

    state->input_file.async_read_some(asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForEncryption, this, state,
                    std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishEncryption(std::shared_ptr<EncryptionState> state, const asio::error_code& ec) {
    if (ec) {
        state->completion_handler(ec);
        return;
    }

    int outlen = 0;
    if (EVP_EncryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
        std::cerr << "Error finalizing encryption." << std::endl;
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::vector<unsigned char> final_block(state->output_buffer.data(), state->output_buffer.data() + outlen);

    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        std::cerr << "Error getting GCM tag." << std::endl;
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    asio::async_write(state->output_file, asio::buffer(final_block),
        [state, this](const asio::error_code& ec_write_final, size_t) {
            if (ec_write_final) {
                std::cerr << "Error writing final encrypted data to output file: " << ec_write_final.message() << std::endl;
                state->completion_handler(ec_write_final);
                return;
            }
            asio::async_write(state->output_file, asio::buffer(state->tag),
                [state](const asio::error_code& ec_write_tag, size_t) {
                    if (ec_write_tag) {
                        std::cerr << "Error writing GCM tag to output file: " << ec_write_tag.message() << std::endl;
                        state->completion_handler(ec_write_tag);
                        return;
                    }
                    state->completion_handler(std::error_code());
                });
        });
}


// Asynchronous Decryption Implementation
void nkCryptoToolECC::decryptFile(
    asio::io_context& io_context,
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& output_filepath,
    const std::filesystem::path& user_private_key_path,
    const std::filesystem::path&,
    std::function<void(std::error_code)> completion_handler)
{
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> user_private_key(loadPrivateKey(user_private_key_path));
    if (!user_private_key) {
        std::cerr << "Error: Failed to load user's private key for decryption." << std::endl;
        completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    auto state = std::make_shared<DecryptionState>(io_context, input_filepath);
    state->completion_handler = completion_handler;

    std::error_code ec_in;
    state->input_file.open(input_filepath.string().c_str(), asio::stream_file::read_only, ec_in);
    if (ec_in) {
        std::cerr << "Error opening input file for decryption: " << ec_in.message() << std::endl;
        state->completion_handler(ec_in);
        return;
    }

    std::error_code ec_out;
    state->output_file.open(output_filepath.string().c_str(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec_out);
    if (ec_out) {
        std::cerr << "Error opening output file for decryption: " << ec_out.message() << std::endl;
        state->completion_handler(ec_out);
        return;
    }

    auto key_len_bytes = std::make_shared<std::vector<unsigned char>>(4);
    asio::async_read(state->input_file, asio::buffer(*key_len_bytes),
        [state, this, user_private_key = std::move(user_private_key), key_len_bytes](const asio::error_code& ec_len, size_t) mutable {
            if (ec_len) {
                std::cerr << "Error reading ephemeral public key length: " << ec_len.message() << std::endl;
                state->completion_handler(ec_len);
                return;
            }
            
            memcpy(&state->ephemeral_key_len, key_len_bytes->data(), 4);

            if (state->ephemeral_key_len == 0 || state->ephemeral_key_len > 4096) {
                std::cerr << "Error: Invalid ephemeral public key length read from header (" << state->ephemeral_key_len << " bytes)." << std::endl;
                state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
                return;
            }

            auto ephemeral_pub_key_bytes = std::make_shared<std::vector<unsigned char>>(state->ephemeral_key_len);
            asio::async_read(state->input_file, asio::buffer(*ephemeral_pub_key_bytes),
                [state, this, user_private_key = std::move(user_private_key), ephemeral_pub_key_bytes](const asio::error_code& ec_ephem_key, size_t) mutable {
                    if (ec_ephem_key) {
                        std::cerr << "Error reading ephemeral public key from header: " << ec_ephem_key.message() << std::endl;
                        state->completion_handler(ec_ephem_key);
                        return;
                    }

                    std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio_mem(BIO_new_mem_buf(ephemeral_pub_key_bytes->data(), static_cast<int>(ephemeral_pub_key_bytes->size())), BIO_free);
                    if (!pub_bio_mem) {
                        std::cerr << "Error: Failed to create memory BIO for ephemeral public key." << std::endl;
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }
                    EVP_PKEY* sender_ephemeral_public_key_raw = PEM_read_bio_PUBKEY(pub_bio_mem.get(), nullptr, nullptr, nullptr);
                    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_ephemeral_public_key(sender_ephemeral_public_key_raw);
                    if (!sender_ephemeral_public_key) {
                        std::cerr << "Error: Failed to parse ephemeral public key from header." << std::endl;
                        printOpenSSLErrors();
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }

                    state->shared_secret = generateSharedSecret(user_private_key.get(), sender_ephemeral_public_key.get());
                    if (state->shared_secret.empty()) {
                        std::cerr << "Error: Failed to derive shared secret for decryption." << std::endl;
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }

                    state->decryption_key = hkdfDerive(state->shared_secret, 32, "", "aes-256-gcm-key", "SHA256");
                    if (state->decryption_key.empty()) {
                        std::cerr << "Error: Failed to derive decryption key." << std::endl;
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }

                    state->iv.resize(GCM_IV_LEN);
                    asio::async_read(state->input_file, asio::buffer(state->iv),
                        [state, this](const asio::error_code& ec_iv, size_t) {
                            if (ec_iv) {
                                std::cerr << "Error reading IV from input file: " << ec_iv.message() << std::endl;
                                state->completion_handler(ec_iv);
                                return;
                            }

                            state->cipher_ctx.reset(EVP_CIPHER_CTX_new());
                            if (!state->cipher_ctx || EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
                                EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) <= 0 ||
                                EVP_DecryptInit_ex(state->cipher_ctx.get(), nullptr, nullptr, state->decryption_key.data(), state->iv.data()) <= 0) {
                                std::cerr << "Error: Failed to initialize AES-GCM decryption." << std::endl;
                                printOpenSSLErrors();
                                state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                                return;
                            }

                            std::error_code file_size_ec;
                            state->total_input_size = std::filesystem::file_size(state->input_filepath_orig, file_size_ec);
                            if (file_size_ec) {
                                std::cerr << "Error getting input file size: " << file_size_ec.message() << std::endl;
                                state->completion_handler(file_size_ec);
                                return;
                            }

                            size_t header_total_size = 4 + state->ephemeral_key_len + GCM_IV_LEN;
                            if (state->total_input_size < header_total_size + GCM_TAG_LEN) {
                                std::cerr << "Error: Input file too small to contain header and GCM tag." << std::endl;
                                state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
                                return;
                            }
                            
                            state->total_input_size -= (header_total_size + GCM_TAG_LEN);
                            handleFileReadForDecryption(state, {}, 0);
                        });
                });
        });
}

void nkCryptoToolECC::handleFileReadForDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec == asio::error::eof || state->current_input_offset >= state->total_input_size) {
        finishDecryption(state, {});
        return;
    }
     if (ec) {
        std::cerr << "Error reading input file during decryption: " << ec.message() << std::endl;
        state->completion_handler(ec);
        return;
    }

    if (bytes_transferred > 0) {
        state->bytes_read = bytes_transferred;
        state->current_input_offset += bytes_transferred;

        int outlen = 0;
        if (EVP_DecryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), state->bytes_read) <= 0) {
            std::cerr << "Error during decryption update." << std::endl;
            printOpenSSLErrors();
            state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
            return;
        }

        if (outlen > 0) {
            asio::async_write(state->output_file, asio::buffer(state->output_buffer.data(), outlen),
                std::bind(&nkCryptoToolECC::handleFileWriteAfterDecryption, this, state,
                            std::placeholders::_1, std::placeholders::_2));
        } else {
             handleFileWriteAfterDecryption(state, {}, 0);
        }
    } else {
        // First call to start the loop
         size_t to_read = std::min((size_t)CHUNK_SIZE, state->total_input_size - state->current_input_offset);
        if (to_read > 0) {
            state->input_file.async_read_some(asio::buffer(state->input_buffer.data(), to_read),
                std::bind(&nkCryptoToolECC::handleFileReadForDecryption, this, state,
                            std::placeholders::_1, std::placeholders::_2));
        } else {
            finishDecryption(state, {});
        }
    }
}

void nkCryptoToolECC::handleFileWriteAfterDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t) {
    if (ec) {
        std::cerr << "Error writing decrypted data to output file: " << ec.message() << std::endl;
        state->completion_handler(ec);
        return;
    }

    if(state->current_input_offset >= state->total_input_size) {
        finishDecryption(state, {});
        return;
    }

    size_t to_read = std::min((size_t)CHUNK_SIZE, state->total_input_size - state->current_input_offset);
    if (to_read > 0) {
        state->input_file.async_read_some(asio::buffer(state->input_buffer.data(), to_read),
            std::bind(&nkCryptoToolECC::handleFileReadForDecryption, this, state,
                        std::placeholders::_1, std::placeholders::_2));
    } else {
         finishDecryption(state, {});
    }
}

void nkCryptoToolECC::finishDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec) {
    if (ec) {
        state->completion_handler(ec);
        return;
    }
    
    state->tag.resize(GCM_TAG_LEN);
    asio::async_read(state->input_file, asio::buffer(state->tag), 
        [state, this](const asio::error_code& tag_ec, size_t bytes_read) {
            if(tag_ec || bytes_read != GCM_TAG_LEN) {
                 std::cerr << "Error reading GCM tag: " << tag_ec.message() << std::endl;
                state->completion_handler(tag_ec ? tag_ec : asio::error::make_error_code(asio::error::bad_descriptor));
                return;
            }

            if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
                std::cerr << "Error setting GCM tag for verification." << std::endl;
                printOpenSSLErrors();
                state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                return;
            }

            int outlen = 0;
            if (EVP_DecryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
                std::cerr << "Error finalizing decryption or GCM tag mismatch." << std::endl;
                printOpenSSLErrors();
                state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                return;
            }

            asio::async_write(state->output_file, asio::buffer(state->output_buffer.data(), outlen),
                [state](const asio::error_code& ec_write_final, size_t) {
                    if (ec_write_final) {
                        std::cerr << "Error writing final decrypted data to output file: " << ec_write_final.message() << std::endl;
                        state->completion_handler(ec_write_final);
                        return;
                    }
                    state->completion_handler(std::error_code());
                });
    });
}


void nkCryptoToolECC::encryptFileHybrid(
    asio::io_context&, const std::filesystem::path&, const std::filesystem::path&,
    const std::filesystem::path&, const std::filesystem::path&,
    std::function<void(std::error_code)> completion_handler) {
    std::cerr << "Hybrid encryption not implemented for ECC mode." << std::endl;
    completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
}

void nkCryptoToolECC::decryptFileHybrid(
    asio::io_context&, const std::filesystem::path&, const std::filesystem::path&,
    const std::filesystem::path&, const std::filesystem::path&,
    std::function<void(std::error_code)> completion_handler) {
    std::cerr << "Hybrid decryption not implemented for ECC mode." << std::endl;
    completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
}


bool nkCryptoToolECC::signFile(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) {
    std::vector<unsigned char> input_data;
    try {
        input_data = readFile(input_filepath);
    } catch (const std::runtime_error& e) {
        std::cerr << "Error reading input file for signing: " << e.what() << std::endl;
        return false;
    }

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> private_key(loadPrivateKey(signing_private_key_path));
    if (!private_key) {
        std::cerr << "Error: Failed to load private key for signing." << std::endl;
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) {
        std::cerr << "Error: Failed to create EVP_MD_CTX." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    const EVP_MD* digest = EVP_get_digestbyname(digest_algo.c_str());
    if (!digest) {
        std::cerr << "Error: Unknown digest algorithm: " << digest_algo << std::endl;
        return false;
    }

    if (EVP_DigestSignInit(mdctx.get(), nullptr, digest, nullptr, private_key.get()) <= 0) {
        std::cerr << "Error: Failed to initialize digest signing." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_DigestSignUpdate(mdctx.get(), input_data.data(), input_data.size()) <= 0) {
        std::cerr << "Error: Failed to update digest for signing." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx.get(), nullptr, &sig_len) <= 0) {
        std::cerr << "Error: Failed to get signature length." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    std::vector<unsigned char> signature(sig_len);

    if (EVP_DigestSignInit(mdctx.get(), nullptr, digest, nullptr, private_key.get()) <= 0) {
        std::cerr << "Error: Failed to re-initialize digest signing." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_DigestSignUpdate(mdctx.get(), input_data.data(), input_data.size()) <= 0) {
        std::cerr << "Error: Failed to re-update digest for signing." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_DigestSignFinal(mdctx.get(), signature.data(), &sig_len) <= 0) {
        std::cerr << "Error: Failed to generate signature." << std::endl;
        printOpenSSLErrors();
        return false;
    }
    signature.resize(sig_len);

    if (!writeFile(signature_filepath, signature)) {
        std::cerr << "Error: Failed to write signature to " << signature_filepath << std::endl;
        return false;
    }

    return true;
}

bool nkCryptoToolECC::verifySignature(const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) {
    std::vector<unsigned char> input_data;
    try {
        input_data = readFile(input_filepath);
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

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> public_key(loadPublicKey(signing_public_key_path));
    if (!public_key) {
        std::cerr << "Error: Failed to load public key for verification." << std::endl;
        return false;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!mdctx) {
        std::cerr << "Error: Failed to create EVP_MD_CTX." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    const EVP_MD* digest = EVP_sha256();
    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, digest, nullptr, public_key.get()) <= 0) {
        std::cerr << "Error: Failed to initialize digest verification." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    if (EVP_DigestVerifyUpdate(mdctx.get(), input_data.data(), input_data.size()) <= 0) {
        std::cerr << "Error: Failed to update digest for verification." << std::endl;
        printOpenSSLErrors();
        return false;
    }

    int result = EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size());
    if (result == 1) {
        return true;
    } else if (result == 0) {
        std::cerr << "Error: Signature verification failed. The signature does not match the file or public key." << std::endl;
        printOpenSSLErrors();
        return false;
    } else {
        std::cerr << "Error: An error occurred during signature verification." << std::endl;
        printOpenSSLErrors();
        return false;
    }
}