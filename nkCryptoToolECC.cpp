// nkCryptoToolECC.cpp (Refactored)

#include "nkCryptoToolECC.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/stream_file.hpp>
#include <functional> // For std::bind

// mainで定義される外部PEMパスフレーズコールバック
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);
extern std::string global_passphrase_for_pem_cb;

// コンストラクタとデストラクタ
nkCryptoToolECC::nkCryptoToolECC() {}
nkCryptoToolECC::~nkCryptoToolECC() {}

/**
 * @brief ECDHを使用して共通鍵を生成します。
 * @param private_key 自身の秘密鍵
 * @param peer_public_key 通信相手の公開鍵
 * @return 生成された共通鍵
 */
std::vector<unsigned char> nkCryptoToolECC::generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new(private_key, nullptr));
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

// --- 鍵パス取得メソッド ---
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

// --- 鍵ペア生成メソッド ---
bool nkCryptoToolECC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
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

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio || PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(),
                                                 passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()),
                                                 passphrase.length(), pem_passwd_cb, &global_passphrase_for_pem_cb) <= 0) {
        std::cerr << "Error: Failed to write private key to " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) {
        std::cerr << "Error: Failed to write public key to " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }

    return true;
}

bool nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
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

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio || PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(),
                                                 passphrase.empty() ? nullptr : const_cast<char*>(passphrase.data()),
                                                 passphrase.length(), pem_passwd_cb, &global_passphrase_for_pem_cb) <= 0) {
        std::cerr << "Error: Failed to write signing private key to " << private_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) {
        std::cerr << "Error: Failed to write signing public key to " << public_key_path << std::endl;
        printOpenSSLErrors();
        return false;
    }
    return true;
}

// --- 非同期暗号化 ---
void nkCryptoToolECC::encryptFile(
    asio::io_context& io_context,
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_public_key_path,
    std::function<void(std::error_code)> completion_handler)
{
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) {
            std::cout << "\nEncryption to '" << output_filepath.string() << "' completed successfully." << std::endl;
        }
        completion_handler(ec);
    };

    auto recipient_public_key = this->loadPublicKey(recipient_public_key_path);
    if (!recipient_public_key) {
        std::cerr << "Error: Failed to load recipient public key for encryption." << std::endl;
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx_ephemeral(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx_ephemeral || EVP_PKEY_keygen_init(pctx_ephemeral.get()) <= 0) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("group", const_cast<char*>("prime256v1"), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx_ephemeral.get(), params) <= 0) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    EVP_PKEY* ephemeral_pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx_ephemeral.get(), &ephemeral_pkey_raw) <= 0) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_private_key(ephemeral_pkey_raw);

    std::vector<unsigned char> shared_secret = generateSharedSecret(ephemeral_private_key.get(), recipient_public_key.get());
    if (shared_secret.empty()) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::vector<unsigned char> encryption_key = this->hkdfDerive(shared_secret, 32, "", "aes-256-gcm-key", "SHA256");
    if (encryption_key.empty()) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    
    auto state = std::make_shared<EncryptionState>(io_context);
    state->encryption_key = std::move(encryption_key);
    state->completion_handler = wrapped_handler;

    if (RAND_bytes(state->iv.data(), GCM_IV_LEN) <= 0) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    
    if (!state->cipher_ctx || EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) <= 0 ||
        EVP_EncryptInit_ex(state->cipher_ctx.get(), nullptr, nullptr, state->encryption_key.data(), state->iv.data()) <= 0) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::error_code ec;
    state->total_input_size = std::filesystem::file_size(input_filepath, ec);
     if (ec) {
        state->completion_handler(ec);
        return;
    }

    state->input_file.open(input_filepath.string().c_str(), asio::stream_file::read_only, ec);
    if (ec) { state->completion_handler(ec); return; }

    state->output_file.open(output_filepath.string().c_str(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) { state->completion_handler(ec); return; }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_private_key.get()) <= 0) {
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
        [this, state](const asio::error_code& ec, size_t) {
            if (ec) {
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
        state->completion_handler(ec);
        return;
    }

    state->bytes_read = bytes_transferred;
    int outlen = 0;
    if (EVP_EncryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), state->bytes_read) <= 0) {
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
        state->completion_handler(ec);
        return;
    }

    state->total_bytes_processed += state->bytes_read;
    if (state->total_input_size > 0) {
        printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);
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
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::vector<unsigned char> final_block(state->output_buffer.data(), state->output_buffer.data() + outlen);

    if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    asio::async_write(state->output_file, asio::buffer(final_block),
        [this, state](const asio::error_code& ec_write_final, size_t) {
            if (ec_write_final) {
                state->completion_handler(ec_write_final);
                return;
            }
            asio::async_write(state->output_file, asio::buffer(state->tag),
                [this, state](const asio::error_code& ec_write_tag, size_t) {
                    printProgress(1.0);
                    state->completion_handler(ec_write_tag);
                });
        });
}


// --- 非同期復号 ---
void nkCryptoToolECC::decryptFile(
    asio::io_context& io_context,
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& output_filepath,
    const std::filesystem::path& user_private_key_path,
    const std::filesystem::path&, // sender_public_key_pathは未使用
    std::function<void(std::error_code)> completion_handler)
{
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) {
            std::cout << "\nDecryption to '" << output_filepath.string() << "' completed successfully." << std::endl;
        }
        completion_handler(ec);
    };

    auto user_private_key = this->loadPrivateKey(user_private_key_path);
    if (!user_private_key) {
        wrapped_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    auto state = std::make_shared<DecryptionState>(io_context, input_filepath);
    state->completion_handler = wrapped_handler;

    std::error_code ec;
    state->input_file.open(input_filepath.string().c_str(), asio::stream_file::read_only, ec);
    if (ec) { state->completion_handler(ec); return; }

    state->output_file.open(output_filepath.string().c_str(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) { state->completion_handler(ec); return; }

    auto key_len_bytes = std::make_shared<std::vector<unsigned char>>(4);
    asio::async_read(state->input_file, asio::buffer(*key_len_bytes),
        [this, state, user_private_key = std::move(user_private_key), key_len_bytes](const asio::error_code& ec_len, size_t) mutable {
            if (ec_len) {
                state->completion_handler(ec_len);
                return;
            }
            
            memcpy(&state->ephemeral_key_len, key_len_bytes->data(), 4);

            if (state->ephemeral_key_len == 0 || state->ephemeral_key_len > 4096) {
                state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
                return;
            }

            auto ephemeral_pub_key_bytes = std::make_shared<std::vector<unsigned char>>(state->ephemeral_key_len);
            asio::async_read(state->input_file, asio::buffer(*ephemeral_pub_key_bytes),
                [this, state, user_private_key = std::move(user_private_key), ephemeral_pub_key_bytes](const asio::error_code& ec_ephem_key, size_t) mutable {
                    if (ec_ephem_key) {
                        state->completion_handler(ec_ephem_key);
                        return;
                    }

                    std::unique_ptr<BIO, BIO_Deleter> pub_bio_mem(BIO_new_mem_buf(ephemeral_pub_key_bytes->data(), static_cast<int>(ephemeral_pub_key_bytes->size())));
                    if (!pub_bio_mem) {
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }
                    EVP_PKEY* sender_ephemeral_public_key_raw = PEM_read_bio_PUBKEY(pub_bio_mem.get(), nullptr, nullptr, nullptr);
                    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_ephemeral_public_key(sender_ephemeral_public_key_raw);
                    if (!sender_ephemeral_public_key) {
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }

                    state->shared_secret = generateSharedSecret(user_private_key.get(), sender_ephemeral_public_key.get());
                    if (state->shared_secret.empty()) {
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }

                    state->decryption_key = this->hkdfDerive(state->shared_secret, 32, "", "aes-256-gcm-key", "SHA256");
                    if (state->decryption_key.empty()) {
                        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                        return;
                    }

                    state->iv.resize(GCM_IV_LEN);
                    asio::async_read(state->input_file, asio::buffer(state->iv),
                        [this, state](const asio::error_code& ec_iv, size_t) {
                            if (ec_iv) {
                                state->completion_handler(ec_iv);
                                return;
                            }

                            if (!state->cipher_ctx || EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
                                EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) <= 0 ||
                                EVP_DecryptInit_ex(state->cipher_ctx.get(), nullptr, nullptr, state->decryption_key.data(), state->iv.data()) <= 0) {
                                state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                                return;
                            }

                            std::error_code file_size_ec;
                            uintmax_t total_file_size = std::filesystem::file_size(state->input_filepath_orig, file_size_ec);
                            if (file_size_ec) {
                                state->completion_handler(file_size_ec);
                                return;
                            }

                            size_t header_total_size = 4 + state->ephemeral_key_len + GCM_IV_LEN;
                            if (total_file_size < header_total_size + GCM_TAG_LEN) {
                                state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
                                return;
                            }
                            
                            state->total_ciphertext_size = total_file_size - header_total_size - GCM_TAG_LEN;
                            handleFileReadForDecryption(state, {}, 0);
                        });
                });
        });
}

void nkCryptoToolECC::handleFileReadForDecryption(std::shared_ptr<DecryptionState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec == asio::error::eof || state->total_bytes_processed >= state->total_ciphertext_size) {
        finishDecryption(state, {});
        return;
    }
     if (ec) {
        state->completion_handler(ec);
        return;
    }

    if (bytes_transferred > 0) {
        state->bytes_read = bytes_transferred;

        int outlen = 0;
        if (EVP_DecryptUpdate(state->cipher_ctx.get(), state->output_buffer.data(), &outlen, state->input_buffer.data(), state->bytes_read) <= 0) {
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
         size_t to_read = std::min((size_t)CHUNK_SIZE, state->total_ciphertext_size - state->total_bytes_processed);
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
        state->completion_handler(ec);
        return;
    }

    state->total_bytes_processed += state->bytes_read;
    if (state->total_ciphertext_size > 0) {
        printProgress(static_cast<double>(state->total_bytes_processed) / state->total_ciphertext_size);
    }

    if(state->total_bytes_processed >= state->total_ciphertext_size) {
        finishDecryption(state, {});
        return;
    }

    size_t to_read = std::min((size_t)CHUNK_SIZE, state->total_ciphertext_size - state->total_bytes_processed);
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
        [this, state](const asio::error_code& tag_ec, size_t bytes_read) {
            if(tag_ec || bytes_read != GCM_TAG_LEN) {
                state->completion_handler(tag_ec ? tag_ec : asio::error::make_error_code(asio::error::bad_descriptor));
                return;
            }

            if (EVP_CIPHER_CTX_ctrl(state->cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, state->tag.data()) <= 0) {
                state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                return;
            }

            int outlen = 0;
            if (EVP_DecryptFinal_ex(state->cipher_ctx.get(), state->output_buffer.data(), &outlen) <= 0) {
                state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
                return;
            }

            asio::async_write(state->output_file, asio::buffer(state->output_buffer.data(), outlen),
                [this, state](const asio::error_code& ec_write_final, size_t) {
                    if (ec_write_final) {
                        state->completion_handler(ec_write_final);
                        return;
                    }
                    printProgress(1.0);
                    state->completion_handler(std::error_code());
                });
    });
}

// --- ハイブリッド（ECC単体では未実装） ---
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

// --- 非同期 署名 ---
void nkCryptoToolECC::signFile(
    asio::io_context& io_context,
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& signature_filepath,
    const std::filesystem::path& signing_private_key_path,
    const std::string& digest_algo,
    std::function<void(std::error_code)> completion_handler)
{
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = completion_handler;

    auto private_key = this->loadPrivateKey(signing_private_key_path);
    if (!private_key) {
        state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
        return;
    }

    const EVP_MD* digest = EVP_get_digestbyname(digest_algo.c_str());
    if (!digest) {
        std::cerr << "Error: Unknown digest algorithm: " << digest_algo << std::endl;
        state->completion_handler(asio::error::make_error_code(asio::error::invalid_argument));
        return;
    }

    if (!state->md_ctx || EVP_DigestSignInit(state->md_ctx.get(), nullptr, digest, nullptr, private_key.get()) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::error_code ec;
    state->total_input_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { state->completion_handler(ec); return; }

    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) { state->completion_handler(ec); return; }

    state->output_file.open(signature_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) { state->completion_handler(ec); return; }

    state->input_file.async_read_some(
        asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForSigning, this, state,
                    std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec == asio::error::eof) {
        finishSigning(state);
        return;
    }
    if (ec) {
        state->completion_handler(ec);
        return;
    }

    if (EVP_DigestSignUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    state->total_bytes_processed += bytes_transferred;
    if (state->total_input_size > 0) {
        printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);
    }

    state->input_file.async_read_some(
        asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForSigning, this, state,
                    std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishSigning(std::shared_ptr<SigningState> state) {
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(state->md_ctx.get(), nullptr, &sig_len) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(state->md_ctx.get(), signature.data(), &sig_len) <= 0) {
        printOpenSSLErrors();
        state->completion_handler(asio::error::make_error_code(asio::error::operation_not_supported));
        return;
    }
    signature.resize(sig_len);

    asio::async_write(state->output_file, asio::buffer(signature),
        [this, state](const asio::error_code& write_ec, size_t) {
            printProgress(1.0);
            state->completion_handler(write_ec);
        });
}

// --- 非同期 検証 ---
void nkCryptoToolECC::verifySignature(
    asio::io_context& io_context,
    const std::filesystem::path& input_filepath,
    const std::filesystem::path& signature_filepath,
    const std::filesystem::path& signing_public_key_path,
    std::function<void(std::error_code, bool)> completion_handler)
{
    auto state = std::make_shared<VerificationState>(io_context);
    state->verification_completion_handler = completion_handler;

    auto public_key = this->loadPublicKey(signing_public_key_path);
    if (!public_key) {
        state->verification_completion_handler(asio::error::make_error_code(asio::error::invalid_argument), false);
        return;
    }
    
    // PQC/ECC署名スキームに応じてダイジェストを動的に決定する必要があるが、
    // ここではECCはSHA256を仮定する
    const EVP_MD* digest = EVP_sha256();
    if (EVP_DigestVerifyInit(state->md_ctx.get(), nullptr, digest, nullptr, public_key.get()) <= 0) {
        printOpenSSLErrors();
        state->verification_completion_handler(asio::error::make_error_code(asio::error::operation_not_supported), false);
        return;
    }

    std::error_code ec;
    state->signature_file.open(signature_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) { state->verification_completion_handler(ec, false); return; }

    uintmax_t sig_size = std::filesystem::file_size(signature_filepath, ec);
    if (ec) { state->verification_completion_handler(ec, false); return; }
    state->signature.resize(sig_size);

    asio::async_read(state->signature_file, asio::buffer(state->signature),
        [this, state, input_filepath](const asio::error_code& read_sig_ec, size_t) {
            if (read_sig_ec) {
                state->verification_completion_handler(read_sig_ec, false);
                return;
            }

            std::error_code open_ec;
            state->total_input_size = std::filesystem::file_size(input_filepath, open_ec);
            if (open_ec) { state->verification_completion_handler(open_ec, false); return; }

            state->input_file.open(input_filepath.string(), asio::stream_file::read_only, open_ec);
            if (open_ec) { state->verification_completion_handler(open_ec, false); return; }

            state->input_file.async_read_some(
                asio::buffer(state->input_buffer),
                std::bind(&nkCryptoToolECC::handleFileReadForVerification, this, state,
                            std::placeholders::_1, std::placeholders::_2));
        });
}

void nkCryptoToolECC::handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred) {
    if (ec == asio::error::eof) {
        finishVerification(state);
        return;
    }
    if (ec) {
        state->verification_completion_handler(ec, false);
        return;
    }

    if (EVP_DigestVerifyUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred) <= 0) {
        printOpenSSLErrors();
        state->verification_completion_handler(asio::error::make_error_code(asio::error::operation_not_supported), false);
        return;
    }

    state->total_bytes_processed += bytes_transferred;
    if (state->total_input_size > 0) {
        printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);
    }

    state->input_file.async_read_some(
        asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForVerification, this, state,
                    std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishVerification(std::shared_ptr<VerificationState> state) {
    printProgress(1.0);
    int result = EVP_DigestVerifyFinal(state->md_ctx.get(), state->signature.data(), state->signature.size());
    if (result == 1) {
        state->verification_completion_handler({}, true); // 検証成功
    } else if (result == 0) {
        // printOpenSSLErrors(); // これはエラーではなく、単に検証失敗を示すので不要なことが多い
        state->verification_completion_handler({}, false); // 検証失敗
    } else {
        printOpenSSLErrors();
        state->verification_completion_handler(asio::error::make_error_code(asio::error::operation_not_supported), false); // OpenSSLエラー
    }
}
