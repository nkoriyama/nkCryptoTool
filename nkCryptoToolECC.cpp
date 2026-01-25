// nkCryptoToolECC.cpp
/*
 * Copyright (c) 2024-2025 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * nkCryptoTool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nkCryptoTool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nkCryptoTool. If not, see <https://www.gnu.org/licenses/>.
 */

#include "nkCryptoToolECC.hpp"
#include "PipelineManager.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <format>
#include <openssl/bio.h> // For BIO_s_mem and PEM_write_bio_PUBKEY
#include <openssl/buffer.h> // For BUF_MEM


namespace {
    
// --- 並列/パイプライン処理用チャンク処理ヘルパー ---
static std::vector<unsigned char> ecc_encrypt_chunk_logic(
    const std::vector<unsigned char>& plain_data,
    EVP_CIPHER_CTX* template_cipher_ctx
) {
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || !EVP_CIPHER_CTX_copy(ctx.get(), template_cipher_ctx)) {
        throw std::runtime_error("OpenSSL Error: Failed to copy cipher context for encryption.");
    }
    std::vector<unsigned char> encrypted_data(plain_data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx.get(), encrypted_data.data(), &outlen, plain_data.data(), plain_data.size()) <= 0) {
        throw std::runtime_error("OpenSSL Error: Encryption update failed.");
    }
    encrypted_data.resize(outlen);
    return encrypted_data;
}

static std::vector<unsigned char> ecc_decrypt_chunk_logic(
    const std::vector<unsigned char>& encrypted_data,
    EVP_CIPHER_CTX* template_cipher_ctx
) {
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || !EVP_CIPHER_CTX_copy(ctx.get(), template_cipher_ctx)) {
        throw std::runtime_error("OpenSSL Error: Failed to copy cipher context for decryption.");
    }
    std::vector<unsigned char> decrypted_data(encrypted_data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx.get(), decrypted_data.data(), &outlen, encrypted_data.data(), encrypted_data.size()) <= 0) {
        // This is not necessarily an error, can happen at block boundaries.
    }
    decrypted_data.resize(outlen);
    return decrypted_data;
}

static std::vector<char> ecc_process_chunk(const std::vector<char>& input_data, EVP_CIPHER_CTX* template_ctx, bool is_encrypt) {
    if (input_data.empty()) return {};

    std::vector<unsigned char> input_uc(input_data.begin(), input_data.end());
    std::vector<unsigned char> processed_data_uc;

    if (is_encrypt) {
        processed_data_uc = ecc_encrypt_chunk_logic(input_uc, template_ctx);
    } else {
        processed_data_uc = ecc_decrypt_chunk_logic(input_uc, template_ctx);
    }
    
    if (is_encrypt && processed_data_uc.empty() && !input_data.empty()){
        throw std::runtime_error("Chunk encryption processing failed");
    }

    std::vector<char> result(processed_data_uc.begin(), processed_data_uc.end());
    return result;
}

} // anonymous namespace

nkCryptoToolECC::nkCryptoToolECC() {}
nkCryptoToolECC::~nkCryptoToolECC() {}

// --- 鍵パス取得 ---
std::filesystem::path nkCryptoToolECC::getEncryptionPrivateKeyPath() const { return getKeyBaseDirectory() / "private_enc_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getSigningPrivateKeyPath() const { return getKeyBaseDirectory() / "private_sign_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getEncryptionPublicKeyPath() const { return getKeyBaseDirectory() / "public_enc_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getSigningPublicKeyPath() const { return getKeyBaseDirectory() / "public_sign_ecc.key"; }

// --- 鍵ペア生成 ---
std::expected<void, CryptoError> nkCryptoToolECC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx) return std::unexpected(CryptoError::KeyGenerationInitError);

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) {
        return std::unexpected(CryptoError::ParameterError);
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
        return std::unexpected(CryptoError::KeyGenerationError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ec_key(pkey);

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) return std::unexpected(CryptoError::FileCreationError);
    
    bool success = false;
    if (passphrase.empty()) {
        std::cout << "Saving private key without encryption." << std::endl;
        success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else {
        success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0;
    }
    if (!success) return std::unexpected(CryptoError::PrivateKeyWriteError);
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) return std::unexpected(CryptoError::FileCreationError);
    if (PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) {
        return std::unexpected(CryptoError::PublicKeyWriteError);
    }
    return {};
}

std::expected<void, CryptoError> nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    return generateEncryptionKeyPair(public_key_path, private_key_path, passphrase);
}

// --- ECC署名・検証 ---
asio::awaitable<void> nkCryptoToolECC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo) {
    auto state = std::make_shared<SigningState>(io_context);

    try {
        auto private_key_res = loadPrivateKey(signing_private_key_path, "ECC signing private key");
        if (!private_key_res) {
            throw std::system_error(std::make_error_code(std::errc::invalid_argument), "Failed to load ECC signing private key: " + toString(private_key_res.error()));
        }
        auto private_key = std::move(*private_key_res);
        
        const EVP_MD* md = EVP_get_digestbyname(digest_algo.c_str());
        if (!md) {
            throw std::runtime_error("Invalid digest algorithm specified.");
        }

        if (EVP_DigestSignInit(state->md_ctx.get(), nullptr, md, nullptr, private_key.get()) <= 0) {
            throw std::runtime_error("OpenSSL Error: Failed to initialize digest signing.");
        }

        std::error_code ec;
        state->total_input_size = std::filesystem::file_size(input_filepath, ec);
        if (ec) {
            throw std::system_error(ec, "Failed to get input file size");
        }

        state->input_file.open(input_filepath.string(), O_RDONLY, ec);
        if (ec) {
            throw std::system_error(ec, "Failed to open input file");
        }
        
        state->output_file.open(signature_filepath.string(), O_WRONLY | O_CREAT | O_TRUNC, ec);
        if (ec) {
            throw std::system_error(ec, "Failed to open signature output file");
        }

        co_await handleFileReadForSigning(state);
        co_await finishSigning(state);
        std::cout << "\nFile signed successfully." << std::endl;
        co_return;
    } catch (const std::exception& e) {
        std::cerr << "Signing failed: " << e.what() << std::endl;
        throw;
    }
}

asio::awaitable<void> nkCryptoToolECC::handleFileReadForSigning(std::shared_ptr<SigningState> state) {
    asio::error_code ec;
    size_t bytes_transferred = co_await state->input_file.get().async_read_some(asio::buffer(state->input_buffer), asio::redirect_error(asio::use_awaitable, ec));

    if (ec == asio::error::eof) {
        co_return;
    }
    if (ec) {
        throw std::system_error(ec);
    }
    EVP_DigestSignUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    co_await handleFileReadForSigning(state);
}

asio::awaitable<void> nkCryptoToolECC::finishSigning(std::shared_ptr<SigningState> state) {
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(state->md_ctx.get(), nullptr, &sig_len) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to get signature length.");
    }
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(state->md_ctx.get(), signature.data(), &sig_len) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to finalize signature.");
    }
    signature.resize(sig_len);
    
    asio::error_code ec;
    co_await asio::async_write(state->output_file.get(), asio::buffer(signature), asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        throw std::system_error(ec);
    }
}


asio::awaitable<std::expected<void, CryptoError>> nkCryptoToolECC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path) {
    auto state = std::make_shared<VerificationState>(io_context);

    try {
        auto public_key_res = loadPublicKey(signing_public_key_path);
        if (!public_key_res) {
            co_return std::unexpected(public_key_res.error());
        }
        auto public_key = std::move(*public_key_res);
        
        if (EVP_DigestVerifyInit(state->md_ctx.get(), nullptr, nullptr, nullptr, public_key.get()) <= 0) {
            co_return std::unexpected(CryptoError::OpenSSLError);
        }
        
        std::error_code ec;
        state->signature_file.open(signature_filepath.string(), O_RDONLY, ec);
        if (ec) {
            co_return std::unexpected(CryptoError::FileReadError);
        }
        
        state->signature.resize(std::filesystem::file_size(signature_filepath, ec));
        if (ec) {
            co_return std::unexpected(CryptoError::FileReadError);
        }
        
        co_await asio::async_read(state->signature_file.get(), asio::buffer(state->signature), asio::redirect_error(asio::use_awaitable, ec));
        if (ec) {
            co_return std::unexpected(CryptoError::FileReadError);
        }
        
        std::error_code open_ec;
        state->total_input_size = std::filesystem::file_size(input_filepath, open_ec);
        if (open_ec) {
            co_return std::unexpected(CryptoError::FileReadError);
        }

        state->input_file.open(input_filepath.string(), O_RDONLY, open_ec);
        if (open_ec) {
            co_return std::unexpected(CryptoError::FileReadError);
        }

        co_await handleFileReadForVerification(state);

        int result = EVP_DigestVerifyFinal(state->md_ctx.get(), state->signature.data(), state->signature.size());
        if (result == 1) {
            co_return std::expected<void, CryptoError>{};
        } else {
            co_return std::unexpected(CryptoError::SignatureVerificationError);
        }

    } catch (const std::exception& e) {
        std::cerr << "Verification failed: " << e.what() << std::endl;
        co_return std::unexpected(CryptoError::OpenSSLError);
    }
}

asio::awaitable<void> nkCryptoToolECC::handleFileReadForVerification(std::shared_ptr<VerificationState> state) {
    asio::error_code ec;
    size_t bytes_transferred = co_await state->input_file.get().async_read_some(asio::buffer(state->input_buffer), asio::redirect_error(asio::use_awaitable, ec));

    if (ec == asio::error::eof) {
        co_return;
    }
    if (ec) {
        throw std::system_error(ec);
    }
    EVP_DigestVerifyUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    co_await handleFileReadForVerification(state);
}

// --- パイプライン処理の実装 ---
void nkCryptoToolECC::encryptFileWithPipeline(
    asio::io_context& io_context,
    const std::string& input_filepath,
    const std::string& output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler
) {
    try {
        auto manager = std::make_shared<PipelineManager>(io_context);
        auto wrapped_handler = [output_filepath, completion_handler, manager](const std::error_code& ec) {
            completion_handler(ec);
        };

        // 鍵導出
        std::vector<unsigned char> ephemeral_ecdh_pubkey_bytes;
        std::vector<unsigned char> secret;

        auto recipient_public_key_res = loadPublicKey(key_paths.at("recipient-pubkey"));
        if (!recipient_public_key_res) {
            throw std::runtime_error("Failed to load recipient public key: " + toString(recipient_public_key_res.error()));
        }
        auto recipient_public_key = std::move(*recipient_public_key_res);

        auto ephemeral_ecdh_key = generate_ephemeral_ec_key();
        if (!ephemeral_ecdh_key) { throw std::runtime_error("OpenSSL Error: Failed to generate ephemeral ECDH key."); }
        
        secret = ecdh_generate_shared_secret(ephemeral_ecdh_key.get(), recipient_public_key.get());
        if (secret.empty()) { throw std::runtime_error("OpenSSL Error: ECDH shared secret generation failed."); }
        
        std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
        if (!PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_ecdh_key.get())) { throw std::runtime_error("Failed to write ephemeral ECDH key to BIO."); }
        BUF_MEM *bio_buf; BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
        ephemeral_ecdh_pubkey_bytes.assign(bio_buf->data, bio_buf->data + bio_buf->length);

        std::vector<unsigned char> salt(16), iv(GCM_IV_LEN);
        RAND_bytes(salt.data(), salt.size());
        RAND_bytes(iv.data(), iv.size());
        std::vector<unsigned char> encryption_key = hkdfDerive(secret, 32, std::string(salt.begin(), salt.end()), "ecc-encryption", "SHA3-256");
        if (encryption_key.empty()) throw std::runtime_error("Failed to derive encryption key with HKDF.");

        auto template_ctx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
        EVP_EncryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());

        // ファイル書き込み
        std::error_code ec;
        async_file_t output_file(io_context);
        output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
        if (ec) throw std::system_error(ec, "Failed to open output file for header writing");

        FileHeader header;
        memcpy(header.magic, MAGIC, sizeof(MAGIC));
        header.version = 1;
        header.reserved = 0; // Not hybrid
        asio::write(output_file.get(), asio::buffer(&header, sizeof(header)), ec); if(ec) throw std::system_error(ec, "Failed to write file header");
        
        uint32_t len;
        len = ephemeral_ecdh_pubkey_bytes.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write ECDH key length");
        asio::write(output_file.get(), asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) throw std::system_error(ec, "Failed to write ECDH key");
        len = salt.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write salt length");
        asio::write(output_file.get(), asio::buffer(salt), ec); if(ec) throw std::system_error(ec, "Failed to write salt");
        len = iv.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write IV length");
        asio::write(output_file.get(), asio::buffer(iv), ec); if(ec) throw std::system_error(ec, "Failed to write IV");
        
        // パイプライン実行
        manager->add_stage([template_ctx](const std::vector<char>& data) {
            return ecc_process_chunk(data, template_ctx.get(), true);
        });

        PipelineManager::FinalizationFunc finalizer = [this, template_ctx](async_file_t& out_final) -> asio::awaitable<void> {
            auto final_block = std::make_shared<std::vector<unsigned char>>(EVP_MAX_BLOCK_LENGTH);
            auto tag = std::make_shared<std::vector<unsigned char>>(GCM_TAG_LEN);
            int final_len = 0;

            if (EVP_EncryptFinal_ex(template_ctx.get(), final_block->data(), &final_len) <= 0) {
                printOpenSSLErrors();
                throw std::runtime_error("Failed to finalize encryption.");
            }
            final_block->resize(final_len);

            if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag->data()) <= 0) {
                printOpenSSLErrors();
                throw std::runtime_error("Failed to get GCM tag.");
            }

            if (!final_block->empty()) {
                co_await asio::async_write(out_final.get(), asio::buffer(*final_block), asio::use_awaitable);
            }
            co_await asio::async_write(out_final.get(), asio::buffer(*tag), asio::use_awaitable);
        };
        
        uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) throw std::system_error(ec);
        manager->run(input_filepath, std::move(output_file), 0, total_input_size, wrapped_handler, std::move(finalizer));

    } catch (const std::exception& e) {
        std::cerr << "\nPipeline encryption setup failed: " << e.what() << std::endl;
        completion_handler(std::make_error_code(std::errc::io_error));
    }
}

void nkCryptoToolECC::decryptFileWithPipeline(
    asio::io_context& io_context,
    const std::string& input_filepath,
    const std::string& output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler
) {
    try {
        auto manager = std::make_shared<PipelineManager>(io_context);
        auto wrapped_handler = [output_filepath, completion_handler, manager](const std::error_code& ec) {
            completion_handler(ec);
        };

        // ファイルヘッダー読み込みと鍵導出
        std::error_code ec;
        async_file_t input_file(io_context);
        input_file.open(input_filepath, O_RDONLY, ec);
        if (ec) throw std::system_error(ec, "Failed to open input file for header reading");

        FileHeader header; asio::read(input_file.get(), asio::buffer(&header, sizeof(header)), ec);
        if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) {
            throw std::runtime_error("Invalid file header");
        }

        uint32_t len;
        std::vector<unsigned char> ephemeral_ecdh_pubkey_bytes, salt, iv;
        asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read ECDH key length"); }
        ephemeral_ecdh_pubkey_bytes.resize(len);
        asio::read(input_file.get(), asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) { throw std::runtime_error("Failed to read ECDH key"); }

        asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read salt length"); }
        salt.resize(len);
        asio::read(input_file.get(), asio::buffer(salt), ec); if(ec) { throw std::runtime_error("Failed to read salt"); }
        asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read IV length"); }
        iv.resize(len);
        asio::read(input_file.get(), asio::buffer(iv), ec); if(ec) { throw std::runtime_error("Failed to read IV"); }
        
        uintmax_t header_size = 0;
#ifdef _WIN32
        header_size = input_file.get().seek(0, asio::file_base::seek_cur, ec);
#else
        off_t pos = ::lseek(input_file.native_handle(), 0, SEEK_CUR);
        if (pos == (off_t)-1) {
            ec.assign(errno, std::system_category());
        } else {
            header_size = pos;
        }
#endif
        if(ec) { throw std::system_error(ec); }

        auto user_private_key_res = loadPrivateKey(key_paths.at("user-privkey"), "ECC private key");
        if (!user_private_key_res) {
            throw std::runtime_error("Failed to load user private key: " + toString(user_private_key_res.error()));
        }
        auto user_private_key = std::move(*user_private_key_res);
        
        std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(ephemeral_ecdh_pubkey_bytes.data(), ephemeral_ecdh_pubkey_bytes.size()));
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
        if(!ephemeral_pub_key) { throw std::runtime_error("OpenSSL Error: Failed to parse ephemeral ECDH key."); }
        
        std::vector<unsigned char> secret = ecdh_generate_shared_secret(user_private_key.get(), ephemeral_pub_key.get());
        if (secret.empty()) { throw std::runtime_error("OpenSSL Error: ECDH shared secret generation failed."); }

        std::vector<unsigned char> decryption_key = hkdfDerive(secret, 32, std::string(salt.begin(), salt.end()), "ecc-encryption", "SHA3-256");
        if (decryption_key.empty()) throw std::runtime_error("Failed to derive decryption key with HKDF.");

        auto template_ctx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
        EVP_DecryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());

        // パイプライン実行
        async_file_t output_file(io_context);
        output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
        if (ec) throw std::system_error(ec, "Failed to create output file");

        manager->add_stage([template_ctx](const std::vector<char>& data) {
            return ecc_process_chunk(data, template_ctx.get(), false);
        });

        PipelineManager::FinalizationFunc finalizer = [this, template_ctx, &io_context, input_filepath, header_size](async_file_t& out_final) -> asio::awaitable<void> {
            auto tag = std::make_shared<std::vector<unsigned char>>(GCM_TAG_LEN);
            auto final_block = std::make_shared<std::vector<unsigned char>>(EVP_MAX_BLOCK_LENGTH);
            int final_len = 0;
            
            async_file_t in_final(io_context);
            std::error_code final_ec;
            in_final.open(input_filepath, O_RDONLY, final_ec);
            if(final_ec) throw std::system_error(final_ec, "Failed to open input for finalization");

#ifdef _WIN32
            uintmax_t file_size = in_final.get().size(final_ec);
            if (!final_ec) {
                in_final.get().seek(file_size - GCM_TAG_LEN, asio::file_base::seek_set, final_ec);
            }
#else
            struct stat stat_buf;
            uintmax_t file_size = 0;
            if (::fstat(in_final.native_handle(), &stat_buf) != -1) {
                file_size = stat_buf.st_size;
            } else {
                final_ec.assign(errno, std::system_category());
            }

            if (!final_ec) {
                if (::lseek(in_final.native_handle(), file_size - GCM_TAG_LEN, SEEK_SET) == -1) {
                    final_ec.assign(errno, std::system_category());
                }
            }
#endif
            if(final_ec) { throw std::system_error(final_ec, "Failed to get size or seek input for finalization"); }
            
            co_await asio::async_read(in_final.get(), asio::buffer(*tag), asio::use_awaitable);
            in_final.close(); // Close after reading tag
            
            if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag->data()) <= 0) {
                 throw std::runtime_error("Failed to set GCM tag.");
            }

            if (EVP_DecryptFinal_ex(template_ctx.get(), final_block->data(), &final_len) <= 0) {
                printOpenSSLErrors();
                throw std::runtime_error("GCM tag verification failed. File may be corrupted or tampered with.");
            }
            final_block->resize(final_len);
            
            if (!final_block->empty()) {
                 co_await asio::async_write(out_final.get(), asio::buffer(*final_block), asio::use_awaitable);
            }
        };

        uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) throw std::system_error(ec);
        uintmax_t ciphertext_size = total_input_size - header_size - GCM_TAG_LEN;
        
        manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, wrapped_handler, std::move(finalizer));
        input_file.close();

    } catch (const std::exception& e) {
        std::cerr << "\nPipeline decryption setup failed: " << e.what() << std::endl;
        completion_handler(std::make_error_code(std::errc::io_error));
    }
}