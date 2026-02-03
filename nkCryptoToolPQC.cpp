// nkCryptoToolPQC.cpp
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

#include "nkCryptoToolPQC.hpp"
#include "PipelineManager.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>
#include <functional>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/params.h> // Required for OSSL_PARAM_construct_size_t KEM parameters
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <format>
#include <fstream>



// --- 並列/パイプライン処理用チャンク処理ヘルパー ---
static std::vector<unsigned char> pqc_encrypt_chunk_logic(
    const std::vector<unsigned char>& plain_data,
    EVP_CIPHER_CTX* template_cipher_ctx
) {
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || !EVP_CIPHER_CTX_copy(ctx.get(), template_cipher_ctx)) throw std::runtime_error("OpenSSL Error: Failed to copy cipher context for encryption.");
    std::vector<unsigned char> encrypted_data(plain_data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx.get(), encrypted_data.data(), &outlen, plain_data.data(), plain_data.size()) <= 0) throw std::runtime_error("OpenSSL Error: Encryption update failed.");
    encrypted_data.resize(outlen);
    return encrypted_data;
}

static std::vector<unsigned char> pqc_decrypt_chunk_logic(
    const std::vector<unsigned char>& encrypted_data,
    EVP_CIPHER_CTX* template_cipher_ctx
) {
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || !EVP_CIPHER_CTX_copy(ctx.get(), template_cipher_ctx)) throw std::runtime_error("OpenSSL Error: Failed to copy cipher context for decryption.");
    std::vector<unsigned char> decrypted_data(encrypted_data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx.get(), decrypted_data.data(), &outlen, encrypted_data.data(), encrypted_data.size()) <= 0) {
        // This is not necessarily an error, can happen at block boundaries.
        // The final verification is done by DecryptFinal and the GCM tag.
    }
    decrypted_data.resize(outlen);
    return decrypted_data;
}

static std::vector<char> pqc_process_chunk(const std::vector<char>& input_data, EVP_CIPHER_CTX* template_ctx, bool is_encrypt) {
    if (input_data.empty()) return {};

    std::vector<unsigned char> input_uc(input_data.begin(), input_data.end());
    std::vector<unsigned char> processed_data_uc;

    if (is_encrypt) {
        processed_data_uc = pqc_encrypt_chunk_logic(input_uc, template_ctx);
    } else {
        processed_data_uc = pqc_decrypt_chunk_logic(input_uc, template_ctx);
    }
    
    if (is_encrypt && processed_data_uc.empty() && !input_data.empty()){
        throw std::runtime_error("Chunk encryption processing failed");
    }

    std::vector<char> result(processed_data_uc.begin(), processed_data_uc.end());
    return result;
}



nkCryptoToolPQC::nkCryptoToolPQC() {}
nkCryptoToolPQC::~nkCryptoToolPQC() {}

// --- 鍵パス取得 ---
std::filesystem::path nkCryptoToolPQC::getEncryptionPrivateKeyPath() const { return getKeyBaseDirectory() / "private_enc_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getSigningPrivateKeyPath() const { return getKeyBaseDirectory() / "private_sign_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getEncryptionPublicKeyPath() const { return getKeyBaseDirectory() / "public_enc_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getSigningPublicKeyPath() const { return getKeyBaseDirectory() / "public_sign_pqc.key"; }

// --- 鍵ペア生成 ---
std::expected<void, CryptoError> nkCryptoToolPQC::generateEncryptionKeyPair(std::filesystem::path public_key_path, std::filesystem::path private_key_path, std::string passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { return std::unexpected(CryptoError::KeyGenerationInitError); }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { return std::unexpected(CryptoError::KeyGenerationError); }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> kem_key(pkey);
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { return std::unexpected(CryptoError::FileCreationError); }
    bool success = false;
    if (passphrase.empty()) { std::cout << "Saving private key without encryption." << std::endl; success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else { success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0; }
    if (!success) { return std::unexpected(CryptoError::PrivateKeyWriteError); }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), kem_key.get()) <= 0) { return std::unexpected(CryptoError::PublicKeyWriteError); }
    return {};
}

std::expected<void, CryptoError> nkCryptoToolPQC::generateSigningKeyPair(std::filesystem::path public_key_path, std::filesystem::path private_key_path, std::string passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
// pctx が生成できなかった理由を標準エラーに出力します
    ERR_print_errors_fp(stderr);
      return std::unexpected(CryptoError::KeyGenerationInitError); }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { return std::unexpected(CryptoError::KeyGenerationError); }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> dsa_key(pkey);
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { return std::unexpected(CryptoError::FileCreationError); }
    bool success = false;
    if (passphrase.empty()) { std::cout << "Saving private key without encryption." << std::endl; success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else { success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0; }
    if (!success) { return std::unexpected(CryptoError::PrivateKeyWriteError); }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), dsa_key.get()) <= 0) { return std::unexpected(CryptoError::PublicKeyWriteError); }
    return {};
}



// --- PQC署名・検証 ---
asio::awaitable<void> nkCryptoToolPQC::signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, std::string passphrase) {
    auto state = std::make_shared<SigningState>(io_context);

    try {
        auto private_key_res = loadPrivateKey(signing_private_key_path, passphrase);
        if (!private_key_res) {
            throw std::system_error(std::make_error_code(std::errc::invalid_argument), "Failed to load PQC signing private key: " + toString(private_key_res.error()));
        }
        state->private_key = std::move(*private_key_res);
        
        const EVP_MD* md = EVP_get_digestbyname(digest_algo.c_str());
        if (!md) {
            throw std::runtime_error("Invalid digest algorithm specified.");
        }

        // Initialize md_ctx for hashing only
        if (EVP_DigestInit_ex(state->md_ctx.get(), md, nullptr) <= 0) {
            throw std::runtime_error("OpenSSL Error: Failed to initialize digest for hashing.");
        }

        std::error_code ec;
        state->total_input_size = std::filesystem::file_size(input_filepath, ec);
        if(ec) {
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

asio::awaitable<void> nkCryptoToolPQC::handleFileReadForSigning(std::shared_ptr<SigningState> state) {
    asio::error_code ec;
    size_t bytes_transferred = co_await state->input_file.get().async_read_some(asio::buffer(state->input_buffer), asio::redirect_error(asio::use_awaitable, ec));

    if (ec == asio::error::eof) {
        co_return;
    }
    if (ec) {
        throw std::system_error(ec);
    }
    EVP_DigestUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    co_await handleFileReadForSigning(state);
}

asio::awaitable<void> nkCryptoToolPQC::finishSigning(std::shared_ptr<SigningState> state) {
    // Finalize the hash
    unsigned int final_hash_len = EVP_MD_CTX_size(state->md_ctx.get());
    state->final_hash.resize(final_hash_len);
    if (EVP_DigestFinal_ex(state->md_ctx.get(), state->final_hash.data(), &final_hash_len) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to finalize digest for signing.");
    }

    // Now, perform the actual signing using EVP_DigestSign (one-shot)
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> sign_ctx(EVP_MD_CTX_new());
    if (!sign_ctx) {
        throw std::runtime_error("OpenSSL Error: Failed to create signing context.");
    }

    // Pass nullptr for the digest type for ML-DSA
    if (EVP_DigestSignInit(sign_ctx.get(), nullptr, nullptr, nullptr, state->private_key.get()) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to initialize one-shot digest signing.");
    }

    size_t sig_len = 0;
    // Get signature length
    if (EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, state->final_hash.data(), state->final_hash.size()) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to get one-shot signature length.");
    }

    std::vector<unsigned char> signature(sig_len);
    // Generate signature
    if (EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, state->final_hash.data(), state->final_hash.size()) <= 0) {
        throw std::runtime_error("OpenSSL Error: Failed to generate one-shot signature.");
    }
    signature.resize(sig_len); // Adjust size in case it was smaller than max

    asio::error_code ec;
    co_await asio::async_write(state->output_file.get(), asio::buffer(signature), asio::redirect_error(asio::use_awaitable, ec));
    if (ec) {
        throw std::system_error(ec);
    }
}


asio::awaitable<std::expected<void, CryptoError>> nkCryptoToolPQC::verifySignature(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_public_key_path, std::string digest_algo) {
    auto state = std::make_shared<VerificationState>(io_context);

    try {
        auto public_key_res = loadPublicKey(signing_public_key_path);
        if (!public_key_res) {
            co_return std::unexpected(public_key_res.error());
        }
        state->public_key = std::move(*public_key_res);

        // Initialize md_ctx for hashing only
        // Get digest type from public key (e.g., for ML-DSA-87 it could be SHA3-512)
        // For ML-DSA-87, assume SHA3-512 as the digest algorithm
        const EVP_MD* md = EVP_get_digestbyname(digest_algo.c_str());
        if (!md) {
            md = EVP_sha3_512(); // フォールバック
        }

        if (EVP_DigestInit_ex(state->md_ctx.get(), md, nullptr) <= 0) {
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

        // Finalize the hash
        unsigned int final_hash_len = EVP_MD_CTX_size(state->md_ctx.get());
        state->final_hash.resize(final_hash_len);
        if (EVP_DigestFinal_ex(state->md_ctx.get(), state->final_hash.data(), &final_hash_len) <= 0) {
            co_return std::unexpected(CryptoError::OpenSSLError);
        }

        // Now, perform the actual verification using EVP_DigestVerify (one-shot)
        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> verify_ctx(EVP_MD_CTX_new());
        if (!verify_ctx) {
            co_return std::unexpected(CryptoError::OpenSSLError);
        }

        // Pass nullptr for the digest type for ML-DSA
        if (EVP_DigestVerifyInit(verify_ctx.get(), nullptr, nullptr, nullptr, state->public_key.get()) <= 0) {
            co_return std::unexpected(CryptoError::OpenSSLError);
        }

        int result = EVP_DigestVerify(verify_ctx.get(),
            state->signature.data(), state->signature.size(), 
            state->final_hash.data(), state->final_hash.size());
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

asio::awaitable<void> nkCryptoToolPQC::handleFileReadForVerification(std::shared_ptr<VerificationState> state) {
    asio::error_code ec;
    size_t bytes_transferred = co_await state->input_file.get().async_read_some(asio::buffer(state->input_buffer), asio::redirect_error(asio::use_awaitable, ec));

    if (ec == asio::error::eof) {
        co_return;
    }
    if (ec) {
        throw std::system_error(ec);
    }
    EVP_DigestUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    co_await handleFileReadForVerification(state);
}

// --- パイプライン処理の実装 ---
void nkCryptoToolPQC::encryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback
) {
    try {
        bool is_hybrid = key_paths.count("recipient-ecdh-pubkey");
        
        auto manager = std::make_shared<PipelineManager>(io_context);
        auto wrapped_handler = [output_filepath, completion_handler, manager](const std::error_code& ec) {
            completion_handler(ec);
        };

        // --- 鍵導出 ---
        std::vector<unsigned char> combined_secret; 
        std::vector<unsigned char> encapsulated_key_mlkem; 
        std::vector<unsigned char> ephemeral_ecdh_pubkey_bytes;
        
        const auto& mlkem_pub_key_path = key_paths.at(is_hybrid ? "recipient-mlkem-pubkey" : "recipient-pubkey");
        auto recipient_mlkem_public_key_res = loadPublicKey(mlkem_pub_key_path);
        if (!recipient_mlkem_public_key_res) {
            throw std::runtime_error("Failed to load recipient ML-KEM public key: " + toString(recipient_mlkem_public_key_res.error()));
        }
        auto recipient_mlkem_public_key = std::move(*recipient_mlkem_public_key_res);

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_public_key.get(), nullptr));
        if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_encapsulate_init failed."); }
        size_t secret_len_mlkem = 0, enc_len_mlkem = 0;
        // Corrected: Use standard EVP_PKEY_encapsulate signature for getting lengths
        if (EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &enc_len_mlkem, nullptr, &secret_len_mlkem) <= 0) { ERR_clear_error(); throw std::runtime_error("OpenSSL Error: EVP_PKEY_encapsulate get length failed."); }
        std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
        encapsulated_key_mlkem.resize(enc_len_mlkem);
        // Corrected: Use standard EVP_PKEY_encapsulate signature for encapsulation
        if (EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key_mlkem.data(), &enc_len_mlkem, secret_mlkem.data(), &secret_len_mlkem) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_encapsulate failed."); }
        combined_secret = secret_mlkem;

        if (is_hybrid) {
            auto recipient_ecdh_public_key_res = loadPublicKey(key_paths.at("recipient-ecdh-pubkey"));
            if (!recipient_ecdh_public_key_res) {
                throw std::runtime_error("Failed to load recipient ECDH public key: " + toString(recipient_ecdh_public_key_res.error()));
            }
            auto recipient_ecdh_public_key = std::move(*recipient_ecdh_public_key_res);
            auto ephemeral_ecdh_key = generate_ephemeral_ec_key();
            if (!ephemeral_ecdh_key) { throw std::runtime_error("OpenSSL Error: Failed to generate ephemeral ECDH key."); }
            std::vector<unsigned char> secret_ecdh = ecdh_generate_shared_secret(ephemeral_ecdh_key.get(), recipient_ecdh_public_key.get());
            if (secret_ecdh.empty()) { throw std::runtime_error("OpenSSL Error: ECDH shared secret generation failed."); }
            
            std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
            if (!PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_ecdh_key.get())) { throw std::runtime_error("Failed to write ephemeral ECDH key to BIO."); }
            BUF_MEM *bio_buf; BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
            ephemeral_ecdh_pubkey_bytes.assign(bio_buf->data, bio_buf->data + bio_buf->length);
            combined_secret.insert(combined_secret.end(), secret_ecdh.begin(), secret_ecdh.end());
        }

        std::vector<unsigned char> salt(16), iv(GCM_IV_LEN); 
        RAND_bytes(salt.data(), salt.size()); 
        RAND_bytes(iv.data(), iv.size());
        std::vector<unsigned char> encryption_key = hkdfDerive(combined_secret, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
        if (encryption_key.empty()) throw std::runtime_error("Failed to derive encryption key with HKDF.");

        auto template_ctx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
        EVP_EncryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());

        // --- ファイル書き込み ---
        std::error_code ec;
        async_file_t output_file(io_context);
        output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
        if (ec) throw std::system_error(ec, "Failed to open output file for header writing");

        FileHeader header; 
        memcpy(header.magic, MAGIC, sizeof(MAGIC)); 
        header.version = 1; 
        header.reserved = is_hybrid ? 1 : 0;
        asio::write(output_file.get(), asio::buffer(&header, sizeof(header)), ec); if(ec) throw std::system_error(ec, "Failed to write file header");
        
        uint32_t len;
        len = encapsulated_key_mlkem.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write ML-KEM key length");
        asio::write(output_file.get(), asio::buffer(encapsulated_key_mlkem), ec); if(ec) throw std::system_error(ec, "Failed to write ML-KEM key");
        if (is_hybrid) {
            len = ephemeral_ecdh_pubkey_bytes.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write ECDH key length");
            asio::write(output_file.get(), asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) throw std::system_error(ec, "Failed to write ECDH key");
        }
        len = salt.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write salt length");
        asio::write(output_file.get(), asio::buffer(salt), ec); if(ec) throw std::system_error(ec, "Failed to write salt");
        len = iv.size(); asio::write(output_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec, "Failed to write IV length");
        asio::write(output_file.get(), asio::buffer(iv), ec); if(ec) throw std::system_error(ec, "Failed to write IV");

        // --- パイプライン実行 ---
        manager->add_stage([template_ctx](const std::vector<char>& data) {
            return pqc_process_chunk(data, template_ctx.get(), true);
        });

        PipelineManager::FinalizationFunc finalizer = [this, template_ctx](async_file_t& out_final) -> asio::awaitable<void> {
            auto final_block = std::make_shared<std::vector<unsigned char>>(EVP_MAX_BLOCK_LENGTH);
            auto tag = std::make_shared<std::vector<unsigned char>>(GCM_TAG_LEN);
            int final_len = 0;
            if (EVP_EncryptFinal_ex(template_ctx.get(), final_block->data(), &final_len) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to finalize encryption."); }
            final_block->resize(final_len);
            if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag->data()) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to get GCM tag."); }
            if (!final_block->empty()) { co_await asio::async_write(out_final.get(), asio::buffer(*final_block), asio::use_awaitable); }
            co_await asio::async_write(out_final.get(), asio::buffer(*tag), asio::use_awaitable);

        };
        
        uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) throw std::system_error(ec);
        manager->run(input_filepath, std::move(output_file), 0, total_input_size, wrapped_handler, std::move(finalizer), progress_callback, total_input_size);

    } catch (const std::exception& e) {
        std::cerr << "\nPipeline encryption setup failed: " << e.what() << std::endl;
        completion_handler(std::make_error_code(std::errc::io_error));
    }
}

void nkCryptoToolPQC::decryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::string passphrase,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback
) {
    try {
        auto manager = std::make_shared<PipelineManager>(io_context);
        auto wrapped_handler = [output_filepath, completion_handler, manager](const std::error_code& ec) {
            completion_handler(ec);
        };

        // --- ファイルヘッダー読み込みと鍵導出 ---
        std::error_code ec;
        async_file_t input_file(io_context);
        input_file.open(input_filepath, O_RDONLY, ec);
        if (ec) throw std::system_error(ec, "Failed to open input file for header reading");
        
        FileHeader header; asio::read(input_file.get(), asio::buffer(&header, sizeof(header)), ec); 
        if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) { throw std::runtime_error("Invalid file header"); }
        bool is_hybrid = header.reserved == 1;
        if (is_hybrid && !key_paths.count("recipient-ecdh-privkey")) { throw std::runtime_error("Hybrid file requires ECDH private key."); }

        uint32_t len;
        std::vector<unsigned char> encapsulated_key_mlkem, ephemeral_ecdh_pubkey_bytes, salt, iv;
        asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read ML-KEM key length");} encapsulated_key_mlkem.resize(len);
        asio::read(input_file.get(), asio::buffer(encapsulated_key_mlkem), ec); if(ec) { throw std::runtime_error("Failed to read ML-KEM key");}
        if(is_hybrid) {
            asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read ECDH key length");} ephemeral_ecdh_pubkey_bytes.resize(len);
            asio::read(input_file.get(), asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) { throw std::runtime_error("Failed to read ECDH key");}
        }
        asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read salt length");} salt.resize(len);
        asio::read(input_file.get(), asio::buffer(salt), ec); if(ec) { throw std::runtime_error("Failed to read salt");}
        asio::read(input_file.get(), asio::buffer(&len, sizeof(len)), ec); if(ec) { throw std::runtime_error("Failed to read IV length");} iv.resize(len);
        asio::read(input_file.get(), asio::buffer(iv), ec); if(ec) { throw std::runtime_error("Failed to read IV");}
        
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

        std::vector<unsigned char> combined_secret;
        const auto& mlkem_priv_key_path = key_paths.at(is_hybrid ? "recipient-mlkem-privkey" : "user-privkey");
        auto recipient_mlkem_private_key_res = loadPrivateKey(mlkem_priv_key_path, passphrase);
        if (!recipient_mlkem_private_key_res) throw std::runtime_error("Failed to load user ML-KEM private key.");
        auto recipient_mlkem_private_key = std::move(*recipient_mlkem_private_key_res);
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_private_key.get(), nullptr));
        if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_decapsulate_init failed."); }
        size_t secret_len_mlkem = 0;
        // Corrected: Use standard EVP_PKEY_decapsulate signature for getting lengths
        if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { ERR_clear_error(); throw std::runtime_error("OpenSSL Error: EVP_PKEY_decapsulate get length failed."); }
        std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
        // Corrected: Use standard EVP_PKEY_decapsulate signature for decapsulation
        if (EVP_PKEY_decapsulate(kem_ctx.get(), secret_mlkem.data(), &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { throw std::runtime_error("OpenSSL Error: Decapsulation failed. The private key may be incorrect or the data corrupted."); }
        combined_secret = secret_mlkem;
        
        if(is_hybrid) {
            auto recipient_ecdh_private_key_res = loadPrivateKey(key_paths.at("recipient-ecdh-privkey"), passphrase);
            if (!recipient_ecdh_private_key_res) throw std::runtime_error("Failed to load user ECDH private key.");
            auto recipient_ecdh_private_key = std::move(*recipient_ecdh_private_key_res);
            std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(ephemeral_ecdh_pubkey_bytes.data(), ephemeral_ecdh_pubkey_bytes.size()));
            std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
            if(!ephemeral_pub_key) { throw std::runtime_error("OpenSSL Error: Failed to parse ephemeral ECDH key."); }
            std::vector<unsigned char> secret_ecdh = ecdh_generate_shared_secret(recipient_ecdh_private_key.get(), ephemeral_pub_key.get());
            if (secret_ecdh.empty()) { throw std::runtime_error("OpenSSL Error: ECDH shared secret generation failed."); }
            combined_secret.insert(combined_secret.end(), secret_ecdh.begin(), secret_ecdh.end());
        }

        std::vector<unsigned char> decryption_key = hkdfDerive(combined_secret, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
        if (decryption_key.empty()) throw std::runtime_error("Failed to derive decryption key.");
        
        auto template_ctx = std::shared_ptr<EVP_CIPHER_CTX>(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
        EVP_DecryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());

        // --- パイプライン実行 ---
        async_file_t output_file(io_context);
        output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
        if (ec) throw std::system_error(ec, "Failed to create output file");

        manager->add_stage([template_ctx](const std::vector<char>& data) {
            return pqc_process_chunk(data, template_ctx.get(), false);
        });

        PipelineManager::FinalizationFunc finalizer = [this, template_ctx, &io_context, input_filepath](async_file_t& out_final) -> asio::awaitable<void> {
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
                 if(::lseek(in_final.native_handle(), file_size - GCM_TAG_LEN, SEEK_SET) == -1) {
                     final_ec.assign(errno, std::system_category());
                 }
            }
#endif
            if(final_ec) { throw std::system_error(final_ec, "Failed to seek for finalization");}
            
            co_await asio::async_read(in_final.get(), asio::buffer(*tag), asio::use_awaitable);
            in_final.close(); // Close after reading tag

            if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag->data()) <= 0) { throw std::runtime_error("Failed to set GCM tag."); }
            if (EVP_DecryptFinal_ex(template_ctx.get(), final_block->data(), &final_len) <= 0) { throw std::runtime_error("OpenSSL Error: GCM tag verification failed. File may be corrupted or tampered with."); }
            final_block->resize(final_len);
            
            if (!final_block->empty()) { co_await asio::async_write(out_final.get(), asio::buffer(*final_block), asio::use_awaitable); }
        };

        uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) throw std::system_error(ec);
        uintmax_t ciphertext_size = total_input_size - header_size - GCM_TAG_LEN;
        
        // The input_file is moved here, its lifetime is managed by the PipelineManager
        manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, wrapped_handler, std::move(finalizer), progress_callback, total_input_size);
        input_file.close(); // Close the original handle after moving from it

    } catch (const std::exception& e) {
        std::cerr << "\nPipeline decryption setup failed: " << e.what() << std::endl;
        completion_handler(std::make_error_code(std::errc::io_error));
    }
}

void nkCryptoToolPQC::encryptFileWithSync(
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths
) {
    try {
        bool is_hybrid = key_paths.count("recipient-ecdh-pubkey");

        // Key Derivation
        std::vector<unsigned char> combined_secret;
        std::vector<unsigned char> encapsulated_key_mlkem;
        std::vector<unsigned char> ephemeral_ecdh_pubkey_bytes;
        
        const auto& mlkem_pub_key_path = key_paths.at(is_hybrid ? "recipient-mlkem-pubkey" : "recipient-pubkey");
        auto recipient_mlkem_public_key_res = loadPublicKey(mlkem_pub_key_path);
        if (!recipient_mlkem_public_key_res) throw std::runtime_error("Failed to load recipient ML-KEM public key: " + toString(recipient_mlkem_public_key_res.error()));
        auto recipient_mlkem_public_key = std::move(*recipient_mlkem_public_key_res);

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_public_key.get(), nullptr));
        if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) throw std::runtime_error("EVP_PKEY_encapsulate_init failed.");
        
        size_t secret_len_mlkem = 0, enc_len_mlkem = 0;
        if (EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &enc_len_mlkem, nullptr, &secret_len_mlkem) <= 0) throw std::runtime_error("EVP_PKEY_encapsulate get length failed.");
        
        std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
        encapsulated_key_mlkem.resize(enc_len_mlkem);
        if (EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key_mlkem.data(), &enc_len_mlkem, secret_mlkem.data(), &secret_len_mlkem) <= 0) throw std::runtime_error("EVP_PKEY_encapsulate failed.");
        combined_secret = secret_mlkem;

        if (is_hybrid) {
            auto recipient_ecdh_public_key_res = loadPublicKey(key_paths.at("recipient-ecdh-pubkey"));
            if (!recipient_ecdh_public_key_res) throw std::runtime_error("Failed to load recipient ECDH public key: " + toString(recipient_ecdh_public_key_res.error()));
            auto recipient_ecdh_public_key = std::move(*recipient_ecdh_public_key_res);
            auto ephemeral_ecdh_key = generate_ephemeral_ec_key();
            std::vector<unsigned char> secret_ecdh = ecdh_generate_shared_secret(ephemeral_ecdh_key.get(), recipient_ecdh_public_key.get());
            
            std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
            PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_ecdh_key.get());
            BUF_MEM *bio_buf; BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
            ephemeral_ecdh_pubkey_bytes.assign(bio_buf->data, bio_buf->data + bio_buf->length);
            combined_secret.insert(combined_secret.end(), secret_ecdh.begin(), secret_ecdh.end());
        }

        std::vector<unsigned char> salt(16), iv(GCM_IV_LEN);
        RAND_bytes(salt.data(), salt.size());
        RAND_bytes(iv.data(), iv.size());
        std::vector<unsigned char> encryption_key = hkdfDerive(combined_secret, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");

        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>(EVP_CIPHER_CTX_new());
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());

        // File I/O
        std::ifstream input_file(input_filepath, std::ios::binary);
        std::ofstream output_file(output_filepath, std::ios::binary | std::ios::trunc);

        // Write header
        FileHeader header;
        memcpy(header.magic, MAGIC, sizeof(MAGIC));
        header.version = 1;
        header.reserved = is_hybrid ? 1 : 0;
        output_file.write(reinterpret_cast<const char*>(&header), sizeof(header));
        
        uint32_t len;
        len = encapsulated_key_mlkem.size(); output_file.write(reinterpret_cast<const char*>(&len), sizeof(len));
        output_file.write(reinterpret_cast<const char*>(encapsulated_key_mlkem.data()), encapsulated_key_mlkem.size());
        if (is_hybrid) {
            len = ephemeral_ecdh_pubkey_bytes.size(); output_file.write(reinterpret_cast<const char*>(&len), sizeof(len));
            output_file.write(reinterpret_cast<const char*>(ephemeral_ecdh_pubkey_bytes.data()), ephemeral_ecdh_pubkey_bytes.size());
        }
        len = salt.size(); output_file.write(reinterpret_cast<const char*>(&len), sizeof(len));
        output_file.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        len = iv.size(); output_file.write(reinterpret_cast<const char*>(&len), sizeof(len));
        output_file.write(reinterpret_cast<const char*>(iv.data()), iv.size());

        // Sync loop
        std::vector<char> in_buffer(CHUNK_SIZE);
        std::vector<unsigned char> out_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
        int out_len = 0;
        while (input_file.read(in_buffer.data(), in_buffer.size())) {
            EVP_EncryptUpdate(ctx.get(), out_buffer.data(), &out_len, reinterpret_cast<const unsigned char*>(in_buffer.data()), input_file.gcount());
            output_file.write(reinterpret_cast<const char*>(out_buffer.data()), out_len);
        }
        if(input_file.gcount() > 0){
             EVP_EncryptUpdate(ctx.get(), out_buffer.data(), &out_len, reinterpret_cast<const unsigned char*>(in_buffer.data()), input_file.gcount());
             output_file.write(reinterpret_cast<const char*>(out_buffer.data()), out_len);
        }

        // Finalization
        EVP_EncryptFinal_ex(ctx.get(), out_buffer.data(), &out_len);
        output_file.write(reinterpret_cast<const char*>(out_buffer.data()), out_len);
        
        std::vector<unsigned char> tag(GCM_TAG_LEN);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag.data());
        output_file.write(reinterpret_cast<const char*>(tag.data()), tag.size());

    } catch (const std::exception& e) {
        std::cerr << "\nSynchronous PQC encryption failed: " << e.what() << std::endl;
        throw;
    }
}

void nkCryptoToolPQC::decryptFileWithSync(
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::string passphrase
) {
    try {
        // 1. Read Header and Derive Key
        std::ifstream input_file(input_filepath, std::ios::binary);
        if (!input_file) throw std::runtime_error("Failed to open input file for header reading: " + input_filepath);
        
        FileHeader header;
        input_file.read(reinterpret_cast<char*>(&header), sizeof(header));
        if (!input_file || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) {
            throw std::runtime_error("Invalid file header");
        }
        bool is_hybrid = header.reserved == 1;
        if (is_hybrid && !key_paths.count("recipient-ecdh-privkey")) {
            throw std::runtime_error("Hybrid file requires ECDH private key.");
        }

        uint32_t len;
        std::vector<unsigned char> encapsulated_key_mlkem, ephemeral_ecdh_pubkey_bytes, salt, iv;
        input_file.read(reinterpret_cast<char*>(&len), sizeof(len)); encapsulated_key_mlkem.resize(len);
        input_file.read(reinterpret_cast<char*>(encapsulated_key_mlkem.data()), len);
        if (is_hybrid) {
            input_file.read(reinterpret_cast<char*>(&len), sizeof(len)); ephemeral_ecdh_pubkey_bytes.resize(len);
            input_file.read(reinterpret_cast<char*>(ephemeral_ecdh_pubkey_bytes.data()), len);
        }
        input_file.read(reinterpret_cast<char*>(&len), sizeof(len)); salt.resize(len);
        input_file.read(reinterpret_cast<char*>(salt.data()), len);
        input_file.read(reinterpret_cast<char*>(&len), sizeof(len)); iv.resize(len);
        input_file.read(reinterpret_cast<char*>(iv.data()), len);
        uintmax_t header_size = input_file.tellg();

        std::vector<unsigned char> combined_secret;
        const auto& mlkem_priv_key_path = key_paths.at(is_hybrid ? "recipient-mlkem-privkey" : "user-privkey");
        auto recipient_mlkem_private_key_res = loadPrivateKey(mlkem_priv_key_path, passphrase);
        if (!recipient_mlkem_private_key_res) throw std::runtime_error("Failed to load user ML-KEM private key.");
        auto recipient_mlkem_private_key = std::move(*recipient_mlkem_private_key_res);
        
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_private_key.get(), nullptr));
        if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) throw std::runtime_error("EVP_PKEY_decapsulate_init failed.");
        size_t secret_len_mlkem = 0;
        if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) throw std::runtime_error("EVP_PKEY_decapsulate get length failed.");
        std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
        if (EVP_PKEY_decapsulate(kem_ctx.get(), secret_mlkem.data(), &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) throw std::runtime_error("Decapsulation failed.");
        combined_secret = secret_mlkem;
        
        if (is_hybrid) {
            auto recipient_ecdh_private_key_res = loadPrivateKey(key_paths.at("recipient-ecdh-privkey"), passphrase);
            if (!recipient_ecdh_private_key_res) throw std::runtime_error("Failed to load user ECDH private key.");
            auto recipient_ecdh_private_key = std::move(*recipient_ecdh_private_key_res);
            std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(ephemeral_ecdh_pubkey_bytes.data(), ephemeral_ecdh_pubkey_bytes.size()));
            std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
            std::vector<unsigned char> secret_ecdh = ecdh_generate_shared_secret(recipient_ecdh_private_key.get(), ephemeral_pub_key.get());
            combined_secret.insert(combined_secret.end(), secret_ecdh.begin(), secret_ecdh.end());
        }

        std::vector<unsigned char> decryption_key = hkdfDerive(combined_secret, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
        auto ctx = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>(EVP_CIPHER_CTX_new());
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());

        // 2. Set Tag
        input_file.seekg(0, std::ios::end);
        uintmax_t total_input_size = input_file.tellg();
        uintmax_t ciphertext_size = total_input_size - header_size - GCM_TAG_LEN;
        std::vector<unsigned char> tag(GCM_TAG_LEN);
        input_file.seekg(total_input_size - GCM_TAG_LEN);
        input_file.read(reinterpret_cast<char*>(tag.data()), GCM_TAG_LEN);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag.data()) <= 0) {
            throw std::runtime_error("Failed to set GCM tag.");
        }

        // 3. Decryption Loop
        std::ofstream output_file(output_filepath, std::ios::binary | std::ios::trunc);
        input_file.seekg(header_size);
        std::vector<char> in_buffer(CHUNK_SIZE);
        std::vector<unsigned char> out_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH);
        int out_len = 0;
        uintmax_t bytes_to_process = ciphertext_size;
        while (bytes_to_process > 0) {
            std::streamsize to_read = std::min((uintmax_t)in_buffer.size(), bytes_to_process);
            input_file.read(in_buffer.data(), to_read);
            std::streamsize bytes_read = input_file.gcount();
            if (bytes_read == 0) break;
            if (EVP_DecryptUpdate(ctx.get(), out_buffer.data(), &out_len, reinterpret_cast<const unsigned char*>(in_buffer.data()), bytes_read) <= 0) {
                throw std::runtime_error("Decrypt update failed.");
            }
            output_file.write(reinterpret_cast<const char*>(out_buffer.data()), out_len);
            bytes_to_process -= bytes_read;
        }

        // 4. Finalization
        if (EVP_DecryptFinal_ex(ctx.get(), out_buffer.data(), &out_len) <= 0) {
            throw std::runtime_error("GCM tag verification failed.");
        }
        output_file.write(reinterpret_cast<const char*>(out_buffer.data()), out_len);

    } catch (const std::exception& e) {
        std::cerr << "\nSynchronous PQC decryption failed: " << e.what() << std::endl;
        throw;
    }
}
