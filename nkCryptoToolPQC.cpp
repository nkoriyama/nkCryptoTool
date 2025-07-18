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
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>



namespace {
// ハイブリッド暗号用のヘルパー関数 (ECDH鍵生成・共有秘密導出)
std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> generate_ephemeral_ec_key() { 
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)); 
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) throw std::runtime_error("OpenSSL Error: Failed to initialize ephemeral EC key generation context."); 
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() }; 
    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) throw std::runtime_error("OpenSSL Error: Failed to set ephemeral EC group parameters."); 
    EVP_PKEY* pkey = nullptr; 
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) throw std::runtime_error("OpenSSL Error: Failed to generate ephemeral EC key pair."); 
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey); 
}
std::vector<unsigned char> ecdh_generate_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) { 
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(private_key, nullptr)); 
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) throw std::runtime_error("OpenSSL Error: Failed to initialize ECDH shared secret derivation."); 
    size_t secret_len; 
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) throw std::runtime_error("OpenSSL Error: Failed to get ECDH shared secret length."); 
    std::vector<unsigned char> secret(secret_len); 
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) throw std::runtime_error("OpenSSL Error: Failed to derive ECDH shared secret."); 
    secret.resize(secret_len); 
    return secret; 
}

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

} // anonymous namespace

nkCryptoToolPQC::nkCryptoToolPQC() {}
nkCryptoToolPQC::~nkCryptoToolPQC() {}

// --- 鍵パス取得 ---
std::filesystem::path nkCryptoToolPQC::getEncryptionPrivateKeyPath() const { return getKeyBaseDirectory() / "private_enc_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getSigningPrivateKeyPath() const { return getKeyBaseDirectory() / "private_sign_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getEncryptionPublicKeyPath() const { return getKeyBaseDirectory() / "public_enc_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getSigningPublicKeyPath() const { return getKeyBaseDirectory() / "public_sign_pqc.key"; }

// --- 鍵ペア生成 ---
bool nkCryptoToolPQC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to initialize ML-KEM key generation context."); }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to generate ML-KEM key pair."); }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> kem_key(pkey);
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { throw std::runtime_error("Error creating private key file: " + private_key_path.string()); }
    bool success = false;
    if (passphrase.empty()) { std::cout << "Saving private key without encryption." << std::endl; success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else { success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0; }
    if (!success) { throw std::runtime_error("OpenSSL Error: Failed to write ML-KEM private key to file."); }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), kem_key.get()) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to write ML-KEM public key to file."); }
    return true;
}

bool nkCryptoToolPQC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to initialize ML-DSA key generation context."); }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to generate ML-DSA key pair."); }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> dsa_key(pkey);
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { throw std::runtime_error("Error creating private key file: " + private_key_path.string()); }
    bool success = false;
    if (passphrase.empty()) { std::cout << "Saving private key without encryption." << std::endl; success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else { success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0; }
    if (!success) { throw std::runtime_error("OpenSSL Error: Failed to write ML-DSA private key to file."); }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), dsa_key.get()) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to write ML-DSA public key to file."); }
    return true;
}



// --- PQC署名・検証 ---
void nkCryptoToolPQC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string&, std::function<void(std::error_code)> completion_handler){
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = [completion_handler](const std::error_code& ec) { 
        if (!ec) std::cout << "\nFile signed successfully." << std::endl; 
        completion_handler(ec); 
    };
    auto private_key = loadPrivateKey(signing_private_key_path, "PQC signing private key");
    if (!private_key) return completion_handler(std::make_error_code(std::errc::invalid_argument));

    if (EVP_DigestSignInit(state->md_ctx.get(), nullptr, nullptr, nullptr, private_key.get()) <= 0) { 
        throw std::runtime_error("OpenSSL Error: Failed to initialize digest signing."); 
    }

    std::error_code ec;
    state->total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) return completion_handler(ec);

#ifdef _WIN32
    state->input_file.open(input_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
    if (fd_in == -1) { ec.assign(errno, std::system_category()); } else { state->input_file.assign(fd_in, ec); }
#endif
    if (ec) return completion_handler(ec);
    
#ifdef _WIN32
    state->output_file.open(signature_filepath.string(), async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
    int fd_out = ::open(signature_filepath.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { state->output_file.assign(fd_out, ec); }
#endif
    if (ec) return completion_handler(ec);

    state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolPQC::handleFileReadForSigning, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolPQC::handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred){
    if (ec == asio::error::eof) { finishSigning(state); return; }
    if (ec) { state->completion_handler(ec); return; }
    EVP_DigestSignUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolPQC::handleFileReadForSigning, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolPQC::finishSigning(std::shared_ptr<SigningState> state){
    size_t sig_len = 0;
    EVP_DigestSignFinal(state->md_ctx.get(), nullptr, &sig_len);
    std::vector<unsigned char> signature(sig_len);
    EVP_DigestSignFinal(state->md_ctx.get(), signature.data(), &sig_len);
    signature.resize(sig_len);
    asio::async_write(state->output_file, asio::buffer(signature), [this, state](const asio::error_code& write_ec, size_t) {
        state->completion_handler(write_ec);
    });
}

void nkCryptoToolPQC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path, std::function<void(std::error_code, bool)> completion_handler){
    auto state = std::make_shared<VerificationState>(io_context);
    state->verification_completion_handler = completion_handler;
    auto public_key = loadPublicKey(signing_public_key_path);
    if (!public_key) return completion_handler(std::make_error_code(std::errc::invalid_argument), false);

    if (EVP_DigestVerifyInit(state->md_ctx.get(), nullptr, nullptr, nullptr, public_key.get()) <= 0) { 
        throw std::runtime_error("OpenSSL Error: Failed to initialize digest verification."); 
    }

    std::error_code ec;
#ifdef _WIN32
    state->signature_file.open(signature_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_sig = ::open(signature_filepath.string().c_str(), O_RDONLY);
    if (fd_sig == -1) { ec.assign(errno, std::system_category()); } else { state->signature_file.assign(fd_sig, ec); }
#endif
    if (ec) { completion_handler(ec, false); return; }

    state->signature.resize(std::filesystem::file_size(signature_filepath, ec));
    if (ec) { completion_handler(ec, false); return; }

    asio::async_read(state->signature_file, asio::buffer(state->signature), [this, state, input_filepath](const asio::error_code& read_sig_ec, size_t) mutable {
        if (read_sig_ec) { state->verification_completion_handler(read_sig_ec, false); return; }
        std::error_code open_ec;
        state->total_input_size = std::filesystem::file_size(input_filepath, open_ec);
        if(open_ec) { state->verification_completion_handler(open_ec, false); return; }

#ifdef _WIN32
        state->input_file.open(input_filepath.string(), async_file_t::read_only, open_ec);
#else
        int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
        if (fd_in == -1) { open_ec.assign(errno, std::system_category()); } else { state->input_file.assign(fd_in, open_ec); }
#endif
        if(open_ec) { state->verification_completion_handler(open_ec, false); return; }

        state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolPQC::handleFileReadForVerification, this, state, std::placeholders::_1, std::placeholders::_2));
    });
}

void nkCryptoToolPQC::handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred){
    if (ec == asio::error::eof) { finishVerification(state); return; }
    if (ec) { state->verification_completion_handler(ec, false); return; }
    EVP_DigestVerifyUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolPQC::handleFileReadForVerification, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolPQC::finishVerification(std::shared_ptr<VerificationState> state){
    int result = EVP_DigestVerifyFinal(state->md_ctx.get(), state->signature.data(), state->signature.size());
    state->verification_completion_handler({}, (result == 1));
}



// --- パイプライン処理の実装 ---
void nkCryptoToolPQC::encryptFileWithPipeline(
    asio::io_context& io_context,
    const std::string& input_filepath,
    const std::string& output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler
) {
    try {
        bool is_hybrid = key_paths.count("recipient-ecdh-pubkey");
        
        auto manager = std::make_shared<PipelineManager>(io_context);
        auto wrapped_handler = [output_filepath, completion_handler, manager](const std::error_code& ec) {
            if (!ec) std::cout << "\nPipeline encryption to '" << output_filepath << "' completed." << std::endl;
            else std::cerr << "\nPipeline encryption failed: " << ec.message() << std::endl;
            completion_handler(ec);
        };

        // --- 鍵導出 ---
        std::vector<unsigned char> combined_secret; 
        std::vector<unsigned char> encapsulated_key_mlkem; 
        std::vector<unsigned char> ephemeral_ecdh_pubkey_bytes;
        
        const auto& mlkem_pub_key_path = key_paths.at(is_hybrid ? "recipient-mlkem-pubkey" : "recipient-pubkey");
        auto recipient_mlkem_public_key = loadPublicKey(mlkem_pub_key_path);
        if (!recipient_mlkem_public_key) throw std::runtime_error("Failed to load recipient ML-KEM public key.");

        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_public_key.get(), nullptr));
        if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_encapsulate_init failed."); }
        size_t secret_len_mlkem = 0, enc_len_mlkem = 0;
                        if (EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &enc_len_mlkem, nullptr, &secret_len_mlkem) <= 0) { ERR_clear_error(); throw std::runtime_error("OpenSSL Error: EVP_PKEY_encapsulate get length failed."); }
        std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
        encapsulated_key_mlkem.resize(enc_len_mlkem);
        if (EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key_mlkem.data(), &enc_len_mlkem, secret_mlkem.data(), &secret_len_mlkem) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_encapsulate failed."); }
        combined_secret = secret_mlkem;

        if (is_hybrid) {
            auto recipient_ecdh_public_key = loadPublicKey(key_paths.at("recipient-ecdh-pubkey"));
            if (!recipient_ecdh_public_key) throw std::runtime_error("Failed to load recipient ECDH public key.");
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
#ifdef _WIN32
        output_file.open(output_filepath, async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
        int fd_out = ::open(output_filepath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { output_file.assign(fd_out, ec); }
#endif
        if (ec) throw std::system_error(ec, "Failed to open output file for header writing");

        FileHeader header; 
        memcpy(header.magic, MAGIC, sizeof(MAGIC)); 
        header.version = 1; 
        header.reserved = is_hybrid ? 1 : 0;
        asio::write(output_file, asio::buffer(&header, sizeof(header)), ec); if(ec) throw std::system_error(ec);
        
        uint32_t len;
        len = encapsulated_key_mlkem.size(); asio::write(output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec);
        asio::write(output_file, asio::buffer(encapsulated_key_mlkem), ec); if(ec) throw std::system_error(ec);
        if (is_hybrid) {
            len = ephemeral_ecdh_pubkey_bytes.size(); asio::write(output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec);
            asio::write(output_file, asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) throw std::system_error(ec);
        }
        len = salt.size(); asio::write(output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec);
        asio::write(output_file, asio::buffer(salt), ec); if(ec) throw std::system_error(ec);
        len = iv.size(); asio::write(output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) throw std::system_error(ec);
        asio::write(output_file, asio::buffer(iv), ec); if(ec) throw std::system_error(ec);

        // --- パイプライン実行 ---
        manager->add_stage([template_ctx](const std::vector<char>& data) {
            return pqc_process_chunk(data, template_ctx.get(), true);
        });

        PipelineManager::FinalizationFunc finalizer = [this, template_ctx](async_file_t out_final) -> asio::awaitable<void> {
            auto final_block = std::make_shared<std::vector<unsigned char>>(EVP_MAX_BLOCK_LENGTH);
            auto tag = std::make_shared<std::vector<unsigned char>>(GCM_TAG_LEN);
            int final_len = 0;
            if (EVP_EncryptFinal_ex(template_ctx.get(), final_block->data(), &final_len) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to finalize encryption."); }
            final_block->resize(final_len);
            if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag->data()) <= 0) { throw std::runtime_error("OpenSSL Error: Failed to get GCM tag."); }
            if (!final_block->empty()) { co_await asio::async_write(out_final, asio::buffer(*final_block), asio::use_awaitable); }
            co_await asio::async_write(out_final, asio::buffer(*tag), asio::use_awaitable);

        };
        
        uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) throw std::system_error(ec);
        manager->run(input_filepath, std::move(output_file), 0, total_input_size, wrapped_handler, std::move(finalizer));

    } catch (const std::exception& e) {
        std::cerr << "\nPipeline encryption setup failed: " << e.what() << std::endl;
        completion_handler(std::make_error_code(std::errc::io_error));
    }
}

void nkCryptoToolPQC::decryptFileWithPipeline(
    asio::io_context& io_context,
    const std::string& input_filepath,
    const std::string& output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler
) {
    try {
        auto manager = std::make_shared<PipelineManager>(io_context);
        auto wrapped_handler = [output_filepath, completion_handler, manager](const std::error_code& ec) {
            if (!ec) std::cout << "\nPipeline decryption to '" << output_filepath << "' completed." << std::endl;
            else std::cerr << "\nPipeline decryption failed: " << ec.message() << std::endl;
            completion_handler(ec);
        };

        // --- ファイルヘッダー読み込みと鍵導出 ---
        std::error_code ec;
        async_file_t input_file(io_context);
#ifdef _WIN32
        input_file.open(input_filepath, async_file_t::read_only, ec);
#else
        int fd_in = ::open(input_filepath.c_str(), O_RDONLY);
        if (fd_in == -1) { ec.assign(errno, std::system_category()); } else { input_file.assign(fd_in, ec); }
#endif
        if (ec) throw std::system_error(ec, "Failed to open input file for header reading");
        
        FileHeader header; asio::read(input_file, asio::buffer(&header, sizeof(header)), ec); 
        if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) { input_file.close(); throw std::runtime_error("Invalid file header"); }
        bool is_hybrid = header.reserved == 1;
        if (is_hybrid && !key_paths.count("recipient-ecdh-privkey")) { input_file.close(); throw std::runtime_error("Hybrid file requires ECDH private key."); }

        uint32_t len;
        std::vector<unsigned char> encapsulated_key_mlkem, ephemeral_ecdh_pubkey_bytes, salt, iv;
        asio::read(input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read ml-kem key length");} encapsulated_key_mlkem.resize(len);
        asio::read(input_file, asio::buffer(encapsulated_key_mlkem), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read ml-kem key");}
        if(is_hybrid) {
            asio::read(input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read ecdh key length");} ephemeral_ecdh_pubkey_bytes.resize(len);
            asio::read(input_file, asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read ecdh key");}
        }
        asio::read(input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read salt length");} salt.resize(len);
        asio::read(input_file, asio::buffer(salt), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read salt");}
        asio::read(input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read iv length");} iv.resize(len);
        asio::read(input_file, asio::buffer(iv), ec); if(ec) {input_file.close(); throw std::runtime_error("Failed to read iv");}
        
        uintmax_t header_size = 0;
#ifdef _WIN32
        header_size = input_file.seek(0, asio::file_base::seek_cur, ec);
#else
        off_t pos = ::lseek(input_file.native_handle(), 0, SEEK_CUR);
        if (pos == (off_t)-1) {
            ec.assign(errno, std::system_category());
        } else {
            header_size = pos;
        }
#endif
        if(ec) {input_file.close(); throw std::system_error(ec);}
        input_file.close(ec);

        std::vector<unsigned char> combined_secret;
        const auto& mlkem_priv_key_path = key_paths.at(is_hybrid ? "recipient-mlkem-privkey" : "user-privkey");
        auto recipient_mlkem_private_key = loadPrivateKey(mlkem_priv_key_path, "ML-KEM private key");
        if (!recipient_mlkem_private_key) throw std::runtime_error("Failed to load user ML-KEM private key.");
        std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_private_key.get(), nullptr));
        if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_decapsulate_init failed."); }
        size_t secret_len_mlkem = 0;
        if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { throw std::runtime_error("OpenSSL Error: EVP_PKEY_decapsulate get length failed."); }
        std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
        if (EVP_PKEY_decapsulate(kem_ctx.get(), secret_mlkem.data(), &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { throw std::runtime_error("OpenSSL Error: Decapsulation failed. The private key may be incorrect or the data corrupted."); }
        combined_secret = secret_mlkem;
        
        if(is_hybrid) {
            auto recipient_ecdh_private_key = loadPrivateKey(key_paths.at("recipient-ecdh-privkey"), "ECDH private key");
            if (!recipient_ecdh_private_key) throw std::runtime_error("Failed to load user ECDH private key.");
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
#ifdef _WIN32
        output_file.open(output_filepath, async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
        int fd_out = ::open(output_filepath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { output_file.assign(fd_out, ec); }
#endif
        if (ec) throw std::system_error(ec, "Failed to create output file");

        manager->add_stage([template_ctx](const std::vector<char>& data) {
            return pqc_process_chunk(data, template_ctx.get(), false);
        });

        PipelineManager::FinalizationFunc finalizer = [this, template_ctx, &io_context, input_filepath](async_file_t out_final) -> asio::awaitable<void> {
            auto tag = std::make_shared<std::vector<unsigned char>>(GCM_TAG_LEN);
            auto final_block = std::make_shared<std::vector<unsigned char>>(EVP_MAX_BLOCK_LENGTH);
            int final_len = 0;
            
            async_file_t in_final(io_context);
            std::error_code final_ec;
#ifdef _WIN32
            in_final.open(input_filepath, async_file_t::read_only, final_ec);
#else
            int fd_in = ::open(input_filepath.c_str(), O_RDONLY);
            if (fd_in == -1) { final_ec.assign(errno, std::system_category()); } else { in_final.assign(fd_in, final_ec); }
#endif
            if(final_ec) throw std::system_error(final_ec, "Failed to open input for finalization");

            uintmax_t file_size = 0;
#ifdef _WIN32
            file_size = in_final.size(final_ec);
            if (!final_ec) {
                in_final.seek(file_size - GCM_TAG_LEN, asio::file_base::seek_set, final_ec);
            }
#else
            struct stat stat_buf;
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
            if(final_ec) {in_final.close(); throw std::system_error(final_ec, "Failed to seek for finalization");}
            
            co_await asio::async_read(in_final, asio::buffer(*tag), asio::use_awaitable);

            if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag->data()) <= 0) { throw std::runtime_error("Failed to set GCM tag."); }
            if (EVP_DecryptFinal_ex(template_ctx.get(), final_block->data(), &final_len) <= 0) { throw std::runtime_error("OpenSSL Error: GCM tag verification failed. File may be corrupted or tampered with."); }
            final_block->resize(final_len);
            
            if (!final_block->empty()) { co_await asio::async_write(out_final, asio::buffer(*final_block), asio::use_awaitable); }
        };

        uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) throw std::system_error(ec);
        uintmax_t ciphertext_size = total_input_size - header_size - GCM_TAG_LEN;
        
        manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, wrapped_handler, std::move(finalizer));

    } catch (const std::exception& e) {
        std::cerr << "\nPipeline decryption setup failed: " << e.what() << std::endl;
        completion_handler(std::make_error_code(std::errc::io_error));
    }
}