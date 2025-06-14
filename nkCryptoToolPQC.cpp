// nkCryptoToolPQC.cpp

#include "nkCryptoToolPQC.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/stream_file.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <functional>

struct nkCryptoToolPQC::SigningState : public std::enable_shared_from_this<SigningState> { asio::stream_file input_file; asio::stream_file output_file; std::vector<unsigned char> file_content; std::function<void(std::error_code)> completion_handler; SigningState(asio::io_context& io) : input_file(io), output_file(io) {} };
struct nkCryptoToolPQC::VerificationState : public std::enable_shared_from_this<VerificationState> { asio::stream_file input_file; asio::stream_file signature_file; std::vector<unsigned char> file_content; std::vector<unsigned char> signature; std::function<void(std::error_code, bool)> verification_completion_handler; VerificationState(asio::io_context& io) : input_file(io), signature_file(io) {} };
namespace { std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> generate_ephemeral_ec_key() { std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)); if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return nullptr; OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() }; if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) return nullptr; EVP_PKEY* pkey = nullptr; if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return nullptr; return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey); }
std::vector<unsigned char> ecdh_generate_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) { std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(private_key, nullptr)); if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) return {}; size_t secret_len; if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) return {}; std::vector<unsigned char> secret(secret_len); if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) return {}; secret.resize(secret_len); return secret; } }

nkCryptoToolPQC::nkCryptoToolPQC() {}
nkCryptoToolPQC::~nkCryptoToolPQC() {}

std::filesystem::path nkCryptoToolPQC::getEncryptionPrivateKeyPath() const { return getKeyBaseDirectory() / "private_enc_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getSigningPrivateKeyPath() const { return getKeyBaseDirectory() / "private_sign_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getEncryptionPublicKeyPath() const { return getKeyBaseDirectory() / "public_enc_pqc.key"; }
std::filesystem::path nkCryptoToolPQC::getSigningPublicKeyPath() const { return getKeyBaseDirectory() / "public_sign_pqc.key"; }

bool nkCryptoToolPQC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-1024", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { printOpenSSLErrors(); return false; }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { printOpenSSLErrors(); return false; }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> kem_key(pkey);
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { std::cerr << "Error creating private key file: " << private_key_path << std::endl; return false; }
    bool success = false;
    if (passphrase.empty()) { std::cout << "Saving private key without encryption." << std::endl; success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else { success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0; }
    if (!success) { printOpenSSLErrors(); return false; }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), kem_key.get()) <= 0) { printOpenSSLErrors(); return false; }
    return true;
}

bool nkCryptoToolPQC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { printOpenSSLErrors(); return false; }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { printOpenSSLErrors(); return false; }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> dsa_key(pkey);
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { std::cerr << "Error creating private key file: " << private_key_path << std::endl; return false; }
    bool success = false;
    if (passphrase.empty()) { std::cout << "Saving private key without encryption." << std::endl; success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else { success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), passphrase.length(), nullptr, nullptr) > 0; }
    if (!success) { printOpenSSLErrors(); return false; }
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), dsa_key.get()) <= 0) { printOpenSSLErrors(); return false; }
    return true;
}

void nkCryptoToolPQC::encryptFile(asio::io_context& io, const std::filesystem::path& in, const std::filesystem::path& out, const std::filesystem::path& pub_key, CompressionAlgorithm algo, std::function<void(std::error_code)> handler) {
    encryptFileHybrid(io, in, out, pub_key, "", algo, handler);
}

void nkCryptoToolPQC::decryptFile(asio::io_context& io, const std::filesystem::path& in, const std::filesystem::path& out, const std::filesystem::path& priv_key, const std::filesystem::path&, std::function<void(std::error_code)> handler) {
    decryptFileHybrid(io, in, out, priv_key, "", handler);
}

void nkCryptoToolPQC::encryptFileHybrid( asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_mlkem_public_key_path, const std::filesystem::path& recipient_ecdh_public_key_path, CompressionAlgorithm algo, std::function<void(std::error_code)> completion_handler) {
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) { if (!ec) std::cout << "\nEncryption to '" << output_filepath.string() << "' completed." << std::endl; else std::cerr << "\nEncryption failed: " << ec.message() << std::endl; completion_handler(ec); };
    bool is_hybrid = !recipient_ecdh_public_key_path.empty();
    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler; state->compression_algo = algo;
    std::vector<unsigned char> combined_secret; std::vector<unsigned char> encapsulated_key_mlkem; std::vector<unsigned char> ephemeral_ecdh_pubkey_bytes;
    auto recipient_mlkem_public_key = loadPublicKey(recipient_mlkem_public_key_path);
    if (!recipient_mlkem_public_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_public_key.get(), nullptr));
    if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    size_t secret_len_mlkem = 0, enc_len_mlkem = 0;
    if (EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &enc_len_mlkem, nullptr, &secret_len_mlkem) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
    encapsulated_key_mlkem.resize(enc_len_mlkem);
    if (EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key_mlkem.data(), &enc_len_mlkem, secret_mlkem.data(), &secret_len_mlkem) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    combined_secret = secret_mlkem;
    if (is_hybrid) {
        auto recipient_ecdh_public_key = loadPublicKey(recipient_ecdh_public_key_path);
        if (!recipient_ecdh_public_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
        auto ephemeral_ecdh_key = generate_ephemeral_ec_key();
        if (!ephemeral_ecdh_key) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
        std::vector<unsigned char> secret_ecdh = ecdh_generate_shared_secret(ephemeral_ecdh_key.get(), recipient_ecdh_public_key.get());
        if (secret_ecdh.empty()) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
        std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
        if (!PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_ecdh_key.get())) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
        BUF_MEM *bio_buf; BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
        ephemeral_ecdh_pubkey_bytes.assign(bio_buf->data, bio_buf->data + bio_buf->length);
        combined_secret.insert(combined_secret.end(), secret_ecdh.begin(), secret_ecdh.end());
    }
    std::vector<unsigned char> salt(16), iv(GCM_IV_LEN); RAND_bytes(salt.data(), salt.size()); RAND_bytes(iv.data(), iv.size());
    std::vector<unsigned char> encryption_key = hkdfDerive(combined_secret, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
    if (encryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));
    std::error_code ec;
    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec); if(ec) return wrapped_handler(ec);
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec); if(ec) return wrapped_handler(ec);
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec); if(ec) return wrapped_handler(ec);
    FileHeader header; memcpy(header.magic, MAGIC, sizeof(MAGIC)); header.version = 1; header.compression_algo = algo; header.reserved = is_hybrid ? 1 : 0;
    asio::write(state->output_file, asio::buffer(&header, sizeof(header)), ec); if(ec) return wrapped_handler(ec);
    uint32_t len;
    len = encapsulated_key_mlkem.size(); asio::write(state->output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(encapsulated_key_mlkem), ec); if(ec) return wrapped_handler(ec);
    if (is_hybrid) {
        len = ephemeral_ecdh_pubkey_bytes.size(); asio::write(state->output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec);
        asio::write(state->output_file, asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) return wrapped_handler(ec);
    }
    len = salt.size(); asio::write(state->output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(salt), ec); if(ec) return wrapped_handler(ec);
    len = iv.size(); asio::write(state->output_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(iv), ec); if(ec) return wrapped_handler(ec);
    if (state->compression_algo == CompressionAlgorithm::LZ4) state->compression_stream = LZ4_createStream();
    EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());
    startEncryptionPipeline(state, total_input_size);
}

void nkCryptoToolPQC::decryptFileHybrid( asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath, const std::filesystem::path& recipient_mlkem_private_key_path, const std::filesystem::path& recipient_ecdh_private_key_path, std::function<void(std::error_code)> completion_handler) {
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) { if (!ec) std::cout << "\nDecryption to '" << output_filepath.string() << "' completed." << std::endl; else std::cerr << "\nDecryption failed: " << ec.message() << std::endl; completion_handler(ec); };
    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler;
    std::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec); if(ec) return wrapped_handler(ec);
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec); if(ec) return wrapped_handler(ec);
    FileHeader header; asio::read(state->input_file, asio::buffer(&header, sizeof(header)), ec);
    if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    state->compression_algo = header.compression_algo;
    bool is_hybrid = header.reserved == 1;
    if (is_hybrid && recipient_ecdh_private_key_path.empty()) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    uint32_t len;
    std::vector<unsigned char> encapsulated_key_mlkem, ephemeral_ecdh_pubkey_bytes, salt, iv;
    asio::read(state->input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec); encapsulated_key_mlkem.resize(len);
    asio::read(state->input_file, asio::buffer(encapsulated_key_mlkem), ec); if(ec) return wrapped_handler(ec);
    if(is_hybrid) {
        asio::read(state->input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec); ephemeral_ecdh_pubkey_bytes.resize(len);
        asio::read(state->input_file, asio::buffer(ephemeral_ecdh_pubkey_bytes), ec); if(ec) return wrapped_handler(ec);
    }
    asio::read(state->input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec); salt.resize(len);
    asio::read(state->input_file, asio::buffer(salt), ec); if(ec) return wrapped_handler(ec);
    asio::read(state->input_file, asio::buffer(&len, sizeof(len)), ec); if(ec) return wrapped_handler(ec); iv.resize(len);
    asio::read(state->input_file, asio::buffer(iv), ec); if(ec) return wrapped_handler(ec);
    std::vector<unsigned char> combined_secret;
    auto recipient_mlkem_private_key = loadPrivateKey(recipient_mlkem_private_key_path, "ML-KEM private key");
    if (!recipient_mlkem_private_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_private_key.get(), nullptr));
    if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    size_t secret_len_mlkem = 0;
    if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::operation_not_permitted)); }
    std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
    if (EVP_PKEY_decapsulate(kem_ctx.get(), secret_mlkem.data(), &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::operation_not_permitted)); }
    combined_secret = secret_mlkem;
    if(is_hybrid) {
        auto recipient_ecdh_private_key = loadPrivateKey(recipient_ecdh_private_key_path, "ECDH private key");
        if (!recipient_ecdh_private_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
        std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(ephemeral_ecdh_pubkey_bytes.data(), ephemeral_ecdh_pubkey_bytes.size()));
        std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
        if(!ephemeral_pub_key) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
        std::vector<unsigned char> secret_ecdh = ecdh_generate_shared_secret(recipient_ecdh_private_key.get(), ephemeral_pub_key.get());
        if (secret_ecdh.empty()) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
        combined_secret.insert(combined_secret.end(), secret_ecdh.begin(), secret_ecdh.end());
    }
    std::vector<unsigned char> decryption_key = hkdfDerive(combined_secret, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
    if (decryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));
    if (state->compression_algo == CompressionAlgorithm::LZ4) state->decompression_stream = LZ4_createStreamDecode();
    else if (state->compression_algo != CompressionAlgorithm::NONE) return wrapped_handler(std::make_error_code(std::errc::not_supported));
    EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());
    uintmax_t total_file_size = std::filesystem::file_size(input_filepath, ec);
    size_t header_total_size = sizeof(FileHeader) + sizeof(uint32_t) + encapsulated_key_mlkem.size() + sizeof(uint32_t) + salt.size() + sizeof(uint32_t) + iv.size();
    if(is_hybrid) header_total_size += sizeof(uint32_t) + ephemeral_ecdh_pubkey_bytes.size();
    uintmax_t ciphertext_size = total_file_size - header_total_size - GCM_TAG_LEN;
    startDecryptionPipeline(state, ciphertext_size);
}

void nkCryptoToolPQC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string&, std::function<void(std::error_code)> completion_handler){
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = [completion_handler](const std::error_code& ec) { if (!ec) std::cout << "\nFile signed successfully." << std::endl; completion_handler(ec); };
    auto private_key = loadPrivateKey(signing_private_key_path, "PQC signing private key");
    if (!private_key) return completion_handler(std::make_error_code(std::errc::invalid_argument));
    std::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec); if (ec) return completion_handler(ec);
    state->output_file.open(signature_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec); if (ec) return completion_handler(ec);
    state->file_content.resize(std::filesystem::file_size(input_filepath, ec)); if (ec) return completion_handler(ec);
    asio::async_read(state->input_file, asio::buffer(state->file_content), [this, state, pkey = std::move(private_key)](const asio::error_code& read_ec, size_t) mutable {
        if (read_ec) return state->completion_handler(read_ec);
        std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx(EVP_MD_CTX_new());
        size_t sig_len;
        if (EVP_DigestSignInit(mdctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) { printOpenSSLErrors(); return state->completion_handler(std::make_error_code(std::errc::io_error)); }
        if (EVP_DigestSign(mdctx.get(), nullptr, &sig_len, state->file_content.data(), state->file_content.size()) <= 0) { printOpenSSLErrors(); return state->completion_handler(std::make_error_code(std::errc::io_error)); }
        std::vector<unsigned char> signature(sig_len);
        if (EVP_DigestSign(mdctx.get(), signature.data(), &sig_len, state->file_content.data(), state->file_content.size()) <= 0) { printOpenSSLErrors(); return state->completion_handler(std::make_error_code(std::errc::io_error)); }
        signature.resize(sig_len);
        asio::async_write(state->output_file, asio::buffer(signature), [state](const asio::error_code& write_ec, size_t) { state->completion_handler(write_ec); });
    });
}

void nkCryptoToolPQC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path, std::function<void(std::error_code, bool)> completion_handler){
    auto state = std::make_shared<VerificationState>(io_context);
    state->verification_completion_handler = completion_handler;
    auto public_key = loadPublicKey(signing_public_key_path);
    if (!public_key) return completion_handler(std::make_error_code(std::errc::invalid_argument), false);
    std::error_code ec;
    state->signature_file.open(signature_filepath.string(), asio::stream_file::read_only, ec); if (ec) return completion_handler(ec, false);
    state->signature.resize(std::filesystem::file_size(signature_filepath, ec)); if (ec) return completion_handler(ec, false);
    asio::async_read(state->signature_file, asio::buffer(state->signature), [this, state, input_filepath, pkey = std::move(public_key)](const asio::error_code& read_sig_ec, size_t) mutable {
        if (read_sig_ec) { state->verification_completion_handler(read_sig_ec, false); return; }
        std::error_code read_input_ec;
        state->input_file.open(input_filepath.string(), asio::stream_file::read_only, read_input_ec); if(read_input_ec) { state->verification_completion_handler(read_input_ec, false); return; }
        state->file_content.resize(std::filesystem::file_size(input_filepath, read_input_ec)); if(read_input_ec) { state->verification_completion_handler(read_input_ec, false); return; }
        asio::async_read(state->input_file, asio::buffer(state->file_content), [this, state, pub_key = std::move(pkey)](const asio::error_code& final_read_ec, size_t) mutable {
            if (final_read_ec && final_read_ec != asio::error::eof) { state->verification_completion_handler(final_read_ec, false); return; }
            std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx(EVP_MD_CTX_new());
            if (EVP_DigestVerifyInit(mdctx.get(), nullptr, nullptr, nullptr, pub_key.get()) <= 0) { printOpenSSLErrors(); state->verification_completion_handler(std::make_error_code(std::errc::io_error), false); return; }
            int result = EVP_DigestVerify(mdctx.get(), state->signature.data(), state->signature.size(), state->file_content.data(), state->file_content.size());
            state->verification_completion_handler({}, (result == 1));
        });
    });
}

asio::awaitable<void> nkCryptoToolPQC::encryptFileParallel(
    asio::io_context&,
    std::string,
    std::string,
    std::string,
    CompressionAlgorithm
) {
    std::cerr << "PQC parallel encryption is not yet implemented." << std::endl;
    co_return;
}

asio::awaitable<void> nkCryptoToolPQC::decryptFileParallel(
    asio::io_context&,
    std::string,
    std::string,
    std::string
) {
    std::cerr << "PQC parallel decryption is not yet implemented." << std::endl;
    co_return;
}
