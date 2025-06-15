// nkCryptoToolPQC.cpp

#include "nkCryptoToolPQC.hpp"
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
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>

// PQC署名/検証用の状態管理構造体
struct nkCryptoToolPQC::SigningState : public std::enable_shared_from_this<SigningState> {
    async_file_t input_file;
    async_file_t output_file;
    std::vector<unsigned char> file_content;
    std::function<void(std::error_code)> completion_handler;
    SigningState(asio::io_context& io) : input_file(io), output_file(io) {}
};

struct nkCryptoToolPQC::VerificationState : public std::enable_shared_from_this<VerificationState> {
    async_file_t input_file;
    async_file_t signature_file;
    std::vector<unsigned char> file_content;
    std::vector<unsigned char> signature;
    std::function<void(std::error_code, bool)> verification_completion_handler;
    VerificationState(asio::io_context& io) : input_file(io), signature_file(io) {}
};

namespace {
// ハイブリッド暗号化用のヘルパー関数 (ECDH鍵生成・共有秘密導出)
std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> generate_ephemeral_ec_key() { std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)); if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return nullptr; OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() }; if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) return nullptr; EVP_PKEY* pkey = nullptr; if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return nullptr; return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey); }
std::vector<unsigned char> ecdh_generate_shared_secret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) { std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(private_key, nullptr)); if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) return {}; size_t secret_len; if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) return {}; std::vector<unsigned char> secret(secret_len); if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) return {}; secret.resize(secret_len); return secret; }

// --- 並列処理用チャンク処理ヘルパー ---
static std::vector<unsigned char> pqc_encrypt_chunk_logic(
    const std::vector<unsigned char>& plain_data,
    EVP_CIPHER_CTX* template_cipher_ctx
) {
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || !EVP_CIPHER_CTX_copy(ctx.get(), template_cipher_ctx)) return {};
    std::vector<unsigned char> encrypted_data(plain_data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx.get(), encrypted_data.data(), &outlen, plain_data.data(), plain_data.size()) <= 0) return {};
    encrypted_data.resize(outlen);
    return encrypted_data;
}

static std::vector<unsigned char> pqc_decrypt_chunk_logic(
    const std::vector<unsigned char>& encrypted_data,
    EVP_CIPHER_CTX* template_cipher_ctx
) {
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (!ctx || !EVP_CIPHER_CTX_copy(ctx.get(), template_cipher_ctx)) return {};
    std::vector<unsigned char> decrypted_data(encrypted_data.size() + EVP_MAX_BLOCK_LENGTH);
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx.get(), decrypted_data.data(), &outlen, encrypted_data.data(), encrypted_data.size()) <= 0) {
        return {};
    }
    decrypted_data.resize(outlen);
    return decrypted_data;
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

// --- 通常の暗号化・復号（ハイブリッド実装へのラッパー） ---
void nkCryptoToolPQC::encryptFile(asio::io_context& io, const std::filesystem::path& in, const std::filesystem::path& out, const std::filesystem::path& pub_key, CompressionAlgorithm algo, std::function<void(std::error_code)> handler) {
    encryptFileHybrid(io, in, out, pub_key, "", algo, handler);
}

void nkCryptoToolPQC::decryptFile(asio::io_context& io, const std::filesystem::path& in, const std::filesystem::path& out, const std::filesystem::path& priv_key, const std::filesystem::path&, std::function<void(std::error_code)> handler) {
    decryptFileHybrid(io, in, out, priv_key, "", handler);
}

// --- ハイブリッド暗号化・復号 ---
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

#ifdef _WIN32
    state->input_file.open(input_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
    if (fd_in == -1) { ec.assign(errno, std::system_category()); } else { state->input_file.assign(fd_in, ec); }
#endif
    if(ec) return wrapped_handler(ec);

#ifdef _WIN32
    state->output_file.open(output_filepath.string(), async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
    int fd_out = ::open(output_filepath.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { state->output_file.assign(fd_out, ec); }
#endif
    if(ec) return wrapped_handler(ec);

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
#ifdef _WIN32
    state->input_file.open(input_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
    if (fd_in == -1) { ec.assign(errno, std::system_category()); } else { state->input_file.assign(fd_in, ec); }
#endif
    if(ec) return wrapped_handler(ec);

#ifdef _WIN32
    state->output_file.open(output_filepath.string(), async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
    int fd_out = ::open(output_filepath.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { state->output_file.assign(fd_out, ec); }
#endif
    if(ec) return wrapped_handler(ec);

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

// --- PQC署名・検証 ---
void nkCryptoToolPQC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string&, std::function<void(std::error_code)> completion_handler){
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = [completion_handler](const std::error_code& ec) { if (!ec) std::cout << "\nFile signed successfully." << std::endl; completion_handler(ec); };
    auto private_key = loadPrivateKey(signing_private_key_path, "PQC signing private key");
    if (!private_key) return completion_handler(std::make_error_code(std::errc::invalid_argument));
    std::error_code ec;

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

#ifdef _WIN32
    state->signature_file.open(signature_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_sig = ::open(signature_filepath.string().c_str(), O_RDONLY);
    if (fd_sig == -1) { ec.assign(errno, std::system_category()); } else { state->signature_file.assign(fd_sig, ec); }
#endif
    if (ec) return completion_handler(ec, false);

    state->signature.resize(std::filesystem::file_size(signature_filepath, ec)); if (ec) return completion_handler(ec, false);
    asio::async_read(state->signature_file, asio::buffer(state->signature), [this, state, input_filepath, pkey = std::move(public_key)](const asio::error_code& read_sig_ec, size_t) mutable {
        if (read_sig_ec) { state->verification_completion_handler(read_sig_ec, false); return; }
        std::error_code read_input_ec;
        
#ifdef _WIN32
        state->input_file.open(input_filepath.string(), async_file_t::read_only, read_input_ec);
#else
        int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
        if (fd_in == -1) { read_input_ec.assign(errno, std::system_category()); } else { state->input_file.assign(fd_in, read_input_ec); }
#endif
        if(read_input_ec) { state->verification_completion_handler(read_input_ec, false); return; }
        
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

//================================================================================
// 並列暗号化・復号の実装 (PQC-only)
//================================================================================

asio::awaitable<void> nkCryptoToolPQC::encryptFileParallel(
    asio::io_context& worker_context,
    std::string input_filepath_str,
    std::string output_filepath_str,
    std::string recipient_public_key_path_str,
    CompressionAlgorithm algo
) {
    if (algo != CompressionAlgorithm::NONE) {
        throw std::runtime_error("Compression is not supported in parallel mode.");
    }

    const std::filesystem::path input_filepath(input_filepath_str);
    const std::filesystem::path output_filepath(output_filepath_str);
    const std::filesystem::path recipient_mlkem_public_key_path(recipient_public_key_path_str);

    auto executor = co_await asio::this_coro::executor;
    auto writer_strand = asio::make_strand(executor);

    async_file_t input_file(executor);
    async_file_t output_file(executor);
    std::error_code ec;
#ifdef _WIN32
    input_file.open(input_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
    if (fd_in == -1) { ec.assign(errno, std::system_category()); } else { input_file.assign(fd_in, ec); }
#endif
    if(ec) { throw std::system_error(ec, "Failed to open input file"); }

#ifdef _WIN32
    output_file.open(output_filepath.string(), async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
    int fd_out = ::open(output_filepath.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { output_file.assign(fd_out, ec); }
#endif
    if(ec) { throw std::system_error(ec, "Failed to open output file"); }

    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) { throw std::system_error(ec, "Failed to get file size"); }

    // --- PQC 暗号化セットアップ ---
    auto recipient_mlkem_public_key = loadPublicKey(recipient_mlkem_public_key_path);
    if (!recipient_mlkem_public_key) { throw std::runtime_error("Failed to load recipient ML-KEM public key."); }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_public_key.get(), nullptr));
    if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to init PQC encapsulation."); }
    
    size_t secret_len_mlkem = 0, enc_len_mlkem = 0;
    if (EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &enc_len_mlkem, nullptr, &secret_len_mlkem) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to get PQC encapsulation lengths."); }
    
    std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
    std::vector<unsigned char> encapsulated_key_mlkem(enc_len_mlkem);
    if (EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key_mlkem.data(), &enc_len_mlkem, secret_mlkem.data(), &secret_len_mlkem) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to perform PQC encapsulation."); }
    
    std::vector<unsigned char> salt(16), iv(GCM_IV_LEN); 
    RAND_bytes(salt.data(), salt.size()); 
    RAND_bytes(iv.data(), iv.size());
    std::vector<unsigned char> encryption_key = hkdfDerive(secret_mlkem, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
    if (encryption_key.empty()) { throw std::runtime_error("Failed to derive encryption key."); }
    
    std::shared_ptr<EVP_CIPHER_CTX> template_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
    EVP_EncryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());

    // --- ヘッダーとメタデータの書き込み ---
    FileHeader header; 
    memcpy(header.magic, MAGIC, sizeof(MAGIC)); 
    header.version = 1; 
    header.compression_algo = algo; 
    header.reserved = 0; // PQC-only
    co_await asio::async_write(output_file, asio::buffer(&header, sizeof(header)), asio::use_awaitable);

    uint32_t len;
    len = encapsulated_key_mlkem.size(); 
    co_await asio::async_write(output_file, asio::buffer(&len, sizeof(len)), asio::use_awaitable);
    co_await asio::async_write(output_file, asio::buffer(encapsulated_key_mlkem), asio::use_awaitable);
    
    len = salt.size(); 
    co_await asio::async_write(output_file, asio::buffer(&len, sizeof(len)), asio::use_awaitable);
    co_await asio::async_write(output_file, asio::buffer(salt), asio::use_awaitable);
    
    len = iv.size(); 
    co_await asio::async_write(output_file, asio::buffer(&len, sizeof(len)), asio::use_awaitable);
    co_await asio::async_write(output_file, asio::buffer(iv), asio::use_awaitable);
    
    // --- 並列処理ループ ---
    const size_t READ_CHUNK_SIZE = 64 * 1024; // 64KB に変更
    auto completed_chunks = std::make_shared<std::map<uint64_t, std::vector<unsigned char>>>();
    auto map_mutex = std::make_shared<std::mutex>();
    auto next_sequence_to_write = std::make_shared<std::atomic<uint64_t>>(0);
    auto tasks_in_flight = std::make_shared<std::atomic<uint64_t>>(0);
    auto first_exception = std::make_shared<std::optional<std::exception_ptr>>();
    
    uint64_t read_sequence = 0;
    uintmax_t bytes_processed_so_far = 0; 

    for (;; read_sequence++) {
        if (*first_exception) break; 
        std::vector<unsigned char> buffer(READ_CHUNK_SIZE);
        auto [read_ec, bytes_read] = co_await input_file.async_read_some(asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
        
        if(read_ec && read_ec != asio::error::eof) {
            *first_exception = std::make_exception_ptr(std::system_error(read_ec));
            break;
        }
        if (bytes_read > 0) { bytes_processed_so_far += bytes_read; }
        if (bytes_read == 0) break;
        buffer.resize(bytes_read);
        
        (*tasks_in_flight)++;

        asio::post(worker_context, [this, seq_id = read_sequence, data = std::move(buffer), template_ctx, completed_chunks, map_mutex, writer_strand, tasks_in_flight, first_exception, &output_file, next_sequence_to_write]() mutable {
            try {
                if (*first_exception) { (*tasks_in_flight)--; return; }
                auto encrypted_data = pqc_encrypt_chunk_logic(data, template_ctx.get());
                if(encrypted_data.empty() && !data.empty()) throw std::runtime_error("Chunk encryption failed");

                std::scoped_lock lock(*map_mutex);
                (*completed_chunks)[seq_id] = std::move(encrypted_data);
            } catch(...) {
                std::scoped_lock lock(*map_mutex);
                if(!*first_exception) *first_exception = std::current_exception();
                (*tasks_in_flight)--; // 例外発生時のみデクリメント
                return;
            }

            asio::post(writer_strand, [this, completed_chunks, map_mutex, next_sequence_to_write, tasks_in_flight, writer_strand, &output_file, first_exception]() mutable {
                if(*first_exception) {
                    return;
                }
                std::scoped_lock lock(*map_mutex);
                for (;;) {
                    auto it = completed_chunks->find(next_sequence_to_write->load());
                    if (it == completed_chunks->end()) {
                        break;
                    }
                    
                    auto data_to_write = std::move(it->second);
                    completed_chunks->erase(it);
                    
                    asio::co_spawn(writer_strand,
                        asio::async_write(output_file, asio::buffer(data_to_write), asio::use_awaitable),
                        [tasks_in_flight, first_exception, map_mutex](std::exception_ptr p, std::size_t) { 
                            if(p && !*first_exception) {
                                std::scoped_lock lock(*map_mutex);
                                *first_exception = p;
                            }
                            (*tasks_in_flight)--; // 書き込み完了後にデクリメント
                        }
                    );
                    (*next_sequence_to_write)++;
                }
            });
        });
        if (total_input_size > 0) printProgress(static_cast<double>(bytes_processed_so_far) / total_input_size); 
    }
    
    while (*tasks_in_flight > 0) {
        co_await asio::steady_timer(executor, std::chrono::milliseconds(20)).async_wait(asio::use_awaitable);
    }
    
    if(*first_exception) {
        std::rethrow_exception(first_exception->value());
    }
    
    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    int final_len = 0;
    if (EVP_EncryptFinal_ex(template_ctx.get(), final_block.data(), &final_len) <= 0) {
        printOpenSSLErrors(); throw std::runtime_error("Failed to finalize encryption.");
    }
    if (final_len > 0) {
        co_await asio::async_write(output_file, asio::buffer(final_block.data(), final_len), asio::use_awaitable);
    }

    std::vector<unsigned char> tag(GCM_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag.data()) <= 0) {
        printOpenSSLErrors(); throw std::runtime_error("Failed to get GCM tag.");
    }
    co_await asio::async_write(output_file, asio::buffer(tag), asio::use_awaitable);
    
    printProgress(1.0);
    std::cout << "\nParallel PQC encryption to '" << output_filepath.string() << "' completed." << std::endl;
    co_return;
}

asio::awaitable<void> nkCryptoToolPQC::decryptFileParallel(
    asio::io_context& worker_context,
    std::string input_filepath_str,
    std::string output_filepath_str,
    std::string user_private_key_path_str
) {
    const std::filesystem::path input_filepath(input_filepath_str);
    const std::filesystem::path output_filepath(output_filepath_str);
    const std::filesystem::path recipient_mlkem_private_key_path(user_private_key_path_str);
    
    auto executor = co_await asio::this_coro::executor;
    auto writer_strand = asio::make_strand(executor);

    async_file_t input_file(executor);
    async_file_t output_file(executor);
    std::error_code ec;
#ifdef _WIN32
    input_file.open(input_filepath.string(), async_file_t::read_only, ec);
#else
    int fd_in = ::open(input_filepath.string().c_str(), O_RDONLY);
    if (fd_in == -1) { ec.assign(errno, std::system_category()); } else { input_file.assign(fd_in, ec); }
#endif
    if(ec) { throw std::system_error(ec, "Failed to open input file"); }

#ifdef _WIN32
    output_file.open(output_filepath.string(), async_file_t::write_only | async_file_t::create | async_file_t::truncate, ec);
#else
    int fd_out = ::open(output_filepath.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd_out == -1) { ec.assign(errno, std::system_category()); } else { output_file.assign(fd_out, ec); }
#endif
    if(ec) { throw std::system_error(ec, "Failed to open output file"); }

    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) { throw std::system_error(ec, "Failed to get file size"); }

    FileHeader header;
    co_await asio::async_read(input_file, asio::buffer(&header, sizeof(header)), asio::use_awaitable);
    if(memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) {
        throw std::runtime_error("Invalid file header.");
    }
    if(header.reserved != 0) {
        throw std::runtime_error("This parallel function only supports PQC-only files, not hybrid files.");
    }
    if(header.compression_algo != CompressionAlgorithm::NONE) {
        throw std::runtime_error("Compression is not supported in parallel decryption mode.");
    }

    uint32_t len;
    std::vector<unsigned char> encapsulated_key_mlkem, salt, iv;
    co_await asio::async_read(input_file, asio::buffer(&len, sizeof(len)), asio::use_awaitable); encapsulated_key_mlkem.resize(len);
    co_await asio::async_read(input_file, asio::buffer(encapsulated_key_mlkem), asio::use_awaitable);
    
    co_await asio::async_read(input_file, asio::buffer(&len, sizeof(len)), asio::use_awaitable); salt.resize(len);
    co_await asio::async_read(input_file, asio::buffer(salt), asio::use_awaitable);

    co_await asio::async_read(input_file, asio::buffer(&len, sizeof(len)), asio::use_awaitable); iv.resize(len);
    co_await asio::async_read(input_file, asio::buffer(iv), asio::use_awaitable);

    auto recipient_mlkem_private_key = loadPrivateKey(recipient_mlkem_private_key_path, "ML-KEM private key");
    if (!recipient_mlkem_private_key) { throw std::runtime_error("Failed to load user ML-KEM private key."); }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_private_key.get(), nullptr));
    if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to init PQC decapsulation."); }
    
    size_t secret_len_mlkem = 0;
    if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to get PQC decapsulation secret length."); }
    
    std::vector<unsigned char> secret_mlkem(secret_len_mlkem);
    if (EVP_PKEY_decapsulate(kem_ctx.get(), secret_mlkem.data(), &secret_len_mlkem, encapsulated_key_mlkem.data(), encapsulated_key_mlkem.size()) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Decapsulation failed. The private key may be incorrect or the data corrupted."); }
    
    std::vector<unsigned char> decryption_key = hkdfDerive(secret_mlkem, 32, std::string(salt.begin(), salt.end()), "hybrid-pqc-ecc-encryption", "SHA3-256");
    if (decryption_key.empty()) { throw std::runtime_error("Failed to derive decryption key."); }
    
    std::shared_ptr<EVP_CIPHER_CTX> template_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
    EVP_DecryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());

    const size_t READ_CHUNK_SIZE = 64 * 1024; // 64KB に変更
    auto completed_chunks = std::make_shared<std::map<uint64_t, std::vector<unsigned char>>>();
    auto map_mutex = std::make_shared<std::mutex>();
    auto next_sequence_to_write = std::make_shared<std::atomic<uint64_t>>(0);
    auto tasks_in_flight = std::make_shared<std::atomic<uint64_t>>(0);
    auto first_exception = std::make_shared<std::optional<std::exception_ptr>>();
    
    uint64_t read_sequence = 0;
    
    uintmax_t header_size = sizeof(FileHeader) + sizeof(uint32_t) + encapsulated_key_mlkem.size() + sizeof(uint32_t) + salt.size() + sizeof(uint32_t) + iv.size();
    uintmax_t ciphertext_size = total_input_size - header_size - GCM_TAG_LEN;
    uintmax_t bytes_read_so_far = 0; 
    
    while(bytes_read_so_far < ciphertext_size) {
        if(*first_exception) break;
        size_t to_read = std::min((uintmax_t)READ_CHUNK_SIZE, ciphertext_size - bytes_read_so_far);
        if (to_read == 0) break;
        std::vector<unsigned char> buffer(to_read);
        auto [read_ec, bytes_read] = co_await asio::async_read(input_file, asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
        
        if(read_ec && read_ec != asio::error::eof) {
            *first_exception = std::make_exception_ptr(std::system_error(read_ec));
            break;
        }
        if (bytes_read > 0) { bytes_read_so_far += bytes_read; }
        if (bytes_read == 0 && bytes_read_so_far < ciphertext_size) {
            *first_exception = std::make_exception_ptr(std::runtime_error("File ended prematurely."));
            break;
        }
        buffer.resize(bytes_read);
        
        (*tasks_in_flight)++;

        asio::post(worker_context, [this, seq_id = read_sequence, data = std::move(buffer), template_ctx, completed_chunks, map_mutex, writer_strand, tasks_in_flight, first_exception, &output_file, next_sequence_to_write]() mutable {
            try {
                if(*first_exception) { (*tasks_in_flight)--; return; }
                auto decrypted_data = pqc_decrypt_chunk_logic(data, template_ctx.get());
                if(decrypted_data.empty() && !data.empty()) throw std::runtime_error("Chunk decryption failed");
                
                std::scoped_lock lock(*map_mutex);
                (*completed_chunks)[seq_id] = std::move(decrypted_data);
            } catch (...) {
                std::scoped_lock lock(*map_mutex);
                if(!*first_exception) *first_exception = std::current_exception();
                (*tasks_in_flight)--;
                return;
            }

            asio::post(writer_strand, [this, completed_chunks, map_mutex, next_sequence_to_write, tasks_in_flight, writer_strand, &output_file, first_exception]() mutable {
                if(*first_exception) { return; }
                std::scoped_lock lock(*map_mutex);
                for (;;) {
                    auto it = completed_chunks->find(next_sequence_to_write->load());
                    if (it == completed_chunks->end()) break;
                    
                    auto data_to_write = std::move(it->second);
                    completed_chunks->erase(it);
                    
                    asio::co_spawn(writer_strand,
                        asio::async_write(output_file, asio::buffer(data_to_write), asio::use_awaitable),
                        [tasks_in_flight, first_exception, map_mutex](std::exception_ptr p, std::size_t) { 
                            if(p && !*first_exception) {
                                std::scoped_lock lock(*map_mutex);
                                *first_exception = p;
                            }
                            (*tasks_in_flight)--; 
                        }
                    );
                    (*next_sequence_to_write)++;
                }
            });
        });
        read_sequence++;
        if (ciphertext_size > 0) printProgress(static_cast<double>(bytes_read_so_far) / ciphertext_size);
    }
    
    while (*tasks_in_flight > 0) {
        co_await asio::steady_timer(executor, std::chrono::milliseconds(20)).async_wait(asio::use_awaitable);
    }
    
    if(*first_exception) {
        std::rethrow_exception(first_exception->value());
    }

    std::vector<unsigned char> tag(GCM_TAG_LEN);
    co_await asio::async_read(input_file, asio::buffer(tag), asio::use_awaitable);
    
    if(EVP_CIPHER_CTX_ctrl(template_ctx.get(), EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag.data()) <= 0) {
        throw std::runtime_error("Failed to set GCM tag.");
    }

    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    int final_len = 0;
    if (EVP_DecryptFinal_ex(template_ctx.get(), final_block.data(), &final_len) <= 0) {
        printOpenSSLErrors();
        throw std::runtime_error("GCM tag verification failed. File may be corrupted or tampered with.");
    }
    
    if(final_len > 0) {
        co_await asio::async_write(output_file, asio::buffer(final_block.data(), final_len), asio::use_awaitable);
    }

    printProgress(1.0);
    std::cout << "\nParallel PQC decryption to '" << output_filepath.string() << "' completed." << std::endl;
    co_return;
}
