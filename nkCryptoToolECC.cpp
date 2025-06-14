// nkCryptoToolECC.cpp

#include "nkCryptoToolECC.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <optional>
#include <fstream>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/stream_file.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <functional>

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

struct nkCryptoToolECC::SigningState : public nkCryptoToolBase::AsyncStateBase, public std::enable_shared_from_this<SigningState> {
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx;
    uintmax_t total_input_size;
    SigningState(asio::io_context& io_context) : AsyncStateBase(io_context), md_ctx(EVP_MD_CTX_new()), total_input_size(0) {}
};
struct nkCryptoToolECC::VerificationState : public nkCryptoToolBase::AsyncStateBase, public std::enable_shared_from_this<VerificationState> {
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> md_ctx;
    asio::stream_file signature_file;
    std::vector<unsigned char> signature;
    uintmax_t total_input_size;
    std::function<void(std::error_code, bool)> verification_completion_handler;
    VerificationState(asio::io_context& io_context) : AsyncStateBase(io_context), md_ctx(EVP_MD_CTX_new()), signature_file(io_context), total_input_size(0) {}
};


nkCryptoToolECC::nkCryptoToolECC() {}
nkCryptoToolECC::~nkCryptoToolECC() {}

std::filesystem::path nkCryptoToolECC::getEncryptionPrivateKeyPath() const { return getKeyBaseDirectory() / "private_enc_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getSigningPrivateKeyPath() const { return getKeyBaseDirectory() / "private_sign_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getEncryptionPublicKeyPath() const { return getKeyBaseDirectory() / "public_enc_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getSigningPublicKeyPath() const { return getKeyBaseDirectory() / "public_sign_ecc.key"; }

bool nkCryptoToolECC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    return generateSigningKeyPair(public_key_path, private_key_path, passphrase);
}

bool nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::ofstream priv_file(private_key_path, std::ios::out | std::ios::binary);
    if (!priv_file.is_open()) {
        std::cerr << "Error creating private key file: " << private_key_path << std::endl;
        return false;
    }
    priv_file.close(); 

    std::ofstream pub_file(public_key_path, std::ios::out | std::ios::binary);
    if (!pub_file.is_open()) {
        std::cerr << "Error creating public key file: " << public_key_path << std::endl;
        return false;
    }
    pub_file.close();

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { printOpenSSLErrors(); return false; }

    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() };
    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) { printOpenSSLErrors(); return false; }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { printOpenSSLErrors(); return false; }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ec_key(pkey);

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) { std::cerr << "Error creating BIO for private key file: " << private_key_path << std::endl; return false; }

    bool success = false;
    if (passphrase.empty()) {
        std::cout << "Saving private key without encryption." << std::endl;
        success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr) > 0;
    } else {
        success = PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(),
                                                (const char*)passphrase.c_str(), passphrase.length(),
                                                nullptr, nullptr) > 0;
    }

    if (!success) { printOpenSSLErrors(); return false; }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) { printOpenSSLErrors(); return false; }
    return true;
}

std::vector<unsigned char> nkCryptoToolECC::generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) {
        printOpenSSLErrors(); return {};
    }
    size_t secret_len;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) { printOpenSSLErrors(); return {}; }
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) { printOpenSSLErrors(); return {}; }
    secret.resize(secret_len);
    return secret;
}

void nkCryptoToolECC::encryptFile(
    asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_public_key_path, CompressionAlgorithm algo, std::function<void(std::error_code)> completion_handler)
{
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nEncryption to '" << output_filepath.string() << "' completed." << std::endl;
        else std::cerr << "\nEncryption failed: " << ec.message() << std::endl;
        completion_handler(ec);
    };

    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler;
    state->compression_algo = algo;
    auto recipient_public_key = loadPublicKey(recipient_public_key_path);
    if (!recipient_public_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx_eph(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx_eph || EVP_PKEY_keygen_init(pctx_eph.get()) <= 0) { return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() };
    if (EVP_PKEY_CTX_set_params(pctx_eph.get(), params) <= 0) { return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    EVP_PKEY* eph_pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx_eph.get(), &eph_pkey_raw) <= 0) { return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_private_key(eph_pkey_raw);
    
    std::vector<unsigned char> shared_secret = generateSharedSecret(ephemeral_private_key.get(), recipient_public_key.get());
    std::vector<unsigned char> iv(GCM_IV_LEN);
    RAND_bytes(iv.data(), GCM_IV_LEN);
    std::vector<unsigned char> encryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "ecc-encryption", "SHA256");
    if (encryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));

    std::error_code ec;
    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) return wrapped_handler(ec);
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) return wrapped_handler(ec);
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) return wrapped_handler(ec);

    FileHeader header;
    memcpy(header.magic, MAGIC, sizeof(MAGIC));
    header.version = 1;
    header.compression_algo = algo;
    header.reserved = 0;
    asio::write(state->output_file, asio::buffer(&header, sizeof(header)), ec);
    if (ec) return wrapped_handler(ec);
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_private_key.get());
    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
    uint32_t key_len = bio_buf->length;
    uint32_t iv_len = iv.size();
    asio::write(state->output_file, asio::buffer(&key_len, sizeof(key_len)), ec); if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(bio_buf->data, key_len), ec); if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(&iv_len, sizeof(iv_len)), ec); if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(iv), ec); if(ec) return wrapped_handler(ec);

    if (state->compression_algo == CompressionAlgorithm::LZ4) { state->compression_stream = LZ4_createStream(); }
    EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());
    startEncryptionPipeline(state, total_input_size);
}

void nkCryptoToolECC::decryptFile(
    asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath,
    const std::filesystem::path& user_private_key_path, const std::filesystem::path&, std::function<void(std::error_code)> completion_handler)
{
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nDecryption to '" << output_filepath.string() << "' completed." << std::endl;
        else std::cerr << "\nDecryption failed: " << ec.message() << std::endl;
        completion_handler(ec);
    };

    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler;
    auto user_private_key = loadPrivateKey(user_private_key_path, "ECC private key");
    if (!user_private_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    
    std::error_code ec; 
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec); if (ec) return wrapped_handler(ec); 
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec); if (ec) return wrapped_handler(ec); 
    FileHeader header; asio::read(state->input_file, asio::buffer(&header, sizeof(header)), ec); if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) { return wrapped_handler(std::make_error_code(std::errc::invalid_argument)); } 
    state->compression_algo = header.compression_algo; uint32_t key_len = 0, iv_len = 0; asio::read(state->input_file, asio::buffer(&key_len, sizeof(key_len)), ec); if(ec || key_len > 2048) return wrapped_handler(ec ? ec : std::make_error_code(std::errc::invalid_argument)); 
    std::vector<char> eph_pub_key_buf(key_len); asio::read(state->input_file, asio::buffer(eph_pub_key_buf), ec); if(ec) return wrapped_handler(ec); 
    asio::read(state->input_file, asio::buffer(&iv_len, sizeof(iv_len)), ec); if(ec || iv_len != GCM_IV_LEN) return wrapped_handler(ec ? ec : std::make_error_code(std::errc::invalid_argument)); 
    std::vector<unsigned char> iv(iv_len); asio::read(state->input_file, asio::buffer(iv), ec); if(ec) return wrapped_handler(ec); 
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(eph_pub_key_buf.data(), key_len)); std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> eph_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr)); if(!eph_pub_key) return wrapped_handler(std::make_error_code(std::errc::io_error)); 
    std::vector<unsigned char> shared_secret = generateSharedSecret(user_private_key.get(), eph_pub_key.get()); std::vector<unsigned char> decryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "ecc-encryption", "SHA256"); if (decryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error)); 
    if (state->compression_algo == CompressionAlgorithm::LZ4) { state->decompression_stream = LZ4_createStreamDecode(); } else if (state->compression_algo != CompressionAlgorithm::NONE) { return wrapped_handler(std::make_error_code(std::errc::not_supported)); } 
    EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data()); 
    uintmax_t total_file_size = std::filesystem::file_size(input_filepath, ec); size_t header_total_size = sizeof(FileHeader) + sizeof(key_len) + key_len + sizeof(iv_len) + iv_len; 
    uintmax_t ciphertext_size = total_file_size - header_total_size - GCM_TAG_LEN; startDecryptionPipeline(state, ciphertext_size);
}

void nkCryptoToolECC::encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)> handler){ handler(std::make_error_code(std::errc::not_supported)); }
void nkCryptoToolECC::decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)> handler){ handler(std::make_error_code(std::errc::not_supported)); }

void nkCryptoToolECC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo, std::function<void(std::error_code)> completion_handler){
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = [completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nFile signed successfully." << std::endl;
        completion_handler(ec);
    };
    auto private_key = loadPrivateKey(signing_private_key_path, "ECC signing private key");
    if (!private_key) return completion_handler(std::make_error_code(std::errc::invalid_argument));
    const EVP_MD* digest = EVP_get_digestbyname(digest_algo.c_str());
    if (!digest) return completion_handler(std::make_error_code(std::errc::invalid_argument));
    EVP_DigestSignInit(state->md_ctx.get(), nullptr, digest, nullptr, private_key.get());
    std::error_code ec;
    state->total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) return completion_handler(ec);
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if(ec) return completion_handler(ec);
    state->output_file.open(signature_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if(ec) return completion_handler(ec);
    state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolECC::handleFileReadForSigning, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred){
    if (ec == asio::error::eof) { finishSigning(state); return; }
    if (ec) { state->completion_handler(ec); return; }
    EVP_DigestSignUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    if (state->total_input_size > 0) printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);
    state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolECC::handleFileReadForSigning, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishSigning(std::shared_ptr<SigningState> state){
    size_t sig_len = 0;
    EVP_DigestSignFinal(state->md_ctx.get(), nullptr, &sig_len);
    std::vector<unsigned char> signature(sig_len);
    EVP_DigestSignFinal(state->md_ctx.get(), signature.data(), &sig_len);
    signature.resize(sig_len);
    asio::async_write(state->output_file, asio::buffer(signature), [this, state](const asio::error_code& write_ec, size_t) {
        printProgress(1.0);
        state->completion_handler(write_ec);
    });
}

void nkCryptoToolECC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path, std::function<void(std::error_code, bool)> completion_handler){
    auto state = std::make_shared<VerificationState>(io_context);
    state->verification_completion_handler = completion_handler;
    auto public_key = loadPublicKey(signing_public_key_path);
    if (!public_key) return completion_handler(std::make_error_code(std::errc::invalid_argument), false);
    const EVP_MD* digest = EVP_get_digestbyname("SHA256");
    EVP_DigestVerifyInit(state->md_ctx.get(), nullptr, digest, nullptr, public_key.get());
    std::error_code ec;
    state->signature_file.open(signature_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) { completion_handler(ec, false); return; }
    state->signature.resize(std::filesystem::file_size(signature_filepath, ec));
    if (ec) { completion_handler(ec, false); return; }
    asio::async_read(state->signature_file, asio::buffer(state->signature), [this, state, input_filepath, pub_key = std::move(public_key)](const asio::error_code& read_sig_ec, size_t) mutable {
        if (read_sig_ec) { state->verification_completion_handler(read_sig_ec, false); return; }
        std::error_code open_ec;
        state->total_input_size = std::filesystem::file_size(input_filepath, open_ec);
        if(open_ec) { state->verification_completion_handler(open_ec, false); return; }
        state->input_file.open(input_filepath.string(), asio::stream_file::read_only, open_ec);
        if(open_ec) { state->verification_completion_handler(open_ec, false); return; }
        state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolECC::handleFileReadForVerification, this, state, std::placeholders::_1, std::placeholders::_2));
    });
}

void nkCryptoToolECC::handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred){
    if (ec == asio::error::eof) { finishVerification(state); return; }
    if (ec) { state->verification_completion_handler(ec, false); return; }
    EVP_DigestVerifyUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    if (state->total_input_size > 0) printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);
    state->input_file.async_read_some(asio::buffer(state->input_buffer), std::bind(&nkCryptoToolECC::handleFileReadForVerification, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishVerification(std::shared_ptr<VerificationState> state){
    printProgress(1.0);
    int result = EVP_DigestVerifyFinal(state->md_ctx.get(), state->signature.data(), state->signature.size());
    state->verification_completion_handler({}, (result == 1));
}
//================================================================================
// 並列暗号化・復号の実装
//================================================================================

// --- 暗号化ヘルパー ---
static std::vector<unsigned char> ecc_encrypt_chunk_logic(
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

// --- 並列暗号化 ---
asio::awaitable<void> nkCryptoToolECC::encryptFileParallel(
    asio::io_context& worker_context,
    std::string input_filepath_str,
    std::string output_filepath_str,
    std::string recipient_public_key_path_str,
    CompressionAlgorithm algo
) {
    const std::filesystem::path input_filepath(input_filepath_str);
    const std::filesystem::path output_filepath(output_filepath_str);
    const std::filesystem::path recipient_public_key_path(recipient_public_key_path_str);

    auto executor = co_await asio::this_coro::executor;
    auto writer_strand = asio::make_strand(executor);

    asio::stream_file input_file(executor);
    asio::stream_file output_file(executor);
    std::error_code ec;
    input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if(ec) { throw std::system_error(ec, "Failed to open input file"); }
    output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if(ec) { throw std::system_error(ec, "Failed to open output file"); }

    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) { throw std::system_error(ec, "Failed to get file size"); }

    auto recipient_public_key = loadPublicKey(recipient_public_key_path);
    if (!recipient_public_key) { throw std::runtime_error("Failed to load recipient public key."); }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx_eph(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx_eph || EVP_PKEY_keygen_init(pctx_eph.get()) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to init ephemeral keygen.");}
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0), OSSL_PARAM_construct_end() };
    if (EVP_PKEY_CTX_set_params(pctx_eph.get(), params) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to set ephemeral key params.");}
    EVP_PKEY* eph_pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pctx_eph.get(), &eph_pkey_raw) <= 0) { printOpenSSLErrors(); throw std::runtime_error("Failed to generate ephemeral key.");}
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_private_key(eph_pkey_raw);
    
    std::vector<unsigned char> shared_secret = generateSharedSecret(ephemeral_private_key.get(), recipient_public_key.get());
    std::vector<unsigned char> iv(GCM_IV_LEN);
    RAND_bytes(iv.data(), GCM_IV_LEN);
    std::vector<unsigned char> encryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "ecc-encryption", "SHA256");
    if (encryption_key.empty()) { throw std::runtime_error("Failed to derive encryption key."); }
    
    std::shared_ptr<EVP_CIPHER_CTX> template_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
    EVP_EncryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());

    FileHeader header; memcpy(header.magic, MAGIC, sizeof(MAGIC)); header.version = 1; header.compression_algo = algo; header.reserved = 0;
    co_await asio::async_write(output_file, asio::buffer(&header, sizeof(header)), asio::use_awaitable);

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PUBKEY(pub_bio.get(), ephemeral_private_key.get());
    BUF_MEM *bio_buf; BIO_get_mem_ptr(pub_bio.get(), &bio_buf);
    uint32_t key_len = bio_buf->length;
    uint32_t iv_len = iv.size();
    co_await asio::async_write(output_file, asio::buffer(&key_len, sizeof(key_len)), asio::use_awaitable);
    co_await asio::async_write(output_file, asio::buffer(bio_buf->data, key_len), asio::use_awaitable);
    co_await asio::async_write(output_file, asio::buffer(&iv_len, sizeof(iv_len)), asio::use_awaitable);
    co_await asio::async_write(output_file, asio::buffer(iv), asio::use_awaitable);
    
    const size_t READ_CHUNK_SIZE = 1 * 1024 * 1024;
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
                auto encrypted_data = ecc_encrypt_chunk_logic(data, template_ctx.get());
                if(encrypted_data.empty()) throw std::runtime_error("Chunk encryption failed");

                std::scoped_lock lock(*map_mutex);
                (*completed_chunks)[seq_id] = std::move(encrypted_data);
            } catch(...) {
                std::scoped_lock lock(*map_mutex);
                if(!*first_exception) *first_exception = std::current_exception();
                (*tasks_in_flight)--;
            }

            asio::post(writer_strand, [this, completed_chunks, map_mutex, next_sequence_to_write, tasks_in_flight, writer_strand, &output_file, first_exception]() mutable {
                if(*first_exception) {
                    *tasks_in_flight = 0;
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
                    (*next_sequence_to_write)++;

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
    std::cout << "\nParallel encryption to '" << output_filepath.string() << "' completed." << std::endl;
    co_return;
}

// --- 復号ヘルパー ---
static std::vector<unsigned char> ecc_decrypt_chunk_logic(
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


// --- 並列復号 ---
asio::awaitable<void> nkCryptoToolECC::decryptFileParallel(
    asio::io_context& worker_context,
    std::string input_filepath_str,
    std::string output_filepath_str,
    std::string user_private_key_path_str
) {
    const std::filesystem::path input_filepath(input_filepath_str);
    const std::filesystem::path output_filepath(output_filepath_str);
    const std::filesystem::path user_private_key_path(user_private_key_path_str);
    
    auto executor = co_await asio::this_coro::executor;
    auto writer_strand = asio::make_strand(executor);

    asio::stream_file input_file(executor);
    asio::stream_file output_file(executor);
    std::error_code ec;
    input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if(ec) { throw std::system_error(ec, "Failed to open input file"); }
    output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if(ec) { throw std::system_error(ec, "Failed to open output file"); }

    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) { throw std::system_error(ec, "Failed to get file size"); }

    FileHeader header;
    co_await asio::async_read(input_file, asio::buffer(&header, sizeof(header)), asio::use_awaitable);
    if(memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) {
        throw std::runtime_error("Invalid file header.");
    }

    uint32_t key_len = 0, iv_len = 0;
    co_await asio::async_read(input_file, asio::buffer(&key_len, sizeof(key_len)), asio::use_awaitable);
    if(key_len > 2048) { throw std::runtime_error("Invalid ephemeral key length."); }
    std::vector<char> eph_pub_key_buf(key_len);
    co_await asio::async_read(input_file, asio::buffer(eph_pub_key_buf), asio::use_awaitable);
    
    co_await asio::async_read(input_file, asio::buffer(&iv_len, sizeof(iv_len)), asio::use_awaitable);
    if(iv_len != GCM_IV_LEN) { throw std::runtime_error("Invalid IV length."); }
    std::vector<unsigned char> iv(iv_len);
    co_await asio::async_read(input_file, asio::buffer(iv), asio::use_awaitable);

    auto user_private_key = loadPrivateKey(user_private_key_path, "ECC private key");
    if (!user_private_key) { throw std::runtime_error("Failed to load user private key."); }
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(eph_pub_key_buf.data(), key_len));
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> eph_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
    if(!eph_pub_key) { printOpenSSLErrors(); throw std::runtime_error("Failed to read ephemeral public key."); }

    std::vector<unsigned char> shared_secret = generateSharedSecret(user_private_key.get(), eph_pub_key.get());
    std::vector<unsigned char> decryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "ecc-encryption", "SHA256");
    if (decryption_key.empty()) { throw std::runtime_error("Failed to derive decryption key."); }
    
    std::shared_ptr<EVP_CIPHER_CTX> template_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_Deleter());
    EVP_DecryptInit_ex(template_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());

    const size_t READ_CHUNK_SIZE = 1 * 1024 * 1024;
    auto completed_chunks = std::make_shared<std::map<uint64_t, std::vector<unsigned char>>>();
    auto map_mutex = std::make_shared<std::mutex>();
    auto next_sequence_to_write = std::make_shared<std::atomic<uint64_t>>(0);
    auto tasks_in_flight = std::make_shared<std::atomic<uint64_t>>(0);
    auto first_exception = std::make_shared<std::optional<std::exception_ptr>>();
    
    uint64_t read_sequence = 0;
    
    uintmax_t header_size = sizeof(FileHeader) + sizeof(key_len) + key_len + sizeof(iv_len) + iv_len;
    uintmax_t ciphertext_size = total_input_size - header_size - GCM_TAG_LEN;
    uintmax_t bytes_read_so_far = 0; 
    
    while(bytes_read_so_far < ciphertext_size) {
        if(*first_exception) break;
        size_t to_read = std::min((uintmax_t)READ_CHUNK_SIZE, ciphertext_size - bytes_read_so_far);
        std::vector<unsigned char> buffer(to_read);
        auto [read_ec, bytes_read] = co_await asio::async_read(input_file, asio::buffer(buffer), asio::as_tuple(asio::use_awaitable));
        
        if(read_ec && read_ec != asio::error::eof) {
            *first_exception = std::make_exception_ptr(std::system_error(read_ec));
            break;
        }
        if (bytes_read > 0) { bytes_read_so_far += bytes_read; }
        if (bytes_read == 0) break;
        buffer.resize(bytes_read);
        
        (*tasks_in_flight)++;

        asio::post(worker_context, [this, seq_id = read_sequence, data = std::move(buffer), template_ctx, completed_chunks, map_mutex, writer_strand, tasks_in_flight, first_exception, &output_file, next_sequence_to_write]() mutable {
            try {
                if(*first_exception) { (*tasks_in_flight)--; return; }
                auto decrypted_data = ecc_decrypt_chunk_logic(data, template_ctx.get());
                std::scoped_lock lock(*map_mutex);
                (*completed_chunks)[seq_id] = std::move(decrypted_data);
            } catch (...) {
                std::scoped_lock lock(*map_mutex);
                if(!*first_exception) *first_exception = std::current_exception();
                (*tasks_in_flight)--;
            }

            asio::post(writer_strand, [this, completed_chunks, map_mutex, next_sequence_to_write, tasks_in_flight, writer_strand, &output_file, first_exception]() mutable {
                if(*first_exception) { *tasks_in_flight = 0; return; }
                std::scoped_lock lock(*map_mutex);
                for (;;) {
                    auto it = completed_chunks->find(next_sequence_to_write->load());
                    if (it == completed_chunks->end()) break;
                    
                    auto data_to_write = std::move(it->second);
                    completed_chunks->erase(it);
                    (*next_sequence_to_write)++;

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
    std::cout << "\nParallel decryption to '" << output_filepath.string() << "' completed." << std::endl;
    co_return;
}
