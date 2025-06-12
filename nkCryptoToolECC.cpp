// nkCryptoToolECC.cpp

#include "nkCryptoToolECC.hpp"
#include <iostream>
#include <vector>
#include <memory>
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

// External PEM passphrase callback defined in main.
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

// Struct for signing/verification state
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

// --- Key Path Getters ---
std::filesystem::path nkCryptoToolECC::getEncryptionPrivateKeyPath() const { return getKeyBaseDirectory() / "private_enc_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getSigningPrivateKeyPath() const { return getKeyBaseDirectory() / "private_sign_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getEncryptionPublicKeyPath() const { return getKeyBaseDirectory() / "public_enc_ecc.key"; }
std::filesystem::path nkCryptoToolECC::getSigningPublicKeyPath() const { return getKeyBaseDirectory() / "public_sign_ecc.key"; }

// --- Key Pair Generation ---
bool nkCryptoToolECC::generateEncryptionKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    // For ECC, the same key type can be used for encryption (ECDH) and signing (ECDSA).
    return generateSigningKeyPair(public_key_path, private_key_path, passphrase);
}

bool nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) {
        printOpenSSLErrors();
        return false;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", (char*)"prime256v1", 0),
        OSSL_PARAM_construct_end()
    };
    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0) {
        printOpenSSLErrors();
        return false;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) {
        printOpenSSLErrors();
        return false;
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ec_key(pkey);

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) {
        std::cerr << "Error creating private key file: " << private_key_path << std::endl;
        return false;
    }

    // *** MODIFIED PART ***
    // Use the callback to handle the passphrase. This allows for interactive
    // prompting if the passphrase is not supplied via arguments.
    // The passphrase string passed to this function is used as 'userdata' for the callback.
    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(),
                                      nullptr, 0, // Let the callback handle the passphrase
                                      pem_passwd_cb, (void*)&passphrase) <= 0) {
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        std::cerr << "Error creating public key file: " << public_key_path << std::endl;
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get()) <= 0) {
        printOpenSSLErrors();
        return false;
    }
    return true;
}

std::vector<unsigned char> nkCryptoToolECC::generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) <= 0 || EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key) <= 0) {
        printOpenSSLErrors();
        return {};
    }
    size_t secret_len;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0) {
        printOpenSSLErrors();
        return {};
    }
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0) {
        printOpenSSLErrors();
        return {};
    }
    secret.resize(secret_len);
    return secret;
}

// --- Encryption ---
void nkCryptoToolECC::encryptFile(
    asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_public_key_path, CompressionAlgorithm algo, std::function<void(std::error_code)> completion_handler)
{
    // (Existing code...)
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
    asio::write(state->output_file, asio::buffer(&key_len, sizeof(key_len)), ec);
    if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(bio_buf->data, key_len), ec);
    if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(&iv_len, sizeof(iv_len)), ec);
    if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(iv), ec);
    if(ec) return wrapped_handler(ec);

    if (state->compression_algo == CompressionAlgorithm::LZ4) {
        state->compression_stream = LZ4_createStream();
    }
    EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());
    
    startEncryptionPipeline(state, total_input_size);
}

// --- Decryption ---
void nkCryptoToolECC::decryptFile(
    asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath,
    const std::filesystem::path& user_private_key_path, const std::filesystem::path&, std::function<void(std::error_code)> completion_handler)
{
    // (Existing code...)
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nDecryption to '" << output_filepath.string() << "' completed." << std::endl;
        else std::cerr << "\nDecryption failed: " << ec.message() << std::endl;
        completion_handler(ec);
    };

    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler;
    auto user_private_key = loadPrivateKey(user_private_key_path);
    if (!user_private_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));

    std::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) return wrapped_handler(ec);
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) return wrapped_handler(ec);

    FileHeader header;
    asio::read(state->input_file, asio::buffer(&header, sizeof(header)), ec);
    if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) {
        return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    }
    state->compression_algo = header.compression_algo;
    
    uint32_t key_len = 0, iv_len = 0;
    asio::read(state->input_file, asio::buffer(&key_len, sizeof(key_len)), ec);
    if(ec || key_len > 2048) return wrapped_handler(ec ? ec : std::make_error_code(std::errc::invalid_argument));
    std::vector<char> eph_pub_key_buf(key_len);
    asio::read(state->input_file, asio::buffer(eph_pub_key_buf), ec);
    if(ec) return wrapped_handler(ec);
    
    asio::read(state->input_file, asio::buffer(&iv_len, sizeof(iv_len)), ec);
    if(ec || iv_len != GCM_IV_LEN) return wrapped_handler(ec ? ec : std::make_error_code(std::errc::invalid_argument));
    std::vector<unsigned char> iv(iv_len);
    asio::read(state->input_file, asio::buffer(iv), ec);
    if(ec) return wrapped_handler(ec);
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_mem_buf(eph_pub_key_buf.data(), key_len));
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> eph_pub_key(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
    if(!eph_pub_key) return wrapped_handler(std::make_error_code(std::errc::io_error));

    std::vector<unsigned char> shared_secret = generateSharedSecret(user_private_key.get(), eph_pub_key.get());
    std::vector<unsigned char> decryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "ecc-encryption", "SHA256");
    if (decryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));
    
    if (state->compression_algo == CompressionAlgorithm::LZ4) {
        state->decompression_stream = LZ4_createStreamDecode();
    } else if (state->compression_algo != CompressionAlgorithm::NONE) {
        return wrapped_handler(std::make_error_code(std::errc::not_supported));
    }

    EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());

    uintmax_t total_file_size = std::filesystem::file_size(input_filepath, ec);
    size_t header_total_size = sizeof(FileHeader) + sizeof(key_len) + key_len + sizeof(iv_len) + iv_len;
    uintmax_t ciphertext_size = total_file_size - header_total_size - GCM_TAG_LEN;

    startDecryptionPipeline(state, ciphertext_size);
}

// --- Stubs for unused hybrid methods ---
void nkCryptoToolECC::encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)> handler){ handler(std::make_error_code(std::errc::not_supported)); }
void nkCryptoToolECC::decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)> handler){ handler(std::make_error_code(std::errc::not_supported)); }

// --- Signing & Verification ---
// (Existing code...)
void nkCryptoToolECC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo, std::function<void(std::error_code)> completion_handler){
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = [completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nFile signed successfully." << std::endl;
        completion_handler(ec);
    };

    auto private_key = loadPrivateKey(signing_private_key_path);
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

    state->input_file.async_read_some(asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForSigning, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred){
    if (ec == asio::error::eof) {
        finishSigning(state);
        return;
    }
    if (ec) {
        state->completion_handler(ec);
        return;
    }
    EVP_DigestSignUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    if (state->total_input_size > 0) printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);

    state->input_file.async_read_some(asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForSigning, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishSigning(std::shared_ptr<SigningState> state){
    size_t sig_len = 0;
    EVP_DigestSignFinal(state->md_ctx.get(), nullptr, &sig_len);
    std::vector<unsigned char> signature(sig_len);
    EVP_DigestSignFinal(state->md_ctx.get(), signature.data(), &sig_len);
    signature.resize(sig_len);

    asio::async_write(state->output_file, asio::buffer(signature),
        [this, state](const asio::error_code& write_ec, size_t) {
            printProgress(1.0);
            state->completion_handler(write_ec);
        });
}

void nkCryptoToolECC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path, std::function<void(std::error_code, bool)> completion_handler){
    auto state = std::make_shared<VerificationState>(io_context);
    state->verification_completion_handler = completion_handler;

    auto public_key = loadPublicKey(signing_public_key_path);
    if (!public_key) return completion_handler(std::make_error_code(std::errc::invalid_argument), false);

    const EVP_MD* digest = EVP_get_digestbyname("SHA256"); // Assuming SHA256 for ECC
    EVP_DigestVerifyInit(state->md_ctx.get(), nullptr, digest, nullptr, public_key.get());
    
    std::error_code ec;
    state->signature_file.open(signature_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) { completion_handler(ec, false); return; }
    state->signature.resize(std::filesystem::file_size(signature_filepath, ec));
    if (ec) { completion_handler(ec, false); return; }

    asio::async_read(state->signature_file, asio::buffer(state->signature),
        [this, state, input_filepath, pub_key = std::move(public_key)](const asio::error_code& read_sig_ec, size_t) mutable {
            if (read_sig_ec) { state->verification_completion_handler(read_sig_ec, false); return; }
            std::error_code open_ec;
            state->total_input_size = std::filesystem::file_size(input_filepath, open_ec);
            if(open_ec) { state->verification_completion_handler(open_ec, false); return; }
            state->input_file.open(input_filepath.string(), asio::stream_file::read_only, open_ec);
            if(open_ec) { state->verification_completion_handler(open_ec, false); return; }

            state->input_file.async_read_some(asio::buffer(state->input_buffer),
                std::bind(&nkCryptoToolECC::handleFileReadForVerification, this, state, std::placeholders::_1, std::placeholders::_2));
        });
}

void nkCryptoToolECC::handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred){
    if (ec == asio::error::eof) {
        finishVerification(state);
        return;
    }
    if (ec) {
        state->verification_completion_handler(ec, false);
        return;
    }
    EVP_DigestVerifyUpdate(state->md_ctx.get(), state->input_buffer.data(), bytes_transferred);
    state->total_bytes_processed += bytes_transferred;
    if (state->total_input_size > 0) printProgress(static_cast<double>(state->total_bytes_processed) / state->total_input_size);
    state->input_file.async_read_some(asio::buffer(state->input_buffer),
        std::bind(&nkCryptoToolECC::handleFileReadForVerification, this, state, std::placeholders::_1, std::placeholders::_2));
}

void nkCryptoToolECC::finishVerification(std::shared_ptr<VerificationState> state){
    printProgress(1.0);
    int result = EVP_DigestVerifyFinal(state->md_ctx.get(), state->signature.data(), state->signature.size());
    state->verification_completion_handler({}, (result == 1));
}
