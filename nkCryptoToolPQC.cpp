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
#include <openssl/ec.h> // For hybrid mode
#include <asio.hpp>
#include <asio/buffer.hpp>
#include <asio/stream_file.hpp>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <functional>

// External PEM passphrase callback defined in main.
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

// Structs for PQC signing/verification state (one-shot)
struct nkCryptoToolPQC::SigningState : public std::enable_shared_from_this<SigningState> {
    asio::stream_file input_file;
    asio::stream_file output_file;
    std::vector<unsigned char> file_content;
    std::function<void(std::error_code)> completion_handler;
    SigningState(asio::io_context& io) : input_file(io), output_file(io) {}
};

struct nkCryptoToolPQC::VerificationState : public std::enable_shared_from_this<VerificationState> {
    asio::stream_file input_file;
    asio::stream_file signature_file;
    std::vector<unsigned char> file_content;
    std::vector<unsigned char> signature;
    std::function<void(std::error_code, bool)> verification_completion_handler;
    VerificationState(asio::io_context& io) : input_file(io), signature_file(io) {}
};


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
    if (!priv_bio) {
        std::cerr << "Error creating private key file: " << private_key_path << std::endl;
        return false;
    }

    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), EVP_aes_256_cbc(),
                                      nullptr, 0,
                                      pem_passwd_cb, (void*)&passphrase) <= 0) {
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
     if (!pub_bio) {
        std::cerr << "Error creating public key file: " << public_key_path << std::endl;
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), kem_key.get()) <= 0) {
        printOpenSSLErrors();
        return false;
    }
    return true;
}

bool nkCryptoToolPQC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-87", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) { printOpenSSLErrors(); return false; }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) { printOpenSSLErrors(); return false; }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> dsa_key(pkey);

    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "wb"));
    if (!priv_bio) {
        std::cerr << "Error creating private key file: " << private_key_path << std::endl;
        return false;
    }
    
    if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), EVP_aes_256_cbc(),
                                      nullptr, 0,
                                      pem_passwd_cb, (void*)&passphrase) <= 0) {
        printOpenSSLErrors();
        return false;
    }

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "wb"));
    if (!pub_bio) {
        std::cerr << "Error creating public key file: " << public_key_path << std::endl;
        return false;
    }
    if (PEM_write_bio_PUBKEY(pub_bio.get(), dsa_key.get()) <= 0) {
        printOpenSSLErrors();
        return false;
    }
    return true;
}

void nkCryptoToolPQC::encryptFile(asio::io_context& io, const std::filesystem::path& in, const std::filesystem::path& out, const std::filesystem::path& pub_key, CompressionAlgorithm algo, std::function<void(std::error_code)> handler) {
    encryptFileHybrid(io, in, out, pub_key, "", algo, handler);
}
void nkCryptoToolPQC::decryptFile(asio::io_context& io, const std::filesystem::path& in, const std::filesystem::path& out, const std::filesystem::path& priv_key, const std::filesystem::path&, std::function<void(std::error_code)> handler) {
    decryptFileHybrid(io, in, out, priv_key, "", handler);
}

void nkCryptoToolPQC::encryptFileHybrid(
    asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_mlkem_public_key_path, const std::filesystem::path& recipient_ecdh_public_key_path,
    CompressionAlgorithm algo, std::function<void(std::error_code)> completion_handler)
{
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nEncryption to '" << output_filepath.string() << "' completed." << std::endl;
        else std::cerr << "\nEncryption failed: " << ec.message() << std::endl;
        completion_handler(ec);
    };

    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler;
    state->compression_algo = algo;
    
    // --- Key Encapsulation (KEM) ---
    auto recipient_mlkem_public_key = loadPublicKey(recipient_mlkem_public_key_path);
    if (!recipient_mlkem_public_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_public_key.get(), nullptr));
    if (!kem_ctx) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    if (EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }

    size_t secret_len = 0, encapsulated_key_len = 0;
    if (EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &encapsulated_key_len, nullptr, &secret_len) <= 0) {
        printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error));
    }
    
    std::vector<unsigned char> shared_secret(secret_len);
    std::vector<unsigned char> encapsulated_key(encapsulated_key_len);
    if (EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key.data(), &encapsulated_key_len, shared_secret.data(), &secret_len) <= 0) {
        printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error));
    }
    
    // --- Key Derivation ---
    std::vector<unsigned char> iv(GCM_IV_LEN);
    RAND_bytes(iv.data(), GCM_IV_LEN);
    std::vector<unsigned char> encryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "pqc-encryption", "SHA3-256");
    if (encryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));

    // --- File Operations ---
    std::error_code ec;
    uintmax_t total_input_size = std::filesystem::file_size(input_filepath, ec);
    if(ec) return wrapped_handler(ec);
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if(ec) return wrapped_handler(ec);
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if(ec) return wrapped_handler(ec);
    
    // --- Write Header ---
    FileHeader header;
    memcpy(header.magic, MAGIC, sizeof(MAGIC));
    header.version = 1;
    header.compression_algo = algo;
    header.reserved = 0;
    asio::write(state->output_file, asio::buffer(&header, sizeof(header)), ec);
    if(ec) return wrapped_handler(ec);

    uint32_t encapsulated_key_len_32 = encapsulated_key.size();
    uint32_t iv_len_32 = iv.size();
    asio::write(state->output_file, asio::buffer(&encapsulated_key_len_32, sizeof(encapsulated_key_len_32)), ec);
    if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(encapsulated_key), ec);
    if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(&iv_len_32, sizeof(iv_len_32)), ec);
    if(ec) return wrapped_handler(ec);
    asio::write(state->output_file, asio::buffer(iv), ec);
    if(ec) return wrapped_handler(ec);

    // --- Start Encryption Pipeline ---
    if (state->compression_algo == CompressionAlgorithm::LZ4) {
        state->compression_stream = LZ4_createStream();
    }
    EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data());
    
    startEncryptionPipeline(state, total_input_size);
}

void nkCryptoToolPQC::decryptFileHybrid(
    asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& output_filepath,
    const std::filesystem::path& recipient_mlkem_private_key_path, const std::filesystem::path& recipient_ecdh_private_key_path,
    std::function<void(std::error_code)> completion_handler)
{
    auto wrapped_handler = [output_filepath, completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nDecryption to '" << output_filepath.string() << "' completed." << std::endl;
        else std::cerr << "\nDecryption failed: " << ec.message() << std::endl;
        completion_handler(ec);
    };
    
    auto state = std::make_shared<AsyncStateBase>(io_context);
    state->completion_handler = wrapped_handler;
    
    // --- File Operations ---
    std::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if(ec) return wrapped_handler(ec);
    state->output_file.open(output_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if(ec) return wrapped_handler(ec);

    // --- Read Header ---
    FileHeader header;
    asio::read(state->input_file, asio::buffer(&header, sizeof(header)), ec);
    if (ec || memcmp(header.magic, MAGIC, sizeof(MAGIC)) != 0 || header.version != 1) {
        return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    }
    state->compression_algo = header.compression_algo;
    
    uint32_t encapsulated_key_len_32 = 0;
    asio::read(state->input_file, asio::buffer(&encapsulated_key_len_32, sizeof(encapsulated_key_len_32)), ec);
    if(ec || encapsulated_key_len_32 > 4096) return wrapped_handler(ec ? ec : std::make_error_code(std::errc::invalid_argument));
    std::vector<unsigned char> encapsulated_key(encapsulated_key_len_32);
    asio::read(state->input_file, asio::buffer(encapsulated_key), ec);
    if(ec) return wrapped_handler(ec);

    uint32_t iv_len_32 = 0;
    asio::read(state->input_file, asio::buffer(&iv_len_32, sizeof(iv_len_32)), ec);
    if(ec || iv_len_32 != GCM_IV_LEN) return wrapped_handler(ec ? ec : std::make_error_code(std::errc::invalid_argument));
    std::vector<unsigned char> iv(iv_len_32);
    asio::read(state->input_file, asio::buffer(iv), ec);
    if(ec) return wrapped_handler(ec);

    // --- Key Decapsulation ---
    auto recipient_mlkem_private_key = loadPrivateKey(recipient_mlkem_private_key_path);
    if (!recipient_mlkem_private_key) return wrapped_handler(std::make_error_code(std::errc::invalid_argument));
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_mlkem_private_key.get(), nullptr));
    if (!kem_ctx) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }
    if (EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) { printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::io_error)); }

    size_t secret_len = 0;
    if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &secret_len, encapsulated_key.data(), encapsulated_key.size()) <= 0) {
        printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::operation_not_permitted));
    }
    std::vector<unsigned char> shared_secret(secret_len);
    if (EVP_PKEY_decapsulate(kem_ctx.get(), shared_secret.data(), &secret_len, encapsulated_key.data(), encapsulated_key.size()) <= 0) {
        printOpenSSLErrors(); return wrapped_handler(std::make_error_code(std::errc::operation_not_permitted));
    }

    // --- Key Derivation ---
    std::vector<unsigned char> decryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "pqc-encryption", "SHA3-256");
    if (decryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));

    // --- Start Decryption Pipeline ---
    if (state->compression_algo == CompressionAlgorithm::LZ4) {
        state->decompression_stream = LZ4_createStreamDecode();
    } else if (state->compression_algo != CompressionAlgorithm::NONE) {
        return wrapped_handler(std::make_error_code(std::errc::not_supported));
    }
    EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data());
    
    uintmax_t total_file_size = std::filesystem::file_size(input_filepath, ec);
    size_t header_total_size = sizeof(FileHeader) + sizeof(encapsulated_key_len_32) + encapsulated_key.size() + sizeof(iv_len_32) + iv.size();
    uintmax_t ciphertext_size = total_file_size - header_total_size - GCM_TAG_LEN;

    startDecryptionPipeline(state, ciphertext_size);
}

// --- PQC Signing & Verification (One-shot implementations) ---
void nkCryptoToolPQC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string&, std::function<void(std::error_code)> completion_handler){
    auto state = std::make_shared<SigningState>(io_context);
    state->completion_handler = [completion_handler](const std::error_code& ec) {
        if (!ec) std::cout << "\nFile signed successfully." << std::endl;
        completion_handler(ec);
    };

    auto private_key = loadPrivateKey(signing_private_key_path);
    if (!private_key) return completion_handler(std::make_error_code(std::errc::invalid_argument));

    std::error_code ec;
    state->input_file.open(input_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) return completion_handler(ec);
    state->output_file.open(signature_filepath.string(), asio::stream_file::write_only | asio::stream_file::create | asio::stream_file::truncate, ec);
    if (ec) return completion_handler(ec);

    state->file_content.resize(std::filesystem::file_size(input_filepath, ec));
    if (ec) return completion_handler(ec);

    asio::async_read(state->input_file, asio::buffer(state->file_content),
        [this, state, pkey = std::move(private_key)](const asio::error_code& read_ec, size_t) mutable {
            if (read_ec) return state->completion_handler(read_ec);
            
            std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx(EVP_MD_CTX_new());
            size_t sig_len;
            if (EVP_DigestSignInit(mdctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0) {
                 printOpenSSLErrors();
                 return state->completion_handler(std::make_error_code(std::errc::io_error));
            }

            if (EVP_DigestSign(mdctx.get(), nullptr, &sig_len, state->file_content.data(), state->file_content.size()) <= 0) {
                 printOpenSSLErrors();
                 return state->completion_handler(std::make_error_code(std::errc::io_error));
            }
            std::vector<unsigned char> signature(sig_len);
            if (EVP_DigestSign(mdctx.get(), signature.data(), &sig_len, state->file_content.data(), state->file_content.size()) <= 0) {
                 printOpenSSLErrors();
                 return state->completion_handler(std::make_error_code(std::errc::io_error));
            }
            signature.resize(sig_len);

            asio::async_write(state->output_file, asio::buffer(signature),
                [state](const asio::error_code& write_ec, size_t) { state->completion_handler(write_ec); });
        });
}

void nkCryptoToolPQC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path, std::function<void(std::error_code, bool)> completion_handler){
    auto state = std::make_shared<VerificationState>(io_context);
    state->verification_completion_handler = completion_handler;

    auto public_key = loadPublicKey(signing_public_key_path);
    if (!public_key) return completion_handler(std::make_error_code(std::errc::invalid_argument), false);
    
    std::error_code ec;
    state->signature_file.open(signature_filepath.string(), asio::stream_file::read_only, ec);
    if (ec) return completion_handler(ec, false);
    state->signature.resize(std::filesystem::file_size(signature_filepath, ec));
    if (ec) return completion_handler(ec, false);

    asio::async_read(state->signature_file, asio::buffer(state->signature),
        [this, state, input_filepath, pkey = std::move(public_key)](const asio::error_code& read_sig_ec, size_t) mutable {
            if (read_sig_ec) return state->verification_completion_handler(read_sig_ec, false);
            
            std::error_code read_input_ec;
            state->input_file.open(input_filepath.string(), asio::stream_file::read_only, read_input_ec);
            if(read_input_ec) return state->verification_completion_handler(read_input_ec, false);
            state->file_content.resize(std::filesystem::file_size(input_filepath, read_input_ec));
            if(read_input_ec) return state->verification_completion_handler(read_input_ec, false);

            asio::async_read(state->input_file, asio::buffer(state->file_content),
                [this, state, pub_key = std::move(pkey)](const asio::error_code& final_read_ec, size_t) mutable {
                    if (final_read_ec) return state->verification_completion_handler(final_read_ec, false);

                    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> mdctx(EVP_MD_CTX_new());
                    if (EVP_DigestVerifyInit(mdctx.get(), nullptr, nullptr, nullptr, pub_key.get()) <= 0) {
                        printOpenSSLErrors();
                        return state->verification_completion_handler(std::make_error_code(std::errc::io_error), false);
                    }
                    int result = EVP_DigestVerify(mdctx.get(), state->signature.data(), state->signature.size(), state->file_content.data(), state->file_content.size());
                    state->verification_completion_handler({}, (result == 1));
                });
        });
}
