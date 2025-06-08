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

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);
extern std::string global_passphrase_for_pem_cb;

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
    // (元の鍵生成実装)
    return true;
}
bool nkCryptoToolECC::generateSigningKeyPair(const std::filesystem::path& public_key_path, const std::filesystem::path& private_key_path, const std::string& passphrase) {
    // (元の鍵生成実装)
    return true;
}
std::vector<unsigned char> nkCryptoToolECC::generateSharedSecret(EVP_PKEY* private_key, EVP_PKEY* peer_public_key) {
    // (元の共通鍵生成実装)
    return {};
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

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_private_key;
    // (一時鍵生成ロジック... 元のコードから)
    
    std::vector<unsigned char> shared_secret = generateSharedSecret(ephemeral_private_key.get(), recipient_public_key.get());
    std::vector<unsigned char> iv(GCM_IV_LEN);
    if (RAND_bytes(iv.data(), GCM_IV_LEN) <= 0) return wrapped_handler(std::make_error_code(std::errc::io_error));
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

    // (一時公開鍵とIVを書き込むECC固有ヘッダーのロジック)

    if (state->compression_algo == CompressionAlgorithm::LZ4) {
        state->compression_stream = LZ4_createStream();
    }
    if (EVP_EncryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, encryption_key.data(), iv.data()) <= 0) {
        return wrapped_handler(std::make_error_code(std::errc::io_error));
    }
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
    
    // (一時公開鍵とIVを読み込むECC固有ヘッダーのロジック)
    std::vector<unsigned char> iv; // 読み込んだIV
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> sender_ephemeral_public_key; // 読み込んだ鍵

    std::vector<unsigned char> shared_secret = generateSharedSecret(user_private_key.get(), sender_ephemeral_public_key.get());
    std::vector<unsigned char> decryption_key = hkdfDerive(shared_secret, 32, std::string(iv.begin(), iv.end()), "ecc-encryption", "SHA256");
    if (decryption_key.empty()) return wrapped_handler(std::make_error_code(std::errc::io_error));
    
    if (state->compression_algo == CompressionAlgorithm::LZ4) {
        state->decompression_stream = LZ4_createStreamDecode();
    } else if (state->compression_algo != CompressionAlgorithm::NONE) {
        return wrapped_handler(std::make_error_code(std::errc::not_supported));
    }
    if (EVP_DecryptInit_ex(state->cipher_ctx.get(), EVP_aes_256_gcm(), nullptr, decryption_key.data(), iv.data()) <= 0) {
        return wrapped_handler(std::make_error_code(std::errc::io_error));
    }

    uintmax_t total_file_size = std::filesystem::file_size(input_filepath, ec);
    size_t header_total_size = 0; // (sizeof(FileHeader) + ECC固有ヘッダサイズ)を計算
    uintmax_t ciphertext_size = total_file_size - header_total_size - GCM_TAG_LEN;

    startDecryptionPipeline(state, ciphertext_size);
}

void nkCryptoToolECC::encryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, CompressionAlgorithm, std::function<void(std::error_code)> handler){ handler(std::make_error_code(std::errc::not_supported)); }
void nkCryptoToolECC::decryptFileHybrid(asio::io_context&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, const std::filesystem::path&, std::function<void(std::error_code)> handler){ handler(std::make_error_code(std::errc::not_supported)); }

void nkCryptoToolECC::signFile(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_private_key_path, const std::string& digest_algo, std::function<void(std::error_code)> completion_handler){
    // (元の署名実装)
}
void nkCryptoToolECC::handleFileReadForSigning(std::shared_ptr<SigningState> state, const asio::error_code& ec, size_t bytes_transferred){
    // (元の署名実装)
}
void nkCryptoToolECC::finishSigning(std::shared_ptr<SigningState> state){
    // (元の署名実装)
}
void nkCryptoToolECC::verifySignature(asio::io_context& io_context, const std::filesystem::path& input_filepath, const std::filesystem::path& signature_filepath, const std::filesystem::path& signing_public_key_path, std::function<void(std::error_code, bool)> completion_handler){
    // (元の検証実装)
}
void nkCryptoToolECC::handleFileReadForVerification(std::shared_ptr<VerificationState> state, const asio::error_code& ec, size_t bytes_transferred){
    // (元の検証実装)
}
void nkCryptoToolECC::finishVerification(std::shared_ptr<VerificationState> state){
    // (元の検証実装)
}
