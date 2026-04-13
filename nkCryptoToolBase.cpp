/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkCryptoToolBase.hpp"
#include "PipelineManager.hpp"
#include "async_file_types.hpp"
#include "TPMUtils.hpp"
#include <fstream>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <asio/write.hpp>
#include <asio/read.hpp>
#include <functional>
#include <format>

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

nkCryptoToolBase::nkCryptoToolBase(std::shared_ptr<ICryptoStrategy> strategy)
    : strategy_(std::move(strategy)) {}

nkCryptoToolBase::~nkCryptoToolBase() {}

void nkCryptoToolBase::setKeyBaseDirectory(std::filesystem::path dir) {
    key_base_directory = dir;
    if (!std::filesystem::exists(key_base_directory)) std::filesystem::create_directories(key_base_directory);
}

std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const { return key_base_directory; }

std::expected<void, CryptoError> nkCryptoToolBase::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    return strategy_->generateEncryptionKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> nkCryptoToolBase::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    return strategy_->generateSigningKeyPair(key_paths, passphrase);
}

// --- 暗号化 ---
void nkCryptoToolBase::encryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback
) {
    auto strategy = strategy_;
    auto res = strategy->prepareEncryption(key_paths);
    if (!res) { completion_handler(std::make_error_code(std::errc::invalid_argument)); return; }

    std::error_code ec;
    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec); return; }

    auto header = strategy->serializeHeader();
    asio::write(output_file.get(), asio::buffer(header), ec);
    if (ec) { completion_handler(ec); return; }

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { return strategy->encryptTransform(data); });

    PipelineManager::FinalizationFunc finalizer = [strategy](async_file_t& out) -> asio::awaitable<void> {
        std::vector<char> final_data;
        if (strategy->finalizeEncryption(final_data)) {
            co_await asio::async_write(out.get(), asio::buffer(final_data), asio::use_awaitable);
        }
    };

    uintmax_t size = std::filesystem::file_size(input_filepath, ec);
    manager->run(input_filepath, std::move(output_file), 0, size, completion_handler, std::move(finalizer), progress_callback, size);
}

// --- 復号 ---
void nkCryptoToolBase::decryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::string& passphrase,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback
) {
    auto strategy = strategy_;
    if (!strategy) { completion_handler(std::make_error_code(std::errc::invalid_argument)); return; }
    
    std::error_code ec;
    if (!std::filesystem::exists(input_filepath)) {
        completion_handler(std::make_error_code(std::errc::no_such_file_or_directory));
        return;
    }
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { completion_handler(ec); return; }

    size_t tag_size = strategy->getTagSize();
    if (total_size < tag_size) { completion_handler(std::make_error_code(std::errc::invalid_argument)); return; }

    std::vector<char> tag(tag_size);
    {
        std::ifstream in(input_filepath, std::ios::binary);
        if (!in) { completion_handler(std::make_error_code(std::errc::no_such_file_or_directory)); return; }
        in.seekg(total_size - tag_size);
        in.read(tag.data(), tag_size);
        
        in.seekg(0);
        std::vector<char> header_peek(16384); 
        in.read(header_peek.data(), header_peek.size());
        std::streamsize read_bytes = in.gcount();
        if (read_bytes < 7) { completion_handler(std::make_error_code(std::errc::illegal_byte_sequence)); return; }
        header_peek.resize(static_cast<size_t>(read_bytes));
        if (!strategy->deserializeHeader(header_peek)) { completion_handler(std::make_error_code(std::errc::illegal_byte_sequence)); return; }
    }

    auto prep_res = strategy->prepareDecryption(key_paths, passphrase);
    if (!prep_res) {
        std::cerr << "\n[ERROR] prepareDecryption failed: " << toString(prep_res.error()) << std::endl;
        completion_handler(std::make_error_code(std::errc::permission_denied));
        return;
    }

    size_t header_size = strategy->getHeaderSize();
    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec); return; }

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { return strategy->decryptTransform(data); });

    PipelineManager::FinalizationFunc finalizer = [strategy, tag](async_file_t& out) -> asio::awaitable<void> {
        if (!strategy->finalizeDecryption(tag)) {
            throw std::runtime_error("Decryption failed: Integrity check error");
        }
        co_return;
    };

    uintmax_t ciphertext_size = total_size - header_size - tag_size;
    manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, completion_handler, std::move(finalizer), progress_callback, total_size);
}

// --- 署名・検証 ---
asio::awaitable<void> nkCryptoToolBase::signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, std::string& passphrase, ProgressCallback progress_callback) {
    auto strategy = strategy_;
    auto res = strategy->prepareSigning(signing_private_key_path, passphrase, digest_algo);
    if (!res) throw std::runtime_error("Failed to prepare signing");

    async_file_t input_file(io_context);
    std::error_code ec;
    input_file.open(input_filepath.string(), O_RDONLY, ec);
    if (ec) throw std::system_error(ec, "Failed to open input file");

    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    uintmax_t processed_size = 0;

    std::vector<char> buffer(CHUNK_SIZE);
    while (true) {
        try {
            size_t n = co_await input_file.get().async_read_some(asio::buffer(buffer), asio::use_awaitable);
            if (n == 0) break;
            strategy->updateHash(std::vector<char>(buffer.begin(), buffer.begin() + n));
            processed_size += n;
            if (progress_callback && total_size > 0) {
                progress_callback(static_cast<double>(processed_size) / total_size);
            }
        } catch (const std::system_error& e) {
            if (e.code() == asio::error::eof) break;
            throw;
        }
    }
    auto sig = strategy->signHash();
    if (!sig) throw std::runtime_error("Failed to sign hash");

    auto header = strategy->serializeSignatureHeader();
    std::ofstream out(signature_filepath, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open signature file for writing");
    out.write(header.data(), (std::streamsize)header.size());
    out.write(sig->data(), (std::streamsize)sig->size());
    co_return;
}

asio::awaitable<std::expected<void, CryptoError>> nkCryptoToolBase::verifySignature(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_public_key_path, std::string digest_algo, ProgressCallback progress_callback) {
    auto strategy = strategy_;

    std::ifstream sig_in(signature_filepath, std::ios::binary);
    if (!sig_in) co_return std::unexpected(CryptoError::FileReadError);
    std::vector<char> sig_data((std::istreambuf_iterator<char>(sig_in)), std::istreambuf_iterator<char>());
    auto header_pos_res = strategy->deserializeSignatureHeader(sig_data);
    if (!header_pos_res) co_return std::unexpected(header_pos_res.error());

    auto res = strategy->prepareVerification(signing_public_key_path, digest_algo);
    if (!res) co_return std::unexpected(res.error());

    async_file_t input_file(io_context);
    std::error_code ec;
    input_file.open(input_filepath.string(), O_RDONLY, ec);
    if (ec) co_return std::unexpected(CryptoError::FileReadError);

    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    uintmax_t processed_size = 0;

    std::vector<char> buffer(CHUNK_SIZE);
    while (true) {
        try {
            size_t n = co_await input_file.get().async_read_some(asio::buffer(buffer), asio::use_awaitable);
            if (n == 0) break;
            strategy->updateHash(std::vector<char>(buffer.begin(), buffer.begin() + n));
            processed_size += n;
            if (progress_callback && total_size > 0) {
                progress_callback(static_cast<double>(processed_size) / total_size);
            }
        } catch (const std::system_error& e) {
            if (e.code() == asio::error::eof) break;
            throw;
        }
    }

    std::vector<char> raw_sig(sig_data.begin() + *header_pos_res, sig_data.end());
    auto result = strategy->verifyHash(raw_sig);
    if (!result) {
        co_return std::unexpected(result.error());
    }
    if (*result) {
        std::cout << "\nSignature verified successfully." << std::endl;
        co_return std::expected<void, CryptoError>{};
    } else {
        co_return std::unexpected(CryptoError::SignatureVerificationError);
    }
}

// --- ユーティリティ ---
std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPublicKey(std::filesystem::path path) {
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_file(path.string().c_str(), "rb"));
    if (!bio) return std::unexpected(CryptoError::FileReadError);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPrivateKey(std::filesystem::path path, std::string& passphrase) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    if (pem_content.find(TPMUtils::TPM_WRAPPED_HEADER) != std::string::npos || pem_content.find(TPMUtils::TPM_WRAPPED_ENC_HEADER) != std::string::npos) {
        return TPMUtils::unwrapKey(pem_content, passphrase);
    }

    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
    void* pwd = passphrase.empty() ? nullptr : (void*)passphrase.c_str();
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::expected<void, CryptoError> nkCryptoToolBase::regeneratePublicKey(std::filesystem::path priv, std::filesystem::path pub, std::string& pass) {
    auto pkey = loadPrivateKey(priv, pass);
    if (!pkey) return std::unexpected(pkey.error());
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_file(pub.string().c_str(), "wb"));
    if (PEM_write_bio_PUBKEY(bio.get(), pkey->get()) <= 0) return std::unexpected(CryptoError::PublicKeyWriteError);
    return {};
}

std::expected<void, CryptoError> nkCryptoToolBase::wrapPrivateKey(std::filesystem::path raw_priv, std::filesystem::path wrapped_priv, std::string& pass) {
    auto pkey = loadPrivateKey(raw_priv, pass);
    if (!pkey) return std::unexpected(pkey.error());
    
    auto wrapped = TPMUtils::wrapKey(pkey->get(), pass);
    if (!wrapped) return std::unexpected(wrapped.error());
    
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_file(wrapped_priv.string().c_str(), "wb"));
    if (!bio) return std::unexpected(CryptoError::FileCreationError);
    
    BIO_write(bio.get(), (*wrapped).data(), (int)(*wrapped).size());
    return {};
}

std::expected<void, CryptoError> nkCryptoToolBase::unwrapPrivateKey(std::filesystem::path wrapped_priv, std::filesystem::path raw_priv, std::string& pass) {
    std::ifstream ifs(wrapped_priv, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    auto pkey = TPMUtils::unwrapKey(pem_content, pass);
    if (!pkey) return std::unexpected(pkey.error());

    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_file(raw_priv.string().c_str(), "wb"));
    if (!bio) return std::unexpected(CryptoError::FileCreationError);

    if (pass.empty()) {
        PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey->get(), nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey->get(), EVP_aes_256_cbc(), (const char*)pass.c_str(), (int)pass.length(), nullptr, nullptr);
    }
    return {};
}

bool nkCryptoToolBase::isPrivateKeyEncrypted(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    // 1. ファイル全体に "ENCRYPTED" という文字列が含まれているかチェック
    // 独自ヘッダー (TPM_WRAPPED_ENC_HEADER) も "ENCRYPTED" を含んでいるため、これで確実にヒットします。
    if (content.find("ENCRYPTED") != std::string::npos) {
        return true;
    }

    // 2. 念のため、標準的な PEM ロードを試みてパスワードを要求されるか確認する (フォールバック)
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(content.data(), (int)content.size()));
    bool password_required = false;
    auto cb = [](char*, int, int, void* u) -> int { *static_cast<bool*>(u) = true; return 0; };
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, cb, &password_required);
    if (pkey) EVP_PKEY_free(pkey);
    
    return password_required;
}

std::expected<StrategyType, CryptoError> nkCryptoToolBase::detectStrategyType(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return std::unexpected(CryptoError::FileReadError);
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    
    char buf[7];
    ifs.read(buf, 7);
    if (ifs.gcount() < 7) return std::unexpected(CryptoError::FileReadError);
    
    std::string magic(buf, 4);
    if (magic != "NKCT" && magic != "NKCS") return std::unexpected(CryptoError::FileReadError);
    uint16_t version; memcpy(&version, buf + 4, 2);
    if (version != 1) return std::unexpected(CryptoError::FileReadError);
    
    uint8_t type = (uint8_t)buf[6];
    return static_cast<StrategyType>(type);
}

std::vector<unsigned char> nkCryptoToolBase::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len, const std::string& salt, const std::string& info, const std::string& digest_algo) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest_algo.c_str(), 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string("salt", (void*)salt.c_str(), salt.length());
    params[3] = OSSL_PARAM_construct_octet_string("info", (void*)info.c_str(), info.length());
    params[4] = OSSL_PARAM_construct_end();
    std::vector<unsigned char> out(output_len);
    EVP_KDF_derive(kctx.get(), out.data(), output_len, params);
    return out;
}

void nkCryptoToolBase::printOpenSSLErrors() { ERR_print_errors_fp(stderr); }

asio::awaitable<std::expected<std::map<std::string, std::string>, CryptoError>> 
nkCryptoToolBase::inspectFile(asio::io_context&, std::filesystem::path input_filepath, ProgressCallback) {
    if (!std::filesystem::exists(input_filepath)) co_return std::unexpected(CryptoError::FileReadError);
    
    std::ifstream in(input_filepath, std::ios::binary);
    if (!in) co_return std::unexpected(CryptoError::FileReadError);
    
    std::vector<char> header_peek(16384);
    in.read(header_peek.data(), (std::streamsize)header_peek.size());
    std::streamsize read_bytes = in.gcount();
    if (read_bytes < 7) co_return std::unexpected(CryptoError::FileReadError);
    
    header_peek.resize(static_cast<size_t>(read_bytes));
    
    std::string magic(header_peek.data(), 4);
    if (magic == "NKCT") {
        auto res = strategy_->deserializeHeader(header_peek);
        if (!res) co_return std::unexpected(res.error());
    } else if (magic == "NKCS") {
        auto res = strategy_->deserializeSignatureHeader(header_peek);
        if (!res) co_return std::unexpected(res.error());
    } else {
        co_return std::unexpected(CryptoError::FileReadError);
    }
    
    auto metadata = strategy_->getMetadata(magic);
    metadata["File-Format"] = (magic == "NKCT" ? "NKCT (Encrypted Data)" : "NKCS (Digital Signature)");
    co_return metadata;
}
