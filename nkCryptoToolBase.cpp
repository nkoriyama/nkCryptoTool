#include "nkCryptoToolBase.hpp"
#include "PipelineManager.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <future>
#include "nkCryptoToolUtils.hpp"
#include "TPMConstants.hpp"

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

nkCryptoToolBase::nkCryptoToolBase(std::shared_ptr<ICryptoStrategy> strategy)
    : strategy_(std::move(strategy)) {}

nkCryptoToolBase::~nkCryptoToolBase() {}

void nkCryptoToolBase::setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider) {
    key_provider_.set(provider);
    if (strategy_) strategy_->setKeyProvider(provider);
}

void nkCryptoToolBase::setKeyBaseDirectory(std::filesystem::path dir) { key_base_directory = dir; }
std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const { return key_base_directory; }

void nkCryptoToolBase::encryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback)
{
    asio::co_spawn(io_context, [this, &io_context, input_filepath, output_filepath, key_paths, completion_handler, progress_callback]() -> asio::awaitable<void> {
        auto strategy = strategy_;
        auto prep_res = strategy->prepareEncryption(key_paths);
        if (!prep_res) {
            completion_handler(std::make_error_code(std::errc::invalid_argument));
            co_return;
        }

        std::error_code ec;
        async_file_t output_file(io_context);
        output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
        if (ec) {
            completion_handler(ec);
            co_return;
        }

        auto header = strategy->serializeHeader();
        co_await asio::async_write(output_file.get(), asio::buffer(header), asio::use_awaitable);

        auto manager = std::make_shared<PipelineManager>(io_context);
        manager->add_stage([strategy](const std::vector<char>& data) { return strategy->encryptTransform(data); });

        PipelineManager::FinalizationFunc finalizer = [strategy](async_file_t& out) -> asio::awaitable<void> {
            std::vector<char> final_block;
            auto res = strategy->finalizeEncryption(final_block);
            if (!res) throw std::runtime_error("Encryption finalization failed");
            if (!final_block.empty()) {
                co_await asio::async_write(out.get(), asio::buffer(final_block), asio::use_awaitable);
            }
            co_return;
        };

        std::error_code size_ec;
        uintmax_t total_size = std::filesystem::file_size(input_filepath, size_ec);
        manager->run(input_filepath, std::move(output_file), 0, 0, completion_handler, std::move(finalizer), progress_callback, total_size);
        co_return;
    }, [completion_handler](std::exception_ptr p) {
        if (p) {
            try { std::rethrow_exception(p); }
            catch (const std::system_error& e) { completion_handler(e.code()); }
            catch (...) { completion_handler(make_error_code(std::errc::io_error)); }
        }
    });
}

void nkCryptoToolBase::decryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    SecureString& passphrase,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback) 
{
    auto strategy = strategy_;
    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { completion_handler(ec); return; }

    size_t tag_size = strategy->getTagSize();
    if (total_size < tag_size) { completion_handler(std::make_error_code(std::errc::invalid_argument)); return; }

    uintmax_t header_size = 0;
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
        auto res = strategy->deserializeHeader(header_peek);
        if (!res) { completion_handler(std::make_error_code(std::errc::illegal_byte_sequence)); return; }
        header_size = *res;
    }

    ERR_clear_error();
    auto prep_res = strategy->prepareDecryption(key_paths, passphrase);
    if (!prep_res) { completion_handler(std::make_error_code(std::errc::permission_denied)); return; }

    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec); return; }

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { return strategy->decryptTransform(data); });

    PipelineManager::FinalizationFunc finalizer = [strategy, tag](async_file_t& out) -> asio::awaitable<void> {
        auto res = strategy->finalizeDecryption(tag);
        if (!res) throw std::runtime_error("Decryption failed: Integrity check error");
        co_return;
    };

    uintmax_t ciphertext_size = total_size - header_size - tag_size;
    manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, completion_handler, std::move(finalizer), progress_callback, total_size);
}

asio::awaitable<void> nkCryptoToolBase::signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, SecureString& passphrase, ProgressCallback progress_callback) {
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
            if (progress_callback) progress_callback(static_cast<double>(processed_size) / total_size);
        } catch (...) {
            break;
        }
    }

    auto signature = strategy->signHash();
    if (!signature) throw std::runtime_error("Failed to sign hash");

    std::ofstream out(signature_filepath, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to create signature file");
    
    auto header = strategy->serializeSignatureHeader();
    out.write(header.data(), header.size());
    out.write(signature->data(), signature->size());
    out.flush();
    out.close();
}

asio::awaitable<std::expected<void, CryptoError>> nkCryptoToolBase::verifySignature(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_public_key_path, std::string digest_algo, ProgressCallback progress_callback) {
    auto strategy = strategy_;
    std::ifstream sig_in(signature_filepath, std::ios::binary);
    if (!sig_in) co_return std::unexpected(CryptoError::FileReadError);
    std::vector<char> sig_header_peek(1024);
    sig_in.read(sig_header_peek.data(), sig_header_peek.size());
    std::streamsize read_bytes = sig_in.gcount();
    sig_header_peek.resize(static_cast<size_t>(read_bytes));
    sig_in.clear(); // EOF到達による failbit をリセット

    auto pos_res = strategy->deserializeSignatureHeader(sig_header_peek);
    if (!pos_res) co_return std::unexpected(pos_res.error());
    size_t header_size = *pos_res;
    sig_in.seekg(0, std::ios::end);
    size_t total_sig_size = sig_in.tellg();
    size_t sig_size = total_sig_size - header_size;
    std::vector<char> signature(sig_size);
    sig_in.seekg(header_size);
    sig_in.read(signature.data(), sig_size);

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
            if (progress_callback) progress_callback(static_cast<double>(processed_size) / total_size);
        } catch (...) {
            break;
        }
    }

    auto verify_res = strategy->verifyHash(signature);
    if (!verify_res) co_return std::unexpected(verify_res.error());
    if (*verify_res) co_return std::expected<void, CryptoError>{};
    co_return std::unexpected(CryptoError::SignatureVerificationError);
}

asio::awaitable<std::expected<std::map<std::string, std::string>, CryptoError>> nkCryptoToolBase::inspectFile(asio::io_context& io_context, std::filesystem::path input_filepath, ProgressCallback progress_callback) {
    std::ifstream in(input_filepath, std::ios::binary);
    if (!in) co_return std::unexpected(CryptoError::FileReadError);
    char magic[4];
    in.read(magic, 4);
    std::string magic_str(magic, 4);
    in.seekg(0);
    std::vector<char> header_peek(16384);
    in.read(header_peek.data(), header_peek.size());
    
    std::expected<size_t, CryptoError> res;
    if (magic_str == "NKCT") {
        res = strategy_->deserializeHeader(header_peek);
    } else if (magic_str == "NKCS") {
        res = strategy_->deserializeSignatureHeader(header_peek);
    } else {
        co_return std::unexpected(CryptoError::FileReadError);
    }

    if (!res) co_return std::unexpected(res.error());
    co_return strategy_->getMetadata(magic_str);
}

std::vector<unsigned char> nkCryptoToolBase::hkdfDerive(const std::vector<unsigned char>& secret, size_t out_len, const std::string& salt, const std::string& info, const std::string& md_name) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    const EVP_MD* md = EVP_get_digestbyname(md_name.c_str());
    if (!md) md = EVP_sha256();
    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)EVP_MD_get0_name(md), 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)secret.data(), secret.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
    params[4] = OSSL_PARAM_construct_end();
    std::vector<unsigned char> out(out_len);
    EVP_KDF_derive(kctx.get(), out.data(), out_len, params);
    return out;
}

std::expected<void, CryptoError> nkCryptoToolBase::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return strategy_->generateEncryptionKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> nkCryptoToolBase::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return strategy_->generateSigningKeyPair(key_paths, passphrase);
}

std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> nkCryptoToolBase::loadPrivateKey(std::filesystem::path path, SecureString& passphrase) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        return key_provider_.unwrap(SecureString(pem_content.begin(), pem_content.end()), passphrase);
    }
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
    void* pwd = passphrase.empty() ? nullptr : (void*)&passphrase;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
}

std::expected<void, CryptoError> nkCryptoToolBase::regeneratePublicKey(std::filesystem::path priv, std::filesystem::path pub, SecureString& pass) {
    auto pkey = loadPrivateKey(priv, pass);
    if (!pkey) return std::unexpected(pkey.error());
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_file(pub.string().c_str(), "wb"));
    if (!bio) return std::unexpected(CryptoError::PublicKeyWriteError);
    if (PEM_write_bio_PUBKEY(bio.get(), pkey->get()) <= 0) return std::unexpected(CryptoError::PublicKeyWriteError);
    return {};
}

std::expected<void, CryptoError> nkCryptoToolBase::wrapPrivateKey(std::filesystem::path raw_priv, std::filesystem::path wrapped_priv, SecureString& pass) {
    auto pkey = loadPrivateKey(raw_priv, pass);
    if (!pkey) return std::unexpected(pkey.error());
    auto wrapped = key_provider_.wrap(pkey->get(), pass);
    if (!wrapped) return std::unexpected(wrapped.error());
    if (wrapped_priv.has_parent_path()) std::filesystem::create_directories(wrapped_priv.parent_path());
    std::ofstream ofs(wrapped_priv, std::ios::binary);
    ofs.write(wrapped->data(), (std::streamsize)wrapped->size());
    return {};
}

std::expected<void, CryptoError> nkCryptoToolBase::unwrapPrivateKey(std::filesystem::path wrapped_priv, std::filesystem::path raw_priv, SecureString& pass) {
    std::ifstream ifs(wrapped_priv, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    auto pkey = key_provider_.unwrap(SecureString(pem_content.begin(), pem_content.end()), pass);
    if (!pkey) return std::unexpected(pkey.error());
    if (raw_priv.has_parent_path()) std::filesystem::create_directories(raw_priv.parent_path());
    std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_file(raw_priv.string().c_str(), "wb"));
    
    // .rawkey 拡張子の場合は、検証用などのために暗号化せずに書き出す
    if (raw_priv.extension() == ".rawkey") {
        PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey->get(), nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        if (pass.empty()) PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey->get(), nullptr, nullptr, 0, nullptr, nullptr);
        else PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey->get(), EVP_aes_256_cbc(), nullptr, 0, pem_passwd_cb, (void*)&pass);
    }
    return {};
}

std::expected<StrategyType, CryptoError> nkCryptoToolBase::detectStrategyType(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    char magic[4];
    ifs.read(magic, 4);
    if (std::memcmp(magic, "NKCT", 4) != 0 && std::memcmp(magic, "NKCS", 4) != 0) return std::unexpected(CryptoError::FileReadError);
    ifs.seekg(6);
    uint8_t type;
    ifs.read((char*)&type, 1);
    return static_cast<StrategyType>(type);
}

bool nkCryptoToolBase::isPrivateKeyEncrypted(const std::filesystem::path& path) {
    std::ifstream ifs(path);
    if (!ifs) return false;
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.find("ENCRYPTED") != std::string::npos) return true;
    }
    return false;
}

void nkCryptoToolBase::printOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
}
