/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkCryptoToolBase.hpp"
#include "PipelineManager.hpp"
#include "CryptoConfig.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <asio.hpp>
#include <future>

nkCryptoToolBase::nkCryptoToolBase(std::shared_ptr<ICryptoStrategy> strategy) : strategy_(strategy) {}
nkCryptoToolBase::~nkCryptoToolBase() = default;

void nkCryptoToolBase::setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider) {
    key_provider_.setProvider(provider);
}

void nkCryptoToolBase::setKeyBaseDirectory(std::filesystem::path dir) {
    key_base_directory = dir;
}

std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const {
    return key_base_directory;
}

void nkCryptoToolBase::encryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback
) {
    auto strategy = strategy_;
    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { completion_handler(ec); return; }

    auto prep_res = strategy->prepareEncryption(key_paths);
    if (!prep_res) { 
        std::cerr << "Encryption Prep Error: " << toString(prep_res.error()) << std::endl;
        completion_handler(std::make_error_code(std::errc::operation_not_permitted)); 
        return; 
    }

    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec); return; }

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { return strategy->encryptTransform(data); });

    PipelineManager::FinalizationFunc finalizer = [strategy](async_file_t& out) -> asio::awaitable<void> {
        std::vector<char> tag;
        auto res = strategy->finalizeEncryption(tag);
        if (!res) throw std::runtime_error("Encryption failed: Finalization error");
        co_await asio::async_write(out.get(), asio::buffer(tag), asio::use_awaitable);
        co_return;
    };

    auto header = strategy->serializeHeader();
    auto& descriptor = output_file.get();
    asio::async_write(descriptor, asio::buffer(header), [manager, input_filepath, out = std::move(output_file), total_size, completion_handler, progress_callback, finalizer](std::error_code ec, std::size_t) mutable {
        if (ec) { completion_handler(ec); return; }
        manager->run(input_filepath, std::move(out), 0, total_size, completion_handler, finalizer, progress_callback, total_size);
    });
}

void nkCryptoToolBase::decryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    SecureString& passphrase,
    std::function<void(std::error_code)> completion_handler,
    ProgressCallback progress_callback
) {
    auto strategy = strategy_;
    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { completion_handler(ec); return; }

    size_t tag_size = strategy->getTagSize();
    if (total_size < tag_size + 8) { completion_handler(std::make_error_code(std::errc::illegal_byte_sequence)); return; }

    std::ifstream ifs(input_filepath, std::ios::binary);
    std::vector<char> header_buf(2048);
    ifs.read(header_buf.data(), 2048);
    auto read_bytes = ifs.gcount();
    header_buf.resize((size_t)read_bytes);
    ifs.clear(); // Clear eof/fail bits if file was smaller than 2048

    auto des_res = strategy->deserializeHeader(header_buf);
    if (!des_res) { 
        std::cerr << "Header Deserialization Error" << std::endl;
        completion_handler(std::make_error_code(std::errc::illegal_byte_sequence)); 
        return; 
    }
    size_t header_size = *des_res;

    auto prep_res = strategy->prepareDecryption(key_paths, passphrase);
    if (!prep_res) { 
        std::cerr << "Decryption Prep Error: " << toString(prep_res.error()) << std::endl;
        completion_handler(std::make_error_code(std::errc::operation_not_permitted)); 
        return; 
    }

    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec); return; }

    std::vector<char> tag(tag_size);
    ifs.seekg(total_size - tag_size);
    ifs.read(tag.data(), (std::streamsize)tag_size);
    if (ifs.gcount() != (std::streamsize)tag_size) { completion_handler(std::make_error_code(std::errc::io_error)); return; }

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { return strategy->decryptTransform(data); });

    PipelineManager::FinalizationFunc finalizer = [strategy, tag](async_file_t&) -> asio::awaitable<void> {
        auto res = strategy->finalizeDecryption(tag);
        if (!res) throw std::runtime_error("Decryption failed: Integrity check error");
        co_return;
    };

    uintmax_t ciphertext_size = total_size - header_size - tag_size;
    manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, completion_handler, finalizer, progress_callback, total_size);
}

asio::awaitable<void> nkCryptoToolBase::signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, SecureString& passphrase, ProgressCallback progress_callback) {
    auto strategy = strategy_;
    auto prep_res = strategy->prepareSigning(signing_private_key_path, passphrase, digest_algo);
    if (!prep_res) throw std::system_error(std::make_error_code(std::errc::operation_not_permitted), toString(prep_res.error()));

    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) throw std::system_error(ec);

    async_file_t input_file(io_context);
    input_file.open(input_filepath, O_RDONLY, ec);
    if (ec) throw std::system_error(ec);

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { 
        strategy->updateHash(data);
        return data; 
    });

    auto self_strategy = strategy_;
    PipelineManager::FinalizationFunc finalizer = [self_strategy, signature_filepath](async_file_t&) -> asio::awaitable<void> {
        auto sig_res = self_strategy->signHash();
        if (!sig_res) throw std::runtime_error("Signing failed");
        
        auto header = self_strategy->serializeSignatureHeader();
        std::ofstream ofs(signature_filepath, std::ios::binary);
        ofs.write(header.data(), (std::streamsize)header.size());
        ofs.write(sig_res->data(), (std::streamsize)sig_res->size());
        co_return;
    };

    std::promise<void> promise;
    manager->run(input_filepath.string(), async_file_t(io_context), 0, total_size, [&promise](std::error_code ec) {
        if (ec) promise.set_exception(std::make_exception_ptr(std::system_error(ec)));
        else promise.set_value();
    }, finalizer, progress_callback, total_size);
    
    co_return;
}

asio::awaitable<std::expected<void, CryptoError>> nkCryptoToolBase::verifySignature(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_public_key_path, std::string digest_algo, ProgressCallback progress_callback) {
    auto strategy = strategy_;
    auto prep_res = strategy->prepareVerification(signing_public_key_path, digest_algo);
    if (!prep_res) co_return std::unexpected(prep_res.error());

    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) co_return std::unexpected(CryptoError::FileReadError);

    uintmax_t sig_size = std::filesystem::file_size(signature_filepath, ec);
    if (ec) co_return std::unexpected(CryptoError::FileReadError);

    std::vector<char> sig_data(sig_size);
    std::ifstream ifs(signature_filepath, std::ios::binary);
    ifs.read(sig_data.data(), (std::streamsize)sig_size);
    
    auto header_size_res = strategy->deserializeSignatureHeader(sig_data);
    if (!header_size_res) co_return std::unexpected(CryptoError::ParameterError);
    std::vector<char> signature(sig_data.begin() + *header_size_res, sig_data.end());

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { strategy->updateHash(data); return data; });

    std::promise<std::expected<void, CryptoError>> promise;
    auto finalizer = [strategy, signature](async_file_t&) -> asio::awaitable<void> {
        auto ver_res = strategy->verifyHash(signature);
        if (!ver_res || !*ver_res) throw std::runtime_error("Signature verification failed");
        co_return;
    };

    manager->run(input_filepath.string(), async_file_t(io_context), 0, total_size, [&promise](std::error_code ec) {
        if (ec) promise.set_value(std::unexpected(CryptoError::OpenSSLError));
        else promise.set_value({});
    }, finalizer, progress_callback, total_size);

    co_return promise.get_future().get();
}

asio::awaitable<std::expected<std::map<std::string, std::string>, CryptoError>> nkCryptoToolBase::inspectFile(asio::io_context&, std::filesystem::path input_filepath, ProgressCallback) { 
    co_return strategy_->getMetadata(input_filepath.string()); 
}

std::expected<void, CryptoError> nkCryptoToolBase::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return strategy_->generateEncryptionKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> nkCryptoToolBase::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return strategy_->generateSigningKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> nkCryptoToolBase::regeneratePublicKey(std::filesystem::path priv, std::filesystem::path pub, SecureString& pass) {
    return strategy_->regeneratePublicKey(priv, pub, pass);
}

std::expected<void, CryptoError> nkCryptoToolBase::wrapPrivateKey(std::filesystem::path raw_priv, std::filesystem::path wrapped_priv, SecureString& pass) {
    return key_provider_.wrapPrivateKey(raw_priv, wrapped_priv, pass);
}

std::expected<void, CryptoError> nkCryptoToolBase::unwrapPrivateKey(std::filesystem::path wrapped_priv, std::filesystem::path raw_priv, SecureString& pass) {
    return key_provider_.unwrapPrivateKey(wrapped_priv, raw_priv, pass);
}

std::expected<StrategyType, CryptoError> nkCryptoToolBase::detectStrategyType(const std::filesystem::path& path) {
    std::ifstream ifs(path, std::ios::binary);
    char header[4];
    if (!ifs.read(header, 4)) return std::unexpected(CryptoError::FileReadError);
    if (std::memcmp(header, "NKCT", 4) == 0) return StrategyType::ECC;
    if (std::memcmp(header, "NKCS", 4) == 0) return StrategyType::ECC;
    return std::unexpected(CryptoError::ParameterError);
}

bool nkCryptoToolBase::isPrivateKeyEncrypted(const std::filesystem::path& path) {
    std::ifstream ifs(path);
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.find("ENCRYPTED") != std::string::npos) return true;
    }
    return false;
}

void nkCryptoToolBase::printErrors() {}

std::expected<std::vector<uint8_t>, CryptoError> nkCryptoToolBase::loadPrivateKey(std::filesystem::path path, SecureString& passphrase) {
    return key_provider_.loadPrivateKey(path, passphrase);
}
