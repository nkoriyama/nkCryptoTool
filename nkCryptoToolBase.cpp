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
    CompletionHandler completion_handler,
    ProgressCallback progress_callback
) {
    auto strategy = strategy_;
    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { completion_handler(ec, "Failed to get file size"); return; }

    auto prep_res = strategy->prepareEncryption(key_paths);
    if (!prep_res) { 
        completion_handler(std::make_error_code(std::errc::operation_not_permitted), "Encryption Prep Error: " + toString(prep_res.error())); 
        return; 
    }

    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec, "Failed to open output file"); return; }

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
        if (ec) { completion_handler(ec, "Header write failed"); return; }
        manager->run(input_filepath, std::move(out), 0, total_size, [completion_handler](std::error_code ec, const std::string& detail) {
            completion_handler(ec, detail);
        }, finalizer, progress_callback, total_size);
    });
}

void nkCryptoToolBase::decryptFileWithPipeline(
    asio::io_context& io_context,
    std::string input_filepath,
    std::string output_filepath,
    const std::map<std::string, std::string>& key_paths,
    SecureString& passphrase,
    CompletionHandler completion_handler,
    ProgressCallback progress_callback
) {
    auto strategy = strategy_;
    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) { completion_handler(ec, "Failed to get file size"); return; }

    size_t tag_size = strategy->getTagSize();
    if (total_size < tag_size + 8) { completion_handler(std::make_error_code(std::errc::illegal_byte_sequence), "File too small"); return; }

    std::ifstream ifs(input_filepath, std::ios::binary);
    std::vector<char> header_buf(4096); // ECC SPKI is around 1KB, PQC SPKI is up to 3KB
    ifs.read(header_buf.data(), 4096);
    auto read_bytes = ifs.gcount();
    header_buf.resize((size_t)read_bytes);
    ifs.clear();

    auto des_res = strategy->deserializeHeader(header_buf);
    if (!des_res) { 
        completion_handler(std::make_error_code(std::errc::illegal_byte_sequence), "Header Deserialization Error"); 
        return; 
    }
    size_t header_size = *des_res;

    auto prep_res = strategy->prepareDecryption(key_paths, passphrase);
    if (!prep_res) { 
        completion_handler(std::make_error_code(std::errc::operation_not_permitted), "Decryption Prep Error: " + toString(prep_res.error())); 
        return; 
    }

    async_file_t output_file(io_context);
    output_file.open(output_filepath, O_WRONLY | O_CREAT | O_TRUNC, ec);
    if (ec) { completion_handler(ec, "Failed to open output file"); return; }

    std::vector<char> tag(tag_size);
    if (total_size < tag_size) {
        completion_handler(std::make_error_code(std::errc::illegal_byte_sequence), "File too small for tag");
        return;
    }
    ifs.seekg(total_size - tag_size);
    ifs.read(tag.data(), (std::streamsize)tag_size);
    if (ifs.gcount() != (std::streamsize)tag_size) {
        completion_handler(std::make_error_code(std::errc::io_error), "Tag read failed");
        return;
    }

    auto manager = std::make_shared<PipelineManager>(io_context);
    manager->add_stage([strategy](const std::vector<char>& data) { return strategy->decryptTransform(data); });

    PipelineManager::FinalizationFunc finalizer = [strategy, tag](async_file_t&) -> asio::awaitable<void> {
        auto res = strategy->finalizeDecryption(tag);
        if (!res) throw std::runtime_error("Decryption failed: Integrity check error");
        co_return;
    };

    uintmax_t ciphertext_size = total_size - header_size - tag_size;
    manager->run(input_filepath, std::move(output_file), header_size, ciphertext_size, [completion_handler](std::error_code ec, const std::string& detail) {
        completion_handler(ec, detail);
    }, finalizer, progress_callback, total_size);
}

asio::awaitable<void> nkCryptoToolBase::signFile(asio::io_context& io_context, std::filesystem::path input_filepath, std::filesystem::path signature_filepath, std::filesystem::path signing_private_key_path, std::string digest_algo, SecureString& passphrase, ProgressCallback progress_callback) {
    auto strategy = strategy_;
    auto prep_res = strategy->prepareSigning(signing_private_key_path, passphrase, digest_algo);
    if (!prep_res) throw std::system_error(std::make_error_code(std::errc::operation_not_permitted), toString(prep_res.error()));

    std::error_code ec;
    uintmax_t total_size = std::filesystem::file_size(input_filepath, ec);
    if (ec) throw std::system_error(ec);

    PipelineManager manager(io_context);
    manager.add_stage([strategy](const std::vector<char>& data) { 
        strategy->updateHash(data);
        return std::vector<char>(); 
    });

    manager.run_sync(input_filepath.string(), "/dev/null", 0, total_size);

    auto sig_res = strategy->signHash();
    if (!sig_res) throw std::runtime_error("Signing failed");
    
    auto header = strategy->serializeSignatureHeader();
    std::ofstream ofs(signature_filepath, std::ios::binary);
    ofs.write(header.data(), (std::streamsize)header.size());
    ofs.write(sig_res->data(), (std::streamsize)sig_res->size());
    
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

    PipelineManager manager(io_context);
    manager.add_stage([strategy](const std::vector<char>& data) { 
        strategy->updateHash(data); 
        return std::vector<char>(); 
    });

    manager.run_sync(input_filepath.string(), "/dev/null", 0, total_size);

    auto ver_res = strategy->verifyHash(signature);
    if (!ver_res || !*ver_res) co_return std::unexpected(CryptoError::SignatureVerificationError);

    co_return std::expected<void, CryptoError>();
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
    char magic[4];
    if (!ifs.read(magic, 4)) return std::unexpected(CryptoError::FileReadError);
    if (std::memcmp(magic, "NKCT", 4) != 0 && std::memcmp(magic, "NKCS", 4) != 0) return std::unexpected(CryptoError::ParameterError);

    uint16_t version;
    if (!ifs.read(reinterpret_cast<char*>(&version), 2)) {
        return StrategyType::ECC;
    }
    
    if (version == 1) {
        uint8_t type;
        if (!ifs.read(reinterpret_cast<char*>(&type), 1)) return std::unexpected(CryptoError::FileReadError);
        return static_cast<StrategyType>(type);
    }

    return StrategyType::ECC;
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
