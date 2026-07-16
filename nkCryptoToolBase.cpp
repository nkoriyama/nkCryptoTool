/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkCryptoToolBase.hpp"
#include "nkV3Format.hpp"
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

    // NKCT v3 (ChunkedAead): every chunk is independently authenticated
    // (ciphertext || 16-byte tag), so the write path is a simple synchronous
    // lookahead loop — the last chunk (possibly zero-length) is sealed with
    // FLAG_FINAL so truncation at a chunk boundary is detectable.
    auto header = strategy->serializeHeader();
    auto sid = nk::v3::sessionId(header);
    if (!sid) { completion_handler(std::make_error_code(std::errc::operation_not_permitted), "v3 session id failed"); return; }
    const uint32_t chunk_size = strategy->v3ChunkSize() ? strategy->v3ChunkSize() : nk::v3::DEFAULT_CHUNK_SIZE;
    const auto key = strategy->v3Key();
    const auto prefix = strategy->v3NoncePrefix();
    const auto aead_algo = strategy->aeadAlgoName();
    if (key.empty() || prefix.size() != nk::v3::NONCE_PREFIX_LEN) {
        completion_handler(std::make_error_code(std::errc::operation_not_permitted), "v3 key material missing");
        return;
    }

    std::ifstream in(input_filepath, std::ios::binary);
    if (!in) { completion_handler(std::make_error_code(std::errc::no_such_file_or_directory), "Failed to open input file"); return; }
    std::ofstream out(output_filepath, std::ios::binary | std::ios::trunc);
    if (!out) { completion_handler(std::make_error_code(std::errc::permission_denied), "Failed to open output file"); return; }
    out.write(header.data(), (std::streamsize)header.size());

    std::vector<char> cur(chunk_size), nxt(chunk_size);
    auto fill = [&](std::vector<char>& buf) -> size_t {
        in.read(buf.data(), (std::streamsize)buf.size());
        return (size_t)in.gcount();
    };

    uint32_t counter = 0;
    uintmax_t processed = 0;
    size_t cur_len = fill(cur);
    for (;;) {
        size_t nxt_len = fill(nxt);
        const bool is_final = (nxt_len == 0);
        if (counter == UINT32_MAX && !is_final) {
            completion_handler(std::make_error_code(std::errc::value_too_large), "v3 chunk counter overflow");
            return;
        }
        auto sealed = nk::v3::sealChunk(aead_algo, key, prefix, *sid, counter,
                                        cur.data(), cur_len, is_final);
        if (!sealed) { completion_handler(std::make_error_code(std::errc::operation_not_permitted), "v3 chunk encryption failed"); return; }
        out.write(sealed->data(), (std::streamsize)sealed->size());
        if (!out) { completion_handler(std::make_error_code(std::errc::io_error), "Ciphertext write failed"); return; }
        counter++;
        processed += cur_len;
        if (progress_callback && total_size > 0) progress_callback((double)processed / (double)total_size);
        if (is_final) break;
        std::swap(cur, nxt);
        cur_len = nxt_len;
    }
    out.flush();
    if (!out) { completion_handler(std::make_error_code(std::errc::io_error), "Ciphertext write failed"); return; }
    completion_handler({}, "");
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

    if (strategy->formatVersion() >= 3) {
        // NKCT v3 (ChunkedAead), two-pass decrypt (THREAT 37-1): pass 1
        // authenticates every chunk without writing anything; only after the
        // whole file verified does pass 2 re-decrypt and write plaintext, to a
        // temp file that is atomically renamed into place. The last wire chunk
        // must carry FLAG_FINAL (enforced by its AAD) — a file truncated at a
        // chunk boundary fails authentication in pass 1.
        std::vector<char> exact_header(header_buf.begin(), header_buf.begin() + (std::streamsize)header_size);
        auto sid = nk::v3::sessionId(exact_header);
        if (!sid) { completion_handler(std::make_error_code(std::errc::operation_not_permitted), "v3 session id failed"); return; }
        const uint32_t chunk_size = strategy->v3ChunkSize();
        const auto key = strategy->v3Key();
        const auto prefix = strategy->v3NoncePrefix();
        const auto aead_algo = strategy->aeadAlgoName();
        if (chunk_size == 0 || key.empty() || prefix.size() != nk::v3::NONCE_PREFIX_LEN) {
            completion_handler(std::make_error_code(std::errc::operation_not_permitted), "v3 key material missing");
            return;
        }
        const uintmax_t body_size = total_size - header_size;
        const uintmax_t max_wire = (uintmax_t)chunk_size + nk::v3::TAG_LEN;

        auto run_pass = [&](bool verify_only, std::ofstream* out) -> std::error_code {
            std::ifstream in(input_filepath, std::ios::binary);
            if (!in) return std::make_error_code(std::errc::no_such_file_or_directory);
            in.seekg((std::streamoff)header_size);
            std::vector<char> buf((size_t)max_wire);
            uintmax_t remaining = body_size;
            uint32_t counter = 0;
            bool final_seen = false;
            while (remaining > 0) {
                const size_t to_read = (size_t)std::min<uintmax_t>(remaining, max_wire);
                in.read(buf.data(), (std::streamsize)to_read);
                if ((size_t)in.gcount() != to_read) return std::make_error_code(std::errc::io_error);
                remaining -= to_read;
                const bool is_final = (remaining == 0);
                if (!is_final && to_read != (size_t)max_wire) return std::make_error_code(std::errc::illegal_byte_sequence);
                if (to_read < nk::v3::TAG_LEN) return std::make_error_code(std::errc::illegal_byte_sequence);
                auto pt = nk::v3::openChunk(aead_algo, key, prefix, *sid, counter,
                                            buf.data(), to_read, is_final);
                if (!pt) return std::make_error_code(std::errc::illegal_byte_sequence);
                if (is_final) final_seen = true;
                if (out) {
                    out->write(pt->data(), (std::streamsize)pt->size());
                    if (!*out) return std::make_error_code(std::errc::io_error);
                }
                counter++;
            }
            if (!final_seen) return std::make_error_code(std::errc::illegal_byte_sequence);
            (void)verify_only;
            return {};
        };

        // Pass 1: verify only. Nothing is created at the destination yet.
        if (auto e = run_pass(true, nullptr)) {
            completion_handler(e, "Decryption failed: Integrity check error");
            return;
        }
        // Pass 2: write via temp file + atomic rename.
        std::string tmp_path = output_filepath + ".nkct-tmp";
        {
            std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
            if (!out) { completion_handler(std::make_error_code(std::errc::permission_denied), "Failed to open output file"); return; }
            if (auto e = run_pass(false, &out)) {
                out.close();
                std::error_code rmec;
                std::filesystem::remove(tmp_path, rmec);
                completion_handler(e, "Decryption failed: Integrity check error");
                return;
            }
            out.flush();
            if (!out) {
                std::error_code rmec;
                std::filesystem::remove(tmp_path, rmec);
                completion_handler(std::make_error_code(std::errc::io_error), "Plaintext write failed");
                return;
            }
        }
        std::error_code ren_ec;
        std::filesystem::rename(tmp_path, output_filepath, ren_ec);
        if (ren_ec) {
            std::error_code rmec;
            std::filesystem::remove(tmp_path, rmec);
            completion_handler(ren_ec, "Output rename failed");
            return;
        }
        if (progress_callback) progress_callback(1.0);
        completion_handler({}, "");
        return;
    }

    // Legacy v1/v2: single streaming AEAD with one trailing tag.
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

std::expected<void, CryptoError> nkCryptoToolBase::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase, bool force) {
    return strategy_->generateEncryptionKeyPair(key_paths, passphrase, force);
}

std::expected<void, CryptoError> nkCryptoToolBase::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase, bool force) {
    return strategy_->generateSigningKeyPair(key_paths, passphrase, force);
}

std::expected<void, CryptoError> nkCryptoToolBase::regeneratePublicKey(std::filesystem::path priv, std::filesystem::path pub, SecureString& pass, bool force) {
    return strategy_->regeneratePublicKey(priv, pub, pass, force);
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
    
    if (version >= 1 && version <= 3) {
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
