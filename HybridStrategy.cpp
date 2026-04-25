#include "HybridStrategy.hpp"
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"

namespace nk {

HybridStrategy::HybridStrategy() : 
    pqc_strategy_(std::make_unique<PQCStrategy>()),
    ecc_strategy_(std::make_unique<ECCStrategy>()) {}

HybridStrategy::~HybridStrategy() {}

std::map<std::string, std::string> HybridStrategy::getMetadata(const std::string& magic) const {
    std::map<std::string, std::string> res;
    res["Strategy"] = "Hybrid";
    if (pqc_strategy_) {
        auto pqc_meta = pqc_strategy_->getMetadata(magic);
        res.insert(pqc_meta.begin(), pqc_meta.end());
    }
    if (ecc_strategy_) {
        auto ecc_meta = ecc_strategy_->getMetadata(magic);
        res.insert(ecc_meta.begin(), ecc_meta.end());
    }
    return res;
}

size_t HybridStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 4 + ecc_strategy_->serializeHeader().size() + 4 + pqc_strategy_->serializeHeader().size();
}

size_t HybridStrategy::getTagSize() const { return 16; }

std::vector<char> HybridStrategy::serializeHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'T'});
    write_u16_le(header, 1);
    header.push_back((char)getStrategyType());

    auto ecc_h = ecc_strategy_->serializeHeader();
    write_u32_le(header, (uint32_t)ecc_h.size());
    header.insert(header.end(), ecc_h.begin(), ecc_h.end());

    auto pqc_h = pqc_strategy_->serializeHeader();
    write_u32_le(header, (uint32_t)pqc_h.size());
    header.insert(header.end(), pqc_h.begin(), pqc_h.end());

    return header;
}

std::expected<size_t, CryptoError> HybridStrategy::deserializeHeader(const std::vector<char>& data) {
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCT") return std::unexpected(CryptoError::FileReadError);
    
    size_t pos = 7;
    uint32_t ecc_len;
    if (!read_u32_le(data, pos, ecc_len)) return std::unexpected(CryptoError::FileReadError);
    if (pos + ecc_len > data.size()) return std::unexpected(CryptoError::FileReadError);
    std::vector<char> ecc_h(data.begin() + pos, data.begin() + pos + ecc_len);
    ecc_strategy_->deserializeHeader(ecc_h);
    pos += ecc_len;

    uint32_t pqc_len;
    if (!read_u32_le(data, pos, pqc_len)) return std::unexpected(CryptoError::FileReadError);
    if (pos + pqc_len > data.size()) return std::unexpected(CryptoError::FileReadError);
    std::vector<char> pqc_h(data.begin() + pos, data.begin() + pos + pqc_len);
    pqc_strategy_->deserializeHeader(pqc_h);
    pos += pqc_len;

    return pos;
}

std::expected<void, CryptoError> HybridStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::map<std::string, std::string> ecc_paths = key_paths;
    std::map<std::string, std::string> pqc_paths = key_paths;

    if (key_paths.count("public-ecdh-key")) ecc_paths["public-key"] = key_paths.at("public-ecdh-key");
    if (key_paths.count("private-ecdh-key")) ecc_paths["private-key"] = key_paths.at("private-ecdh-key");
    if (key_paths.count("public-mlkem-key")) pqc_paths["public-key"] = key_paths.at("public-mlkem-key");
    if (key_paths.count("private-mlkem-key")) pqc_paths["private-key"] = key_paths.at("private-mlkem-key");

    auto ecc_res = ecc_strategy_->generateEncryptionKeyPair(ecc_paths, passphrase);
    if (!ecc_res) return ecc_res;
    return pqc_strategy_->generateEncryptionKeyPair(pqc_paths, passphrase);
}

std::expected<void, CryptoError> HybridStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    // ハイブリッド署名鍵生成 (現在は PQC 鍵のみ生成)
    return pqc_strategy_->generateSigningKeyPair(key_paths, passphrase);
}

std::expected<void, CryptoError> HybridStrategy::regeneratePublicKey(const std::filesystem::path& priv_path, const std::filesystem::path& pub_path, SecureString& passphrase) {
    return pqc_strategy_->regeneratePublicKey(priv_path, pub_path, passphrase);
}

std::expected<void, CryptoError> HybridStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    std::map<std::string, std::string> ecc_paths = key_paths;
    std::map<std::string, std::string> pqc_paths = key_paths;

    if (key_paths.count("recipient-ecdh-pubkey")) ecc_paths["recipient-pubkey"] = key_paths.at("recipient-ecdh-pubkey");
    if (key_paths.count("recipient-mlkem-pubkey")) pqc_paths["recipient-pubkey"] = key_paths.at("recipient-mlkem-pubkey");

    auto ecc_res = ecc_strategy_->prepareEncryption(ecc_paths);
    if (!ecc_res) return ecc_res;
    auto pqc_res = pqc_strategy_->prepareEncryption(pqc_paths);
    if (!pqc_res) return pqc_res;

    auto ss_ecc = ecc_strategy_->getSharedSecret();
    auto ss_pqc = pqc_strategy_->getSharedSecret();
    
    std::vector<uint8_t> shared_secret = ss_ecc;
    shared_secret.insert(shared_secret.end(), ss_pqc.begin(), ss_pqc.end());
    
    auto salt = ecc_strategy_->getSalt();
    iv_ = ecc_strategy_->getIV();

    auto backend = nk::backend::getBackend();
    std::vector<uint8_t> salt_v(salt.begin(), salt.end());
    encryption_key_ = backend->hkdf(shared_secret, 32, salt_v, "hybrid-encryption", "SHA3-256");

    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, true);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);

    return {};
}

std::expected<void, CryptoError> HybridStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::map<std::string, std::string> ecc_paths = key_paths;
    std::map<std::string, std::string> pqc_paths = key_paths;

    if (key_paths.count("user-ecdh-privkey")) ecc_paths["user-privkey"] = key_paths.at("user-ecdh-privkey");
    if (key_paths.count("user-mlkem-privkey")) pqc_paths["user-privkey"] = key_paths.at("user-mlkem-privkey");

    // Decryption 時は AEAD の初期化を避けるため、各ストラテジーの内部状態のみを更新する必要があるが、
    // 現在の実装では prepareDecryption が AEAD まで初期化してしまう。
    // そのため、一時的に生成された AEAD ではなく、Hybrid 側で統合した shared_secret を使う。
    
    auto ecc_res = ecc_strategy_->prepareDecryption(ecc_paths, passphrase);
    if (!ecc_res) return ecc_res;
    auto pqc_res = pqc_strategy_->prepareDecryption(pqc_paths, passphrase);
    if (!pqc_res) return pqc_res;

    auto ss_ecc = ecc_strategy_->getSharedSecret();
    auto ss_pqc = pqc_strategy_->getSharedSecret();
    
    std::vector<uint8_t> shared_secret = ss_ecc;
    shared_secret.insert(shared_secret.end(), ss_pqc.begin(), ss_pqc.end());
    
    auto salt = ecc_strategy_->getSalt();
    iv_ = ecc_strategy_->getIV();

    auto backend = nk::backend::getBackend();
    std::vector<uint8_t> salt_v(salt.begin(), salt.end());
    encryption_key_ = backend->hkdf(shared_secret, 32, salt_v, "hybrid-encryption", "SHA3-256");

    auto aead = backend->createAead("AES-256-GCM", encryption_key_, iv_, false);
    if (!aead) return std::unexpected(aead.error());
    aead_ctx_ = std::move(*aead);

    return {};
}

std::vector<char> HybridStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<uint8_t> out(data.size());
    auto res = aead_ctx_->update((const uint8_t*)data.data(), data.size(), (uint8_t*)out.data());
    if (!res) return {};
    return std::vector<char>(out.begin(), out.begin() + *res);
}

std::vector<char> HybridStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<uint8_t> out(data.size());
    auto res = aead_ctx_->update((const uint8_t*)data.data(), data.size(), (uint8_t*)out.data());
    if (!res) return {};
    return std::vector<char>(out.begin(), out.begin() + *res);
}

std::expected<void, CryptoError> HybridStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<uint8_t> final_block(16);
    auto res = aead_ctx_->finalize((uint8_t*)final_block.data());
    if (!res) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> tag(16);
    auto tag_res = aead_ctx_->getTag(tag.data(), 16);
    if (!tag_res) return std::unexpected(CryptoError::OpenSSLError);
    
    out_final.assign(final_block.begin(), final_block.begin() + *res);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> HybridStrategy::finalizeDecryption(const std::vector<char>& tag) {
    auto res_tag = aead_ctx_->setTag((const uint8_t*)tag.data(), tag.size());
    if (!res_tag) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> final_block(16);
    auto res = aead_ctx_->finalize((uint8_t*)final_block.data());
    if (!res) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

std::expected<void, CryptoError> HybridStrategy::prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) {
    return pqc_strategy_->prepareSigning(priv_key_path, passphrase, digest_algo);
}

std::expected<void, CryptoError> HybridStrategy::prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) {
    return pqc_strategy_->prepareVerification(pub_key_path, digest_algo);
}

void HybridStrategy::updateHash(const std::vector<char>& data) {
    pqc_strategy_->updateHash(data);
}

std::expected<std::vector<char>, CryptoError> HybridStrategy::signHash() {
    return pqc_strategy_->signHash();
}

std::expected<bool, CryptoError> HybridStrategy::verifyHash(const std::vector<char>& signature) {
    return pqc_strategy_->verifyHash(signature);
}

std::vector<char> HybridStrategy::serializeSignatureHeader() const {
    return pqc_strategy_->serializeSignatureHeader();
}

std::expected<size_t, CryptoError> HybridStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    return pqc_strategy_->deserializeSignatureHeader(data);
}

} // namespace nk
