#include "PQCStrategy.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <stdexcept>
#include <cstring>
#include <iostream>
#include <fstream>
#include "nkCryptoToolBase.hpp"
#include "TPMUtils.hpp"

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

PQCStrategy::PQCStrategy() : cipher_ctx_(EVP_CIPHER_CTX_new()), md_ctx_(EVP_MD_CTX_new()) {}
PQCStrategy::~PQCStrategy() {}

size_t PQCStrategy::getHeaderSize() const { return 4 + encapsulated_key_.size() + 4 + salt_.size() + 4 + iv_.size(); }
size_t PQCStrategy::getTagSize() const { return 16; }

std::vector<char> PQCStrategy::serializeHeader() const {
    std::vector<char> header;
    auto add_vec = [&](const std::vector<unsigned char>& vec) {
        uint32_t len = (uint32_t)vec.size();
        header.insert(header.end(), (char*)&len, (char*)&len + 4);
        header.insert(header.end(), vec.begin(), vec.end());
    };
    add_vec(encapsulated_key_); add_vec(salt_); add_vec(iv_);
    return header;
}

std::expected<void, CryptoError> PQCStrategy::deserializeHeader(const std::vector<char>& data) {
    size_t pos = 0;
    auto read_vec = [&](std::vector<unsigned char>& vec) -> bool { 
        if (pos + 4 > data.size()) return false; 
        uint32_t len; memcpy(&len, &data[pos], 4); pos += 4; 
        if (pos + len > data.size()) return false; 
        vec.assign(data.begin() + pos, data.begin() + pos + len); pos += len; 
        return true;
    };
    if (!read_vec(encapsulated_key_) || !read_vec(salt_) || !read_vec(iv_)) return std::unexpected(CryptoError::FileReadError);
    return {};
}

std::expected<void, CryptoError> PQCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    if (key_paths.count("public-key") == 0 || key_paths.count("private-key") == 0) return std::unexpected(CryptoError::FileCreationError);
    const auto& pub_path = key_paths.at("public-key");
    const auto& priv_path = key_paths.at("private-key");
    
    std::string algo = "ML-KEM-1024";
    if (key_paths.count("pqc-kem-algo")) algo = key_paths.at("pqc-kem-algo");
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, algo.c_str(), nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return std::unexpected(CryptoError::KeyGenerationError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> kem_key(pkey);
    
    bool use_tpm = key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true";
    
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(priv_path.c_str(), "wb"));
    if (!priv_bio) return std::unexpected(CryptoError::FileCreationError);
    
    if (use_tpm) {
        auto wrapped = TPMUtils::wrapKey(kem_key.get(), passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        BIO_write(priv_bio.get(), wrapped->data(), (int)wrapped->size());
    } else if (passphrase.empty()) {
        if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), nullptr, nullptr, 0, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::PrivateKeyWriteError);
    } else {
        if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), kem_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), (int)passphrase.length(), nullptr, nullptr) <= 0) return std::unexpected(CryptoError::PrivateKeyWriteError);
    }
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pub_path.c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), kem_key.get()) <= 0) return std::unexpected(CryptoError::PublicKeyWriteError);
    
    return {};
}

std::expected<void, CryptoError> PQCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    if (key_paths.count("public-key") == 0 || key_paths.count("private-key") == 0) return std::unexpected(CryptoError::FileCreationError);
    const auto& pub_path = key_paths.at("public-key");
    const auto& priv_path = key_paths.at("private-key");
    
    std::string algo = "ML-DSA-87";
    if (key_paths.count("pqc-dsa-algo")) algo = key_paths.at("pqc-dsa-algo");
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, algo.c_str(), nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);
    
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return std::unexpected(CryptoError::KeyGenerationError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> dsa_key(pkey);
    
    bool use_tpm = key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true";
    
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(priv_path.c_str(), "wb"));
    if (!priv_bio) return std::unexpected(CryptoError::FileCreationError);
    
    if (use_tpm) {
        auto wrapped = TPMUtils::wrapKey(dsa_key.get(), passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        BIO_write(priv_bio.get(), wrapped->data(), (int)wrapped->size());
    } else if (passphrase.empty()) {
        if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), nullptr, nullptr, 0, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::PrivateKeyWriteError);
    } else {
        if (PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), dsa_key.get(), EVP_aes_256_cbc(), (const char*)passphrase.c_str(), (int)passphrase.length(), nullptr, nullptr) <= 0) return std::unexpected(CryptoError::PrivateKeyWriteError);
    }
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pub_path.c_str(), "wb"));
    if (!pub_bio || PEM_write_bio_PUBKEY(pub_bio.get(), dsa_key.get()) <= 0) return std::unexpected(CryptoError::PublicKeyWriteError);
    
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (!key_paths.count("recipient-pubkey")) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(key_paths.at("recipient-pubkey").c_str(), "rb"));
    if (!pub_bio) return std::unexpected(CryptoError::PublicKeyLoadError);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_pub(pkey);
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(recipient_pub.get(), nullptr));
    if (!kem_ctx || EVP_PKEY_encapsulate_init(kem_ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    size_t slen, elen; EVP_PKEY_encapsulate(kem_ctx.get(), nullptr, &elen, nullptr, &slen);
    std::vector<unsigned char> secret(slen); encapsulated_key_.resize(elen);
    EVP_PKEY_encapsulate(kem_ctx.get(), encapsulated_key_.data(), &elen, secret.data(), &slen);
    salt_.resize(16); iv_.resize(12); RAND_bytes(salt_.data(), 16); RAND_bytes(iv_.data(), 12);
    encryption_key_ = nkCryptoToolBase::hkdfDerive(secret, 32, std::string(salt_.begin(), salt_.end()), "pqc-encryption", "SHA3-256");
    if (!cipher_ctx_ || EVP_EncryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, encryption_key_.data(), iv_.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, std::string& passphrase) {
    if (!key_paths.count("user-privkey")) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string priv_path = key_paths.at("user-privkey");
    std::ifstream ifs(priv_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    
    encryption_priv_key_.reset();
    if (pem_content.find(TPMUtils::TPM_WRAPPED_HEADER) != std::string::npos || pem_content.find(TPMUtils::TPM_WRAPPED_ENC_HEADER) != std::string::npos) {
        auto unwrapped = TPMUtils::unwrapKey(pem_content, passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        encryption_priv_key_ = std::move(*unwrapped);
    } else {
        std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
        void* pwd = passphrase.empty() ? nullptr : (void*)passphrase.c_str();
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        encryption_priv_key_.reset(pkey);
    }
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> kem_ctx(EVP_PKEY_CTX_new(encryption_priv_key_.get(), nullptr));
    if (!kem_ctx || EVP_PKEY_decapsulate_init(kem_ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    size_t slen; 
    if (EVP_PKEY_decapsulate(kem_ctx.get(), nullptr, &slen, encapsulated_key_.data(), encapsulated_key_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> secret(slen);
    if (EVP_PKEY_decapsulate(kem_ctx.get(), secret.data(), &slen, encapsulated_key_.data(), encapsulated_key_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    encryption_key_ = nkCryptoToolBase::hkdfDerive(secret, 32, std::string(salt_.begin(), salt_.end()), "pqc-encryption", "SHA3-256");
    if (!cipher_ctx_ || EVP_DecryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, encryption_key_.data(), iv_.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    decrypt_buffer_.clear();
    return {};
}

std::vector<char> PQCStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + 16);
    int out_len = 0;
    if (EVP_EncryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size()) <= 0) throw std::runtime_error("Encryption update failed");
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::vector<char> PQCStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + 16);
    int out_len = 0;
    if (EVP_DecryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size()) <= 0) throw std::runtime_error("Decryption update failed");
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> PQCStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<unsigned char> final_block(16);
    int final_len = 0;
    if (EVP_EncryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> tag(16);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    out_final.assign(final_block.begin(), final_block.begin() + final_len);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> final_block(16);
    int final_len = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len) <= 0) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareSigning(const std::filesystem::path& priv_key_path, std::string& passphrase, const std::string& digest_algo) {
    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey_ptr;
    if (pem_content.find(TPMUtils::TPM_WRAPPED_HEADER) != std::string::npos || pem_content.find(TPMUtils::TPM_WRAPPED_ENC_HEADER) != std::string::npos) {
        auto unwrapped = TPMUtils::unwrapKey(pem_content, passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        pkey_ptr = std::move(*unwrapped);
    } else {
        std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
        void* pwd = passphrase.empty() ? nullptr : (void*)passphrase.c_str();
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        pkey_ptr.reset(pkey);
    }
    
    sign_key_.reset(pkey_ptr.release());
    message_buffer_.clear();
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) {
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pub_key_path.string().c_str(), "rb"));
    if (!pub_bio) return std::unexpected(CryptoError::PublicKeyLoadError);
    verify_key_.reset(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
    if (!verify_key_) return std::unexpected(CryptoError::PublicKeyLoadError);
    message_buffer_.clear();
    return {};
}

void PQCStrategy::updateHash(const std::vector<char>& data) {
    message_buffer_.insert(message_buffer_.end(), data.begin(), data.end());
}

std::expected<std::vector<char>, CryptoError> PQCStrategy::signHash() {
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> s_ctx(EVP_MD_CTX_new());
    if (EVP_DigestSignInit(s_ctx.get(), nullptr, nullptr, nullptr, sign_key_.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    size_t sig_len = 0;
    if (EVP_DigestSign(s_ctx.get(), nullptr, &sig_len, (const unsigned char*)message_buffer_.data(), message_buffer_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<char> sig(sig_len);
    if (EVP_DigestSign(s_ctx.get(), (unsigned char*)sig.data(), &sig_len, (const unsigned char*)message_buffer_.data(), message_buffer_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    sig.resize(sig_len);
    return sig;
}

std::expected<bool, CryptoError> PQCStrategy::verifyHash(const std::vector<char>& signature) {
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> v_ctx(EVP_MD_CTX_new());
    if (EVP_DigestVerifyInit(v_ctx.get(), nullptr, nullptr, nullptr, verify_key_.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    int res = EVP_DigestVerify(v_ctx.get(), (const unsigned char*)signature.data(), signature.size(), (const unsigned char*)message_buffer_.data(), message_buffer_.size());
    if (res == 1) return true;
    if (res == 0) return false;
    return std::unexpected(CryptoError::OpenSSLError);
}
