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
#include "nkCryptoToolUtils.hpp"

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

PQCStrategy::PQCStrategy() : cipher_ctx_(EVP_CIPHER_CTX_new()) {}
PQCStrategy::~PQCStrategy() {
    if (!shared_secret_.empty()) OPENSSL_cleanse(shared_secret_.data(), shared_secret_.size());
    if (!encryption_key_.empty()) OPENSSL_cleanse(encryption_key_.data(), encryption_key_.size());
}

std::map<std::string, std::string> PQCStrategy::getMetadata(const std::string& magic) const {
    std::map<std::string, std::string> res;
    res["Strategy"] = "PQC";
    res["KEM-Algorithm"] = kem_algo_;
    res["DSA-Algorithm"] = dsa_algo_;
    return res;
}

size_t PQCStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 
           4 + kem_algo_.size() + 
           4 + dsa_algo_.size() + 
           4 + kem_ct_.size() + 4 + salt_.size() + 4 + iv_.size();
}

size_t PQCStrategy::getTagSize() const { return 16; }

std::vector<char> PQCStrategy::serializeHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'T'});
    write_u16_le(header, 1);
    header.push_back((char)getStrategyType());

    auto add_string = [&](const std::string& s) {
        write_u32_le(header, (uint32_t)s.size());
        header.insert(header.end(), s.begin(), s.end());
    };
    auto add_vec = [&](const std::vector<unsigned char>& vec) {
        write_u32_le(header, (uint32_t)vec.size());
        header.insert(header.end(), vec.begin(), vec.end());
    };
    add_string(kem_algo_);
    add_string(dsa_algo_);
    add_vec(kem_ct_);
    add_vec(salt_);
    add_vec(iv_);
    return header;
}

std::expected<size_t, CryptoError> PQCStrategy::deserializeHeader(const std::vector<char>& data) {
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCT") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    
    uint16_t version;
    if (!read_u16_le(data, pos, version) || version != 1) return std::unexpected(CryptoError::FileReadError);
    
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    auto read_string = [&](std::string& s) -> bool {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (len > data.size() || pos > data.size() - len) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };
    auto read_vec = [&](std::vector<unsigned char>& vec) -> bool { 
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (len > data.size() || pos > data.size() - len) return false;
        vec.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };
    if (!read_string(kem_algo_) || !read_string(dsa_algo_) || 
        !read_vec(kem_ct_) || !read_vec(salt_) || !read_vec(iv_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}

std::expected<void, CryptoError> PQCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string pub, priv;
    if (key_paths.count("public-key")) {
        pub = key_paths.at("public-key");
        priv = key_paths.at("private-key");
    } else if (key_paths.count("signing-public-key")) {
        pub = key_paths.at("signing-public-key");
        priv = key_paths.at("signing-private-key");
    } else {
        return std::unexpected(CryptoError::FileCreationError);
    }

    bool use_tpm = key_paths.count("use-tpm") && key_paths.at("use-tpm") == "true";
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, kem_algo_.c_str(), nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);
    EVP_PKEY* pkey = nullptr; 
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return std::unexpected(CryptoError::KeyGenerationError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pqc_key(pkey);

    if (use_tpm) {
        auto wrapped = TPMUtils::wrapKey(pqc_key.get(), passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        std::ofstream ofs(priv, std::ios::binary);
        if (!ofs) return std::unexpected(CryptoError::FileCreationError);
        ofs.write(wrapped->data(), (std::streamsize)wrapped->size());
    } else {
        std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(priv.c_str(), "wb"));
        if (!priv_bio) return std::unexpected(CryptoError::FileCreationError);
        if (passphrase.empty()) PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pqc_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        else PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), pqc_key.get(), EVP_aes_256_cbc(), nullptr, 0, pem_passwd_cb, (void*)&passphrase);
    }
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pub.c_str(), "wb"));
    if (!pub_bio) return std::unexpected(CryptoError::FileCreationError);
    PEM_write_bio_PUBKEY(pub_bio.get(), pqc_key.get());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return generateEncryptionKeyPair(key_paths, passphrase);
}


std::expected<void, CryptoError> PQCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (!key_paths.count("recipient-pubkey")) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(key_paths.at("recipient-pubkey").c_str(), "rb"));
    if (!pub_bio) return std::unexpected(CryptoError::PublicKeyLoadError);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_pub(pkey);
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(recipient_pub.get(), nullptr));
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    size_t secret_len, ct_len;
    if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &secret_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> secret(secret_len);
    kem_ct_.resize(ct_len);
    if (EVP_PKEY_encapsulate(ctx.get(), kem_ct_.data(), &ct_len, secret.data(), &secret_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    shared_secret_ = secret;
    salt_.resize(16); iv_.resize(12); RAND_bytes(salt_.data(), 16); RAND_bytes(iv_.data(), 12);
    encryption_key_ = nkCryptoToolBase::hkdfDerive(secret, 32, std::string(salt_.begin(), salt_.end()), "pqc-encryption", "SHA3-256");
    
    if (!cipher_ctx_) cipher_ctx_.reset(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv_.size(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_EncryptInit_ex(cipher_ctx_.get(), nullptr, nullptr, encryption_key_.data(), iv_.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::vector<char> PQCStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    EVP_EncryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size());
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> PQCStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    int final_len = 0;
    EVP_EncryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len);
    std::vector<unsigned char> tag(16);
    EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    out_final.assign(final_block.begin(), final_block.begin() + final_len);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    const std::string& priv_key_path = key_paths.at("user-privkey");
    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto unwrapped = TPMUtils::unwrapKey(SecureString(pem_content.begin(), pem_content.end()), passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        encryption_priv_key_ = std::move(*unwrapped);
    } else {
        encryption_priv_key_.reset();
        std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
        void* pwd = passphrase.empty() ? nullptr : (void*)&passphrase;
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        encryption_priv_key_.reset(pkey);
    }

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(encryption_priv_key_.get(), nullptr));
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    size_t secret_len;
    EVP_PKEY_decapsulate(ctx.get(), nullptr, &secret_len, kem_ct_.data(), kem_ct_.size());
    std::vector<unsigned char> secret(secret_len);
    if (EVP_PKEY_decapsulate(ctx.get(), secret.data(), &secret_len, kem_ct_.data(), kem_ct_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    shared_secret_ = secret;
    encryption_key_ = nkCryptoToolBase::hkdfDerive(secret, 32, std::string(salt_.begin(), salt_.end()), "pqc-encryption", "SHA3-256");
    
    cipher_ctx_.reset(EVP_CIPHER_CTX_new());
    if (EVP_DecryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv_.size(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_DecryptInit_ex(cipher_ctx_.get(), nullptr, nullptr, encryption_key_.data(), iv_.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::vector<char> PQCStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    EVP_DecryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size());
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> PQCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    int final_len = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len) <= 0) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

std::expected<void, CryptoError> PQCStrategy::prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) {
    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> pkey_ptr;
    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto unwrapped = TPMUtils::unwrapKey(SecureString(pem_content.begin(), pem_content.end()), passphrase);
        if (!unwrapped) return std::unexpected(unwrapped.error());
        pkey_ptr = std::move(*unwrapped);
    } else {
        std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
        void* pwd = passphrase.empty() ? nullptr : (void*)&passphrase;
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
    return {};
}

void PQCStrategy::updateHash(const std::vector<char>& data) {
    message_buffer_.insert(message_buffer_.end(), data.begin(), data.end());
}

std::expected<std::vector<char>, CryptoError> PQCStrategy::signHash() {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(sign_key_.get(), nullptr));
    if (!ctx || EVP_PKEY_sign_init(ctx.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    size_t sig_len;
    EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, (const unsigned char*)message_buffer_.data(), message_buffer_.size());
    std::vector<unsigned char> sig(sig_len);
    if (EVP_PKEY_sign(ctx.get(), sig.data(), &sig_len, (const unsigned char*)message_buffer_.data(), message_buffer_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    message_buffer_.clear();
    return std::vector<char>(sig.begin(), sig.end());
}

std::expected<bool, CryptoError> PQCStrategy::verifyHash(const std::vector<char>& signature) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(verify_key_.get(), nullptr));
    if (!ctx || EVP_PKEY_verify_init(ctx.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    int res = EVP_PKEY_verify(ctx.get(), (const unsigned char*)signature.data(), signature.size(), (const unsigned char*)message_buffer_.data(), message_buffer_.size());
    message_buffer_.clear();
    if (res == 1) return true;
    if (res == 0) return false;
    return std::unexpected(CryptoError::OpenSSLError);
}

std::vector<char> PQCStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    uint16_t version = 1;
    header.insert(header.end(), (char*)&version, (char*)&version + 2);
    header.push_back((char)getStrategyType());
    auto add_string = [&](const std::string& s) {
        uint32_t len = (uint32_t)s.size();
        header.insert(header.end(), (char*)&len, (char*)&len + 4);
        header.insert(header.end(), s.begin(), s.end());
    };
    add_string(kem_algo_);
    add_string(dsa_algo_);
    return header;
}

std::expected<size_t, CryptoError> PQCStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCS") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    uint16_t version; memcpy(&version, &data[pos], 2); pos += 2;
    if (version != 1) return std::unexpected(CryptoError::FileReadError);
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    auto read_string = [&](std::string& s) -> bool {
        if (pos + 4 > data.size()) return false;
        uint32_t len; memcpy(&len, &data[pos], 4); pos += 4;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len); pos += len;
        return true;
    };
    if (!read_string(kem_algo_) || !read_string(dsa_algo_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}
