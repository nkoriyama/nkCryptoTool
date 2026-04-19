#include "ECCStrategy.hpp"
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
#include "TPMConstants.hpp"
#include "nkCryptoToolUtils.hpp"

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

ECCStrategy::ECCStrategy() : cipher_ctx_(EVP_CIPHER_CTX_new()), md_ctx_(EVP_MD_CTX_new()) {}
ECCStrategy::~ECCStrategy() {
    if (!shared_secret_.empty()) OPENSSL_cleanse(shared_secret_.data(), shared_secret_.size());
    if (!encryption_key_.empty()) OPENSSL_cleanse(encryption_key_.data(), encryption_key_.size());
    if (!decrypt_buffer_.empty()) OPENSSL_cleanse(decrypt_buffer_.data(), decrypt_buffer_.size());
    if (!tpm_digest_buffer_.empty()) OPENSSL_cleanse(tpm_digest_buffer_.data(), tpm_digest_buffer_.size());
}

std::map<std::string, std::string> ECCStrategy::getMetadata(const std::string& magic) const {
    std::map<std::string, std::string> res;
    res["Strategy"] = "ECC";
    if (magic == "NKCS") {
        res["File-Type"] = "Signature";
    } else {
        res["File-Type"] = "Encrypted";
    }
    res["Curve-Name"] = curve_name_;
    res["Digest-Algorithm"] = digest_algo_;
    return res;
}

size_t ECCStrategy::getHeaderSize() const {
    return 4 + 2 + 1 + 
           4 + curve_name_.size() + 
           4 + digest_algo_.size() + 
           4 + ephemeral_pubkey_.size() + 4 + salt_.size() + 4 + iv_.size();
}

size_t ECCStrategy::getTagSize() const { return 16; }

std::vector<char> ECCStrategy::serializeHeader() const {
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
    add_string(curve_name_);
    add_string(digest_algo_);
    add_vec(ephemeral_pubkey_);
    add_vec(salt_);
    add_vec(iv_);
    return header;
}

std::expected<size_t, CryptoError> ECCStrategy::deserializeHeader(const std::vector<char>& data) {
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
    if (!read_string(curve_name_) || !read_string(digest_algo_) || 
        !read_vec(ephemeral_pubkey_) || !read_vec(salt_) || !read_vec(iv_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}

std::expected<void, CryptoError> ECCStrategy::generateEncryptionKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
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
    
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ec_key;
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)curve_name_.c_str(), 0), OSSL_PARAM_construct_end() };
    EVP_PKEY_CTX_set_params(pctx.get(), params);
    EVP_PKEY* pkey = nullptr; 
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return std::unexpected(CryptoError::KeyGenerationError);
    ec_key.reset(pkey);

    if (use_tpm) {
        auto wrapped = key_provider_.wrap(ec_key.get(), passphrase);
        if (!wrapped) return std::unexpected(wrapped.error());
        std::ofstream ofs(priv, std::ios::binary);
        if (!ofs) return std::unexpected(CryptoError::FileCreationError);
        ofs.write(wrapped->data(), (std::streamsize)wrapped->size());
    } else {
        std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(priv.c_str(), "wb"));
        if (!priv_bio) return std::unexpected(CryptoError::FileCreationError);
        if (passphrase.empty()) PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
        else PEM_write_bio_PKCS8PrivateKey(priv_bio.get(), ec_key.get(), EVP_aes_256_cbc(), nullptr, 0, pem_passwd_cb, (void*)&passphrase);
    }
    
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pub.c_str(), "wb"));
    if (!pub_bio) return std::unexpected(CryptoError::FileCreationError);
    PEM_write_bio_PUBKEY(pub_bio.get(), ec_key.get());
    return {};
}

std::expected<void, CryptoError> ECCStrategy::generateSigningKeyPair(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    return generateEncryptionKeyPair(key_paths, passphrase);
}


std::expected<void, CryptoError> ECCStrategy::prepareEncryption(const std::map<std::string, std::string>& key_paths) {
    if (key_paths.count("digest-algo")) digest_algo_ = key_paths.at("digest-algo");
    
    std::string pubkey_path;
    if (key_paths.count("recipient-pubkey")) pubkey_path = key_paths.at("recipient-pubkey");
    else if (key_paths.count("recipient-ecdh-pubkey")) pubkey_path = key_paths.at("recipient-ecdh-pubkey");
    else return std::unexpected(CryptoError::PublicKeyLoadError);

    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pubkey_path.c_str(), "rb"));
    if (!pub_bio) return std::unexpected(CryptoError::PublicKeyLoadError);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> recipient_pub(pkey);
    
    char name[128];
    if (EVP_PKEY_get_group_name(recipient_pub.get(), name, sizeof(name), nullptr) > 0) curve_name_ = name;

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)curve_name_.c_str(), 0), OSSL_PARAM_construct_end() };
    EVP_PKEY_CTX_set_params(pctx.get(), params);
    
    EVP_PKEY* epkey = nullptr; 
    if (EVP_PKEY_keygen(pctx.get(), &epkey) <= 0) return std::unexpected(CryptoError::KeyGenerationError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_key(epkey);
    
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_ctx(EVP_PKEY_CTX_new(ephemeral_key.get(), nullptr));
    if (!ecdh_ctx || EVP_PKEY_derive_init(ecdh_ctx.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_PKEY_derive_set_peer(ecdh_ctx.get(), recipient_pub.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    size_t slen; 
    EVP_PKEY_derive(ecdh_ctx.get(), nullptr, &slen);
    std::vector<unsigned char> secret(slen);
    EVP_PKEY_derive(ecdh_ctx.get(), secret.data(), &slen);
    shared_secret_ = secret;
    
    std::unique_ptr<BIO, BIO_Deleter> mem_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PUBKEY(mem_bio.get(), ephemeral_key.get());
    BUF_MEM *bio_buf; BIO_get_mem_ptr(mem_bio.get(), &bio_buf);
    ephemeral_pubkey_.assign(bio_buf->data, bio_buf->data + bio_buf->length);
    salt_.resize(16); iv_.resize(12); RAND_bytes(salt_.data(), 16); RAND_bytes(iv_.data(), 12);
    encryption_key_ = nkCryptoToolBase::hkdfDerive(secret, 32, std::string(salt_.begin(), salt_.end()), "ecc-encryption", "SHA3-256");
    
    if (!cipher_ctx_) cipher_ctx_.reset(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv_.size(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_EncryptInit_ex(cipher_ctx_.get(), nullptr, nullptr, encryption_key_.data(), iv_.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::vector<char> ECCStrategy::encryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    EVP_EncryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size());
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> ECCStrategy::finalizeEncryption(std::vector<char>& out_final) {
    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    int final_len = 0;
    EVP_EncryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len);
    std::vector<unsigned char> tag(16);
    EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    out_final.assign(final_block.begin(), final_block.begin() + final_len);
    out_final.insert(out_final.end(), tag.begin(), tag.end());
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareDecryption(const std::map<std::string, std::string>& key_paths, SecureString& passphrase) {
    std::string priv_key_path;
    if (key_paths.count("user-privkey")) priv_key_path = key_paths.at("user-privkey");
    else if (key_paths.count("recipient-ecdh-privkey")) priv_key_path = key_paths.at("recipient-ecdh-privkey");
    else if (key_paths.count("private-ecdh-key")) priv_key_path = key_paths.at("private-ecdh-key");
    else return std::unexpected(CryptoError::PrivateKeyLoadError);

    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto loaded = key_provider_.unwrap(SecureString(pem_content.begin(), pem_content.end()), passphrase);
        if (!loaded) return std::unexpected(loaded.error());
        encryption_priv_key_ = std::move(*loaded);
    } else {
        encryption_priv_key_.reset();
        std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
        void* pwd = passphrase.empty() ? nullptr : (void*)&passphrase;
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        encryption_priv_key_.reset(pkey);
    }

    std::unique_ptr<BIO, BIO_Deleter> mem_bio(BIO_new_mem_buf(ephemeral_pubkey_.data(), (int)ephemeral_pubkey_.size()));
    EVP_PKEY* epkey = PEM_read_bio_PUBKEY(mem_bio.get(), nullptr, nullptr, nullptr);
    if (!epkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> ephemeral_key(epkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_ctx(EVP_PKEY_CTX_new(encryption_priv_key_.get(), nullptr));
    if (!ecdh_ctx || EVP_PKEY_derive_init(ecdh_ctx.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_PKEY_derive_set_peer(ecdh_ctx.get(), ephemeral_key.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    size_t slen; 
    EVP_PKEY_derive(ecdh_ctx.get(), nullptr, &slen);
    std::vector<unsigned char> secret(slen);
    EVP_PKEY_derive(ecdh_ctx.get(), secret.data(), &slen);
    
    shared_secret_ = secret;
    encryption_key_ = nkCryptoToolBase::hkdfDerive(secret, 32, std::string(salt_.begin(), salt_.end()), "ecc-encryption", "SHA3-256");
    
    cipher_ctx_.reset(EVP_CIPHER_CTX_new());
    if (EVP_DecryptInit_ex(cipher_ctx_.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv_.size(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_DecryptInit_ex(cipher_ctx_.get(), nullptr, nullptr, encryption_key_.data(), iv_.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    decrypt_buffer_.clear();
    return {};
}

std::vector<char> ECCStrategy::decryptTransform(const std::vector<char>& data) {
    if (data.empty()) return {};
    std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len = 0;
    EVP_DecryptUpdate(cipher_ctx_.get(), out.data(), &out_len, (const unsigned char*)data.data(), (int)data.size());
    out.resize(out_len);
    return std::vector<char>(out.begin(), out.end());
}

std::expected<void, CryptoError> ECCStrategy::finalizeDecryption(const std::vector<char>& tag) {
    if (EVP_CIPHER_CTX_ctrl(cipher_ctx_.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> final_block(EVP_MAX_BLOCK_LENGTH);
    int final_len = 0;
    if (EVP_DecryptFinal_ex(cipher_ctx_.get(), final_block.data(), &final_len) <= 0) return std::unexpected(CryptoError::SignatureVerificationError);
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareSigning(const std::filesystem::path& priv_key_path, SecureString& passphrase, const std::string& digest_algo) {
    digest_algo_ = digest_algo;
    std::ifstream ifs(priv_key_path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::string pem_content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    if (pem_content.find(TPMUtils::TPM_BLOB_HEADER) != std::string::npos) {
        auto loaded = key_provider_.unwrap(SecureString(pem_content.begin(), pem_content.end()), passphrase);
        if (!loaded) return std::unexpected(loaded.error());
        sign_key_ = std::move(*loaded);
    } else {
        std::unique_ptr<BIO, BIO_Deleter> bio(BIO_new_mem_buf(pem_content.data(), (int)pem_content.size()));
        void* pwd = passphrase.empty() ? nullptr : (void*)&passphrase;
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, pem_passwd_cb, pwd);
        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        sign_key_.reset(pkey);
    }

    const EVP_MD* md = EVP_get_digestbyname(digest_algo.c_str());
    if (!md) md = EVP_sha3_512();
    EVP_MD_CTX_reset(md_ctx_.get());
    if (EVP_DigestSignInit(md_ctx_.get(), nullptr, md, nullptr, sign_key_.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::expected<void, CryptoError> ECCStrategy::prepareVerification(const std::filesystem::path& pub_key_path, const std::string& digest_algo) {
    digest_algo_ = digest_algo;
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(pub_key_path.string().c_str(), "rb"));
    if (!pub_bio) return std::unexpected(CryptoError::PublicKeyLoadError);
    verify_key_.reset(PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr));
    if (!verify_key_) return std::unexpected(CryptoError::PublicKeyLoadError);
    const EVP_MD* md = EVP_get_digestbyname(digest_algo.c_str());
    if (!md) md = EVP_sha3_512();
    EVP_MD_CTX_reset(md_ctx_.get());
    if (EVP_DigestVerifyInit(md_ctx_.get(), nullptr, md, nullptr, verify_key_.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

void ECCStrategy::updateHash(const std::vector<char>& data) {
    if (sign_key_) EVP_DigestSignUpdate(md_ctx_.get(), data.data(), data.size());
    else if (verify_key_) EVP_DigestVerifyUpdate(md_ctx_.get(), data.data(), data.size());
}

std::expected<std::vector<char>, CryptoError> ECCStrategy::signHash() {
    size_t slen = 0;
    if (EVP_DigestSignFinal(md_ctx_.get(), nullptr, &slen) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<unsigned char> sig(slen);
    if (EVP_DigestSignFinal(md_ctx_.get(), sig.data(), &slen) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    sig.resize(slen);
    return std::vector<char>(sig.begin(), sig.end());
}

std::expected<bool, CryptoError> ECCStrategy::verifyHash(const std::vector<char>& signature) {
    int res = EVP_DigestVerifyFinal(md_ctx_.get(), (const unsigned char*)signature.data(), signature.size());
    if (res == 1) return true;
    if (res == 0) return false;
    return std::unexpected(CryptoError::OpenSSLError);
}

std::vector<char> ECCStrategy::serializeSignatureHeader() const {
    std::vector<char> header;
    header.insert(header.end(), {'N', 'K', 'C', 'S'});
    write_u16_le(header, 1);
    header.push_back((char)getStrategyType());
    auto add_string = [&](const std::string& s) {
        write_u32_le(header, (uint32_t)s.size());
        header.insert(header.end(), s.begin(), s.end());
    };
    add_string(curve_name_);
    add_string(digest_algo_);
    return header;
}

std::expected<size_t, CryptoError> ECCStrategy::deserializeSignatureHeader(const std::vector<char>& data) {
    size_t pos = 0;
    if (data.size() < 7) return std::unexpected(CryptoError::FileReadError);
    if (std::string(data.data(), 4) != "NKCS") return std::unexpected(CryptoError::FileReadError);
    pos += 4;
    uint16_t version; if (!read_u16_le(data, pos, version) || version != 1) return std::unexpected(CryptoError::FileReadError);
    uint8_t type = (uint8_t)data[pos++];
    if (type != (uint8_t)getStrategyType()) return std::unexpected(CryptoError::FileReadError);

    auto read_string = [&](std::string& s) -> bool {
        uint32_t len;
        if (!read_u32_le(data, pos, len)) return false;
        if (pos + len > data.size()) return false;
        s.assign(data.begin() + pos, data.begin() + pos + len); pos += len;
        return true;
    };
    if (!read_string(curve_name_) || !read_string(digest_algo_)) return std::unexpected(CryptoError::FileReadError);
    return pos;
}
