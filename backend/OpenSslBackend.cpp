/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "OpenSslBackend.hpp"
#include "SecureMemory.hpp"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <cstring>
#include <iostream>

#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace nk::backend {

static void reportOpenSSLErrors(const std::string& context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "[OpenSSL] " << context << " Error: " << buf << std::endl;
    }
}

static EVP_PKEY* loadPrivateKeyRobust(const uint8_t* der, size_t len, const SecureString& passphrase) {
    if (!der || len == 0) return nullptr;
    const uint8_t* p = der;
    
    // Try auto first (handles unencrypted PKCS#8 or traditional formats)
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)len);
    if (pkey) return pkey;

    // If it fails, try encrypted PKCS#8
    BIO* mem = BIO_new_mem_buf(der, (int)len);
    if (!mem) return nullptr;
    pkey = d2i_PKCS8PrivateKey_bio(mem, nullptr, ossl_passphrase_cb, (void*)&passphrase);
    BIO_free(mem);
    
    return pkey;
}

// --- OpenSslAeadBackend ---

OpenSslAeadBackend::OpenSslAeadBackend(std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx)
    : ctx_(std::move(ctx)) {}

std::expected<size_t, CryptoError> OpenSslAeadBackend::update(const uint8_t* in, size_t in_len, uint8_t* out) {
    int out_l = 0;
    if (EVP_CipherUpdate(ctx_.get(), out, &out_l, in, (int)in_len) <= 0) {
        reportOpenSSLErrors("AEAD Update");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return (size_t)out_l;
}

std::expected<size_t, CryptoError> OpenSslAeadBackend::finalize(uint8_t* out) {
    int out_l = 0;
    if (EVP_CipherFinal_ex(ctx_.get(), out, &out_l) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return (size_t)out_l;
}

std::expected<void, CryptoError> OpenSslAeadBackend::getTag(uint8_t* tag, size_t tag_len) {
    if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) <= 0) {
        reportOpenSSLErrors("AEAD GetTag");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

std::expected<void, CryptoError> OpenSslAeadBackend::setTag(const uint8_t* tag, size_t tag_len) {
    if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) <= 0) {
        reportOpenSSLErrors("AEAD SetTag");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

// --- OpenSslHashBackend ---

OpenSslHashBackend::OpenSslHashBackend(std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx, const EVP_MD* md)
    : ctx_(std::move(ctx)), md_(md) {}

std::expected<void, CryptoError> OpenSslHashBackend::update(const uint8_t* data, size_t len) {
    buffer_.insert(buffer_.end(), data, data + len);
    return {};
}

std::expected<void, CryptoError> OpenSslHashBackend::initSign(const std::vector<uint8_t>& priv_key_der, const SecureString& passphrase) {
    EVP_PKEY* pkey = loadPrivateKeyRobust(priv_key_der.data(), priv_key_der.size(), passphrase);
    if (!pkey) {
        reportOpenSSLErrors("initSign: Load Private Key");
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    pkey_ = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    buffer_.clear();
    return {};
}

std::expected<std::vector<uint8_t>, CryptoError> OpenSslHashBackend::finalizeSign() {
    EVP_MD_CTX_reset(ctx_.get());
    
    const char* pkey_name = EVP_PKEY_get0_type_name(pkey_.get());
    const EVP_MD* actual_md = md_;
    if (pkey_name && (std::string(pkey_name).find("ML-DSA") != std::string::npos || std::string(pkey_name).find("mldsa") != std::string::npos)) {
        actual_md = nullptr;
    }

    if (EVP_DigestSignInit(ctx_.get(), nullptr, actual_md, nullptr, pkey_.get()) <= 0) {
        reportOpenSSLErrors("DigestSignInit");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    size_t slen = 0;
    if (EVP_DigestSign(ctx_.get(), nullptr, &slen, (const uint8_t*)buffer_.data(), buffer_.size()) <= 0) {
        reportOpenSSLErrors("DigestSign (Length)");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    std::vector<uint8_t> sig(slen);
    if (EVP_DigestSign(ctx_.get(), sig.data(), &slen, (const uint8_t*)buffer_.data(), buffer_.size()) <= 0) {
        reportOpenSSLErrors("DigestSign (Execution)");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    sig.resize(slen);
    return sig;
}

std::expected<void, CryptoError> OpenSslHashBackend::initVerify(const std::vector<uint8_t>& pub_key_der) {
    const uint8_t* p = pub_key_der.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)pub_key_der.size());
    if (!pkey) {
        reportOpenSSLErrors("initVerify: Load Public Key");
        return std::unexpected(CryptoError::PublicKeyLoadError);
    }
    pkey_ = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    buffer_.clear();
    return {};
}

std::expected<bool, CryptoError> OpenSslHashBackend::finalizeVerify(const std::vector<uint8_t>& signature) {
    EVP_MD_CTX_reset(ctx_.get());
    
    const char* pkey_name = EVP_PKEY_get0_type_name(pkey_.get());
    const EVP_MD* actual_md = md_;
    if (pkey_name && (std::string(pkey_name).find("ML-DSA") != std::string::npos || std::string(pkey_name).find("mldsa") != std::string::npos)) {
        actual_md = nullptr;
    }

    if (EVP_DigestVerifyInit(ctx_.get(), nullptr, actual_md, nullptr, pkey_.get()) <= 0) {
        reportOpenSSLErrors("DigestVerifyInit");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    int res = EVP_DigestVerify(ctx_.get(), signature.data(), signature.size(), (const uint8_t*)buffer_.data(), buffer_.size());
    if (res == 1) return true;
    if (res == 0) return false;
    
    reportOpenSSLErrors("DigestVerify");
    return std::unexpected(CryptoError::OpenSSLError);
}

// --- OpenSslBackend ---

OpenSslBackend::OpenSslBackend() {}

std::expected<std::unique_ptr<IAeadBackend>, CryptoError> OpenSslBackend::createAead(const std::string& cipher_name, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt) {
    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name.c_str());
    if (!cipher) return std::unexpected(CryptoError::OpenSSLError);
    
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx(EVP_CIPHER_CTX_new());
    if (encrypt) {
        if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    } else {
        if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    }
    
    return std::make_unique<OpenSslAeadBackend>(std::move(ctx));
}

std::expected<std::unique_ptr<IHashBackend>, CryptoError> OpenSslBackend::createHash(const std::string& algo_name) {
    const EVP_MD* md = EVP_get_digestbyname(algo_name.c_str());
    if (!md) return std::unexpected(CryptoError::OpenSSLError);
    
    std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx(EVP_MD_CTX_new());
    return std::make_unique<OpenSslHashBackend>(std::move(ctx), md);
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> OpenSslBackend::generateEccKeyPair(const std::string& curve_name) {
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("group", (char*)curve_name.c_str(), 0), OSSL_PARAM_construct_end() };
    EVP_PKEY_CTX_set_params(pctx.get(), params);
    
    EVP_PKEY* pkey = nullptr; 
    if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) return std::unexpected(CryptoError::KeyGenerationError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);
    
    uint8_t *priv = nullptr, *pub = nullptr;
    int priv_len = i2d_PrivateKey(spkey.get(), &priv);
    int pub_len = i2d_PUBKEY(spkey.get(), &pub);
    
    std::vector<uint8_t> priv_v(priv, priv + priv_len), pub_v(pub, pub + pub_len);
    OPENSSL_free(priv); OPENSSL_free(pub);
    return std::make_pair(priv_v, pub_v);
}

std::expected<std::vector<uint8_t>, CryptoError> OpenSslBackend::eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der, const SecureString& passphrase) {
    EVP_PKEY* priv = loadPrivateKeyRobust(priv_der.data(), priv_der.size(), passphrase);
    const uint8_t* p2 = pub_der.data();
    EVP_PKEY* pub = d2i_PUBKEY(nullptr, &p2, (long)pub_der.size());
    if (!priv || !pub) {
        if (priv) EVP_PKEY_free(priv);
        reportOpenSSLErrors("eccDh: Key Load");
        return std::unexpected(CryptoError::KeyGenerationError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spriv(priv), spub(pub);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ecdh_ctx(EVP_PKEY_CTX_new(spriv.get(), nullptr));
    if (!ecdh_ctx || EVP_PKEY_derive_init(ecdh_ctx.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_PKEY_derive_set_peer(ecdh_ctx.get(), spub.get()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    size_t slen; 
    EVP_PKEY_derive(ecdh_ctx.get(), nullptr, &slen);
    std::vector<uint8_t> secret(slen);
    EVP_PKEY_derive(ecdh_ctx.get(), secret.data(), &slen);
    return secret;
}

std::expected<std::vector<uint8_t>, CryptoError> OpenSslBackend::extractPublicKey(const std::vector<uint8_t>& priv_der, const SecureString& passphrase) {
    EVP_PKEY* pkey = loadPrivateKeyRobust(priv_der.data(), priv_der.size(), passphrase);
    if (!pkey) {
        reportOpenSSLErrors("extractPublicKey: Load Private Key");
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);
    
    uint8_t *pub = nullptr;
    int pub_len = i2d_PUBKEY(spkey.get(), &pub);
    if (pub_len <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> pub_v(pub, pub + pub_len);
    OPENSSL_free(pub);
    return pub_v;
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> OpenSslBackend::generatePqcSignKeyPair(const std::string& algo_name) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, algo_name.c_str());
    if (!pkey) {
        reportOpenSSLErrors("generatePqcSignKeyPair: EVP_PKEY_Q_keygen");
        return std::unexpected(CryptoError::KeyGenerationError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);
    
    uint8_t *priv = nullptr, *pub = nullptr;
    int priv_len = i2d_PrivateKey(spkey.get(), &priv);
    int pub_len = i2d_PUBKEY(spkey.get(), &pub);
    
    std::vector<uint8_t> priv_v(priv, priv + priv_len), pub_v(pub, pub + pub_len);
    OPENSSL_free(priv); OPENSSL_free(pub);
    return std::make_pair(priv_v, pub_v);
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> OpenSslBackend::pqcEncap(const std::vector<uint8_t>& pub_key_der) {
    const uint8_t* p = pub_key_der.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)pub_key_der.size());
    if (!pkey) {
        reportOpenSSLErrors("pqcEncap: Load Public Key");
        return std::unexpected(CryptoError::PublicKeyLoadError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(spkey.get(), nullptr));
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    size_t secret_len, ct_len;
    if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &secret_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> secret(secret_len), ct(ct_len);
    if (EVP_PKEY_encapsulate(ctx.get(), ct.data(), &ct_len, secret.data(), &secret_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    return std::make_pair(secret, ct);
}

std::expected<std::vector<uint8_t>, CryptoError> OpenSslBackend::pqcDecap(const std::vector<uint8_t>& priv_key_der, const std::vector<uint8_t>& kem_ct, const SecureString& passphrase) {
    EVP_PKEY* pkey = loadPrivateKeyRobust(priv_key_der.data(), priv_key_der.size(), passphrase);
    if (!pkey) {
        reportOpenSSLErrors("pqcDecap: Load Private Key");
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(spkey.get(), nullptr));
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
        reportOpenSSLErrors("pqcDecap: Decapsulate Init");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    size_t secret_len;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &secret_len, (const unsigned char*)kem_ct.data(), kem_ct.size()) <= 0) {
        reportOpenSSLErrors("pqcDecap: Decapsulate (Length)");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_decapsulate(ctx.get(), secret.data(), &secret_len, (const unsigned char*)kem_ct.data(), kem_ct.size()) <= 0) {
        reportOpenSSLErrors("pqcDecap: Decapsulate (Execution)");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    
    return secret;
}

std::vector<uint8_t> OpenSslBackend::hkdf(const std::vector<uint8_t>& secret, size_t out_len, const std::vector<uint8_t>& salt, const std::string& info, const std::string& md_name) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    const EVP_MD* md = EVP_get_digestbyname(md_name.c_str());
    if (!md) md = EVP_sha256();
    
    uint8_t zero_salt[64] = {0};
    void* salt_ptr = (void*)salt.data();
    if (salt.empty()) salt_ptr = zero_salt;

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)EVP_MD_get0_name(md), 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)secret.data(), secret.size());
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt_ptr, salt.size());
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
    params[4] = OSSL_PARAM_construct_end();
    
    std::vector<uint8_t> out(out_len);
    if (EVP_KDF_derive(kctx.get(), out.data(), out_len, params) <= 0) {
        reportOpenSSLErrors("HKDF Derive");
    }
    return out;
}

std::expected<void, CryptoError> OpenSslBackend::randomBytes(uint8_t* out, size_t len) {
    if (RAND_bytes(out, (int)len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

void OpenSslBackend::cleanse(void* ptr, size_t len) {
    OPENSSL_cleanse(ptr, len);
}

std::string OpenSslBackend::base64Encode(const std::vector<uint8_t>& data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), (int)data.size());
    BIO_flush(b64);
    BUF_MEM *ptr;
    BIO_get_mem_ptr(b64, &ptr);
    std::string res(ptr->data, ptr->length);
    BIO_free_all(b64);
    return res;
}

std::vector<uint8_t> OpenSslBackend::base64Decode(const std::string& base64_str) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(base64_str.data(), (int)base64_str.size());
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    std::vector<uint8_t> decoded(base64_str.size());
    int len = BIO_read(b64, decoded.data(), (int)decoded.size());
    if (len > 0) decoded.resize(len); else decoded.clear();
    BIO_free_all(b64);
    return decoded;
}

} // namespace nk::backend

#ifdef USE_BACKEND_OPENSSL
std::shared_ptr<nk::backend::ICryptoBackend> get_nk_backend() {
    static auto instance = std::make_shared<nk::backend::OpenSslBackend>();
    return instance;
}
#endif

namespace nk::backend {

int ossl_passphrase_cb(char *pass, int pass_max, int rwflag, void *arg) {
    if (arg == nullptr) return 0;
    const SecureString* passphrase = static_cast<const SecureString*>(arg);
    int len = (int)passphrase->length();
    if (len >= pass_max) return 0;
    std::memcpy(pass, passphrase->c_str(), len);
    return len;
}

} // namespace nk::backend
