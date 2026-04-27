/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "WolfSslBackend.hpp"
#include "nkCryptoToolUtils.hpp"
#include <wolfssl/options.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <iostream>
#include <cstring>
#include <algorithm>
#include <iomanip>

namespace nk::backend {

static void printWolfError(const std::string& context) {
    unsigned long err = wolfSSL_ERR_get_error();
    char err_buf[256];
    while (err != 0) {
        wolfSSL_ERR_error_string_n(err, err_buf, sizeof(err_buf));
        std::cerr << "[WolfSSL] " << context << " FAILED: " << err_buf << std::endl;
        err = wolfSSL_ERR_get_error();
    }
}

static WOLFSSL_EVP_PKEY* loadPrivateKeyRobust(const uint8_t* der, size_t len, const SecureString& passphrase) {
    if (!der || len == 0) return nullptr;
    const uint8_t* p = der;
    
    // Try auto first (handles unencrypted)
    WOLFSSL_EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)len);
    if (pkey) return pkey;

    // If it fails, try with passphrase if provided
    if (!passphrase.empty()) {
        WOLFSSL_BIO* mem = wolfSSL_BIO_new_mem_buf((void*)der, (int)len);
        if (mem) {
            // Note: wolfSSL_PEM_read_bio_PrivateKey might expect PEM, but we have DER.
            // In WolfSSL, we should use wolfSSL_d2i_PKCS8PrivateKey_bio if available.
            pkey = wolfSSL_d2i_PKCS8PrivateKey_bio(mem, nullptr, nullptr, (void*)passphrase.c_str());
            wolfSSL_BIO_free(mem);
            if (pkey) return pkey;
        }
    }

    while (wolfSSL_ERR_get_error() != 0);
    return nullptr;
}

static WOLFSSL_EVP_PKEY* loadPublicKeyRobust(const uint8_t* der, size_t len) {
    if (!der || len == 0) return nullptr;
    const uint8_t* p = der;
    WOLFSSL_EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)len);
    if (pkey) return pkey;
    while (wolfSSL_ERR_get_error() != 0);
    return nullptr;
}

// --- HKDF Manual Implementation to avoid wolfSSL build issues ---
static int wolfssl_hkdf_manual(int type, const uint8_t* secret, size_t secret_len, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* out, size_t out_len) {
    word32 hash_len = 32;
    if (type == WC_SHA512 || type == WC_SHA3_512 || type == WC_HASH_TYPE_SHA512 || type == WC_HASH_TYPE_SHA3_512) hash_len = 64;

    uint8_t prk[64];
    const uint8_t* local_salt = salt;
    uint8_t zero_salt[64] = {0};
    if (salt_len == 0 || !salt) {
        local_salt = zero_salt;
        salt_len = hash_len;
    }

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    Hmac hmac_ext;
    if (wc_HmacSetKey(&hmac_ext, type, local_salt, (word32)salt_len) != 0) return -1;
    if (wc_HmacUpdate(&hmac_ext, secret, (word32)secret_len) != 0) return -1;
    if (wc_HmacFinal(&hmac_ext, prk) != 0) return -1;

    // HKDF-Expand
    uint8_t t[64];
    size_t generated = 0;
    uint8_t counter = 1;
    while (generated < out_len) {
        Hmac hmac_exp;
        if (wc_HmacSetKey(&hmac_exp, type, prk, hash_len) != 0) return -1;
        if (generated > 0) {
            if (wc_HmacUpdate(&hmac_exp, t, hash_len) != 0) return -1;
        }
        if (wc_HmacUpdate(&hmac_exp, info, (word32)info_len) != 0) return -1;
        if (wc_HmacUpdate(&hmac_exp, &counter, 1) != 0) return -1;
        if (wc_HmacFinal(&hmac_exp, t) != 0) return -1;

        size_t to_copy = std::min((size_t)hash_len, out_len - generated);
        std::memcpy(out + generated, t, to_copy);
        generated += to_copy;
        counter++;
    }
    return 0;
}

// --- ASN.1 Helper for PQC Interop ---

static size_t read_asn1_len(const uint8_t* der, size_t len, size_t& pos) {
    if (pos >= len) return 0;
    uint8_t b = der[pos++];
    if (b < 128) return b;
    size_t n = b & 0x7F;
    if (pos + n > len || n > 4) return 0;
    size_t res = 0;
    for (size_t i = 0; i < n; ++i) res = (res << 8) | der[pos++];
    return res;
}

static std::vector<uint8_t> unwrapPqcDer(const uint8_t* der, size_t len, bool is_public) {
    if (!der || len < 32) return {};
    // すでに生のバイナリ（非ASN.1）の場合はそのまま返す
    if (der[0] != 0x30) return std::vector<uint8_t>(der, der + len);

    auto is_pqc_size = [](size_t s) {
        return s == 1632 || s == 2400 || s == 3168 || // Kyber Priv
               s == 800 || s == 1184 || s == 1568 ||  // Kyber Pub
               s == 2560 || s == 4032 || s == 4896 || // Dilithium Priv
               s == 1312 || s == 1952 || s == 2592;   // Dilithium Pub
    };

    std::vector<uint8_t> best;
    // 浅い階層から順に、PQCサイズに合致する OCTET STRING (0x04) または BIT STRING (0x03) を探す
    // 本ツールの構造では OCTET STRING の中にさらに ASN.1 が入っている場合があるため、
    // 見つかったデータが ASN.1 (0x30) であればその中も探す
    for (size_t i = 0; i < len - 4; ++i) {
        uint8_t tag = der[i];
        if (tag == 0x04 || (is_public && tag == 0x03)) {
            size_t pos = i + 1;
            size_t o_len = read_asn1_len(der, len, pos);
            if (o_len > 0 && pos + o_len <= len) {
                const uint8_t* data = der + pos;
                size_t actual_len = o_len;
                if (tag == 0x03 && actual_len > 1 && data[0] == 0x00) { data++; actual_len--; }
                
                if (is_pqc_size(actual_len)) return std::vector<uint8_t>(data, data + actual_len);
                
                // ネストされた構造を 1段階だけ深く探す
                if (actual_len > 32 && data[0] == 0x30) {
                    auto inner = unwrapPqcDer(data, actual_len, is_public);
                    if (is_pqc_size(inner.size())) return inner;
                }
                if (actual_len > best.size()) best.assign(data, data + actual_len);
            }
        }
    }
    return best.empty() ? std::vector<uint8_t>(der, der + len) : best;
}

static void asn1_append_len(std::vector<uint8_t>& buf, size_t len) {
    if (len < 128) { buf.push_back((uint8_t)len); }
    else if (len < 256) { buf.push_back(0x81); buf.push_back((uint8_t)len); }
    else { buf.push_back(0x82); buf.push_back((uint8_t)(len >> 8)); buf.push_back((uint8_t)(len & 0xff)); }
}

static void asn1_append_seq(std::vector<uint8_t>& buf, const std::vector<uint8_t>& content) {
    buf.push_back(0x30); asn1_append_len(buf, content.size());
    buf.insert(buf.end(), content.begin(), content.end());
}

static std::vector<uint8_t> wrapPqcDer(const std::vector<uint8_t>& raw, const std::string& algo_name, bool is_public, const uint8_t* seed_ptr, size_t seed_len) {
    std::vector<uint8_t> oid;
    size_t default_seed_len = 0;
    if (algo_name == "ML-KEM-512") { oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01}; default_seed_len = 64; }
    else if (algo_name == "ML-KEM-768") { oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02}; default_seed_len = 64; }
    else if (algo_name == "ML-KEM-1024") { oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03}; default_seed_len = 64; }
    else if (algo_name == "ML-DSA-44") { oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11}; default_seed_len = 32; }
    else if (algo_name == "ML-DSA-65") { oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12}; default_seed_len = 32; }
    else if (algo_name == "ML-DSA-87") { oid = {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13}; default_seed_len = 32; }
    else return raw;

    std::vector<uint8_t> algo_id;
    asn1_append_seq(algo_id, oid);

    if (is_public) {
        std::vector<uint8_t> bit_str;
        bit_str.push_back(0x03); asn1_append_len(bit_str, raw.size() + 1); bit_str.push_back(0x00);
        bit_str.insert(bit_str.end(), raw.begin(), raw.end());
        
        std::vector<uint8_t> spki_content;
        spki_content.insert(spki_content.end(), algo_id.begin(), algo_id.end());
        spki_content.insert(spki_content.end(), bit_str.begin(), bit_str.end());
        
        std::vector<uint8_t> res;
        asn1_append_seq(res, spki_content);
        return res;
    } else {
        std::vector<uint8_t> seed_v(default_seed_len, 0);
        if (seed_ptr && seed_len >= default_seed_len) std::memcpy(seed_v.data(), seed_ptr, default_seed_len);
        else if (raw.size() == 1632 || raw.size() == 2400 || raw.size() == 3168) {
            std::memcpy(seed_v.data(), raw.data(), 32);
            std::memcpy(seed_v.data() + 32, raw.data() + raw.size() - 32, 32);
        } else if (raw.size() == 2560 || raw.size() == 4032 || raw.size() == 4896) {
            std::memcpy(seed_v.data(), raw.data(), 32);
        }
        
        std::vector<uint8_t> seed_oct;
        seed_oct.push_back(0x04); asn1_append_len(seed_oct, seed_v.size());
        seed_oct.insert(seed_oct.end(), seed_v.begin(), seed_v.end());
        
        std::vector<uint8_t> key_oct;
        key_oct.push_back(0x04); asn1_append_len(key_oct, raw.size());
        key_oct.insert(key_oct.end(), raw.begin(), raw.end());
        
        std::vector<uint8_t> nested_seq_content;
        nested_seq_content.insert(nested_seq_content.end(), seed_oct.begin(), seed_oct.end());
        nested_seq_content.insert(nested_seq_content.end(), key_oct.begin(), key_oct.end());
        std::vector<uint8_t> nested_seq;
        asn1_append_seq(nested_seq, nested_seq_content);
        
        std::vector<uint8_t> p8_content;
        p8_content.push_back(0x02); p8_content.push_back(0x01); p8_content.push_back(0x00);
        p8_content.insert(p8_content.end(), algo_id.begin(), algo_id.end());
        
        std::vector<uint8_t> final_key_oct;
        final_key_oct.push_back(0x04); asn1_append_len(final_key_oct, nested_seq.size());
        final_key_oct.insert(final_key_oct.end(), nested_seq.begin(), nested_seq.end());
        
        p8_content.insert(p8_content.end(), final_key_oct.begin(), final_key_oct.end());
        
        std::vector<uint8_t> res;
        asn1_append_seq(res, p8_content);
        return res;
    }
}

// --- WolfSslAeadBackend ---

WolfSslAeadBackend::WolfSslAeadBackend(WOLFSSL_EVP_CIPHER_CTX* ctx) : ctx_(ctx) {}
WolfSslAeadBackend::~WolfSslAeadBackend() { wolfSSL_EVP_CIPHER_CTX_free(ctx_); }

std::expected<size_t, CryptoError> WolfSslAeadBackend::update(const uint8_t* in, size_t in_len, uint8_t* out) {
    int out_l = 0;
    if (wolfSSL_EVP_CipherUpdate(ctx_, out, &out_l, in, (int)in_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return (size_t)out_l;
}

std::expected<size_t, CryptoError> WolfSslAeadBackend::finalize(uint8_t* out) {
    int out_l = 0;
    if (wolfSSL_EVP_CipherFinal(ctx_, out, &out_l) <= 0) {
        return std::unexpected(CryptoError::SignatureVerificationError);
    }
    return (size_t)out_l;
}

std::expected<void, CryptoError> WolfSslAeadBackend::getTag(uint8_t* tag, size_t tag_len) {
    if (wolfSSL_EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::expected<void, CryptoError> WolfSslAeadBackend::setTag(const uint8_t* tag, size_t tag_len) {
    if (wolfSSL_EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

// --- WolfSslHashBackend ---

WolfSslHashBackend::WolfSslHashBackend(WOLFSSL_EVP_MD_CTX* ctx, const WOLFSSL_EVP_MD* md) : ctx_(ctx), md_(md), is_sign_(false) {
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
    wc_dilithium_init(&dilithium_key_);
#endif
}

WolfSslHashBackend::~WolfSslHashBackend() {
    wolfSSL_EVP_MD_CTX_free(ctx_);
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
    wc_dilithium_free(&dilithium_key_);
#endif
}

std::expected<void, CryptoError> WolfSslHashBackend::update(const uint8_t* data, size_t len) {
    if (len == 0) return {};
    buffer_.insert(buffer_.end(), data, data + len);
    return {};
}

std::expected<void, CryptoError> WolfSslHashBackend::initSign(const std::vector<uint8_t>& priv_key_der, const SecureString& passphrase) {
    buffer_.clear();
    is_sign_ = true;
    pqc_dsa_type_ = -1;

    std::vector<uint8_t> working_der = priv_key_der;
    WOLFSSL_EVP_PKEY* pkey_dec = loadPrivateKeyRobust(priv_key_der.data(), priv_key_der.size(), passphrase);
    if (pkey_dec) {
        int len = i2d_PrivateKey(pkey_dec, nullptr);
        if (len > 0) {
            working_der.assign(len, 0);
            uint8_t* p = working_der.data();
            i2d_PrivateKey(pkey_dec, &p);
        }
        wolfSSL_EVP_PKEY_free(pkey_dec);
    }

    std::vector<uint8_t> raw_key = unwrapPqcDer(working_der.data(), working_der.size(), false);
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
    int level = -1;
    if (raw_key.size() == DILITHIUM_LEVEL2_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_44_PRV_KEY_SIZE) level = 2;
    else if (raw_key.size() == DILITHIUM_LEVEL3_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_65_PRV_KEY_SIZE) level = 3;
    else if (raw_key.size() == DILITHIUM_LEVEL5_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_87_PRV_KEY_SIZE) level = 5;

    if (level != -1) {
        wc_dilithium_free(&dilithium_key_);
        wc_dilithium_init(&dilithium_key_);
        wc_dilithium_set_level(&dilithium_key_, level);
        if (wc_dilithium_import_private(raw_key.data(), (word32)raw_key.size(), &dilithium_key_) == 0) {
            pqc_dsa_type_ = level;
            return {};
        }
    }
#endif

    WOLFSSL_EVP_PKEY* pkey = loadPrivateKeyRobust(priv_key_der.data(), priv_key_der.size(), passphrase);
    if (pkey) {
        if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
        pkey_ = pkey;
        return {};
    }

    return std::unexpected(CryptoError::PrivateKeyLoadError);
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslHashBackend::finalizeSign() {
    if (pqc_dsa_type_ != -1) {
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
        WC_RNG rng;
        wc_InitRng(&rng);
        word32 slen = wc_dilithium_sig_size(&dilithium_key_);
        std::vector<uint8_t> sig(slen);
        if (wc_dilithium_sign_ctx_msg(nullptr, 0, buffer_.data(), (word32)buffer_.size(), sig.data(), &slen, &dilithium_key_, &rng) == 0) {
            sig.resize(slen);
            wc_FreeRng(&rng);
            return sig;
        }
        wc_FreeRng(&rng);
#endif
        return std::unexpected(CryptoError::OpenSSLError);
    } else if (pkey_) {
        wolfSSL_EVP_MD_CTX_cleanup(ctx_);
        wolfSSL_EVP_MD_CTX_init(ctx_);
        if (wolfSSL_EVP_DigestSignInit(ctx_, nullptr, nullptr, nullptr, pkey_) <= 0) {
            if (wolfSSL_EVP_DigestSignInit(ctx_, nullptr, md_, nullptr, pkey_) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        }
        if (wolfSSL_EVP_DigestSignUpdate(ctx_, buffer_.data(), buffer_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        size_t slen = 0;
        if (wolfSSL_EVP_DigestSignFinal(ctx_, nullptr, &slen) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        std::vector<uint8_t> sig(slen);
        if (wolfSSL_EVP_DigestSignFinal(ctx_, sig.data(), &slen) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        sig.resize(slen);
        return sig;
    }
    return std::unexpected(CryptoError::ParameterError);
}

std::expected<void, CryptoError> WolfSslHashBackend::initVerify(const std::vector<uint8_t>& pub_key_der) {
    buffer_.clear();
    is_sign_ = false;
    pqc_dsa_type_ = -1;

    std::vector<uint8_t> raw_key = unwrapPqcDer(pub_key_der.data(), pub_key_der.size(), true);
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
    int level = -1;
    if (raw_key.size() == DILITHIUM_LEVEL2_PUB_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_44_PUB_KEY_SIZE) level = 2;
    else if (raw_key.size() == DILITHIUM_LEVEL3_PUB_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_65_PUB_KEY_SIZE) level = 3;
    else if (raw_key.size() == DILITHIUM_LEVEL5_PUB_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_87_PUB_KEY_SIZE) level = 5;

    if (level != -1) {
        wc_dilithium_free(&dilithium_key_);
        wc_dilithium_init(&dilithium_key_);
        wc_dilithium_set_level(&dilithium_key_, level);
        if (wc_dilithium_import_public(raw_key.data(), (word32)raw_key.size(), &dilithium_key_) == 0) {
            pqc_dsa_type_ = level;
            return {};
        }
    }
#endif

    WOLFSSL_EVP_PKEY* pkey = loadPublicKeyRobust(pub_key_der.data(), pub_key_der.size());
    if (pkey) {
        if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
        pkey_ = pkey;
        return {};
    }

    return std::unexpected(CryptoError::PublicKeyLoadError);
}

std::expected<bool, CryptoError> WolfSslHashBackend::finalizeVerify(const std::vector<uint8_t>& signature) {
    if (pqc_dsa_type_ != -1) {
    #if 0
        int res = 0;
        if (wc_dilithium_verify_ctx_msg(signature.data(), (word32)signature.size(), nullptr, 0, buffer_.data(), (word32)buffer_.size(), &res, &dilithium_key_) == 0) {
            return res == 1;
        }
    #endif
        return std::unexpected(CryptoError::OpenSSLError);
    }
 else if (pkey_) {
        wolfSSL_EVP_MD_CTX_cleanup(ctx_);
        wolfSSL_EVP_MD_CTX_init(ctx_);
        if (wolfSSL_EVP_DigestVerifyInit(ctx_, nullptr, nullptr, nullptr, pkey_) <= 0) {
            if (wolfSSL_EVP_DigestVerifyInit(ctx_, nullptr, md_, nullptr, pkey_) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        }
        if (wolfSSL_EVP_DigestVerifyUpdate(ctx_, buffer_.data(), buffer_.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
        int res = wolfSSL_EVP_DigestVerifyFinal(ctx_, (unsigned char*)signature.data(), signature.size());
        if (res < 0) return std::unexpected(CryptoError::OpenSSLError);
        return res == 1;
    }
    return std::unexpected(CryptoError::ParameterError);
}

// --- WolfSslBackend ---

std::expected<std::unique_ptr<IAeadBackend>, CryptoError> WolfSslBackend::createAead(const std::string& cipher_name, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt) {
    const WOLFSSL_EVP_CIPHER* cipher = (cipher_name == "AES-256-GCM") ? wolfSSL_EVP_aes_256_gcm() : wolfSSL_EVP_aes_128_gcm();
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (encrypt) {
        wolfSSL_EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
        wolfSSL_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        if (wolfSSL_EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    } else {
        wolfSSL_EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
        wolfSSL_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        if (wolfSSL_EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    }
    return std::make_unique<WolfSslAeadBackend>(ctx);
}

std::expected<std::unique_ptr<IHashBackend>, CryptoError> WolfSslBackend::createHash(const std::string& algo_name) {
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_get_digestbyname(algo_name.c_str());
    if (!md) {
        if (algo_name == "SHA3-512") md = wolfSSL_EVP_sha3_512();
        else if (algo_name == "SHA3-256") md = wolfSSL_EVP_sha3_256();
        else if (algo_name == "SHA256") md = wolfSSL_EVP_sha256();
    }
    if (!md) return std::unexpected(CryptoError::ParameterError);
    return std::make_unique<WolfSslHashBackend>(wolfSSL_EVP_MD_CTX_new(), md);
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> WolfSslBackend::generateEccKeyPair(const std::string&) {
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    if (wc_ecc_make_key(&rng, 32, &key) != 0) {
        wc_ecc_free(&key); wc_FreeRng(&rng);
        return std::unexpected(CryptoError::KeyGenerationError);
    }
    std::vector<uint8_t> priv_v(1024);
    word32 priv_len = (word32)priv_v.size();
    if (wc_EccKeyToPKCS8(&key, priv_v.data(), &priv_len) != 0) {
        priv_len = wc_EccKeyToDer(&key, priv_v.data(), (word32)priv_v.size());
    }
    priv_v.resize(priv_len);
    std::vector<uint8_t> pub_v(1024);
    int pub_len = wc_EccPublicKeyToDer(&key, pub_v.data(), (word32)pub_v.size(), 1); 
    pub_v.resize(pub_len);
    wc_ecc_free(&key); wc_FreeRng(&rng);
    return std::make_pair(priv_v, pub_v);
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der, const SecureString& passphrase) {
    WOLFSSL_EVP_PKEY* priv = loadPrivateKeyRobust(priv_der.data(), priv_der.size(), passphrase);
    WOLFSSL_EVP_PKEY* pub = loadPublicKeyRobust(pub_der.data(), pub_der.size());
    if (!priv || !pub) {
        if (priv) wolfSSL_EVP_PKEY_free(priv);
        if (pub) wolfSSL_EVP_PKEY_free(pub);
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    WOLFSSL_EC_KEY* ec_priv = wolfSSL_EVP_PKEY_get1_EC_KEY(priv);
    WOLFSSL_EC_KEY* ec_pub = wolfSSL_EVP_PKEY_get1_EC_KEY(pub);
    std::vector<uint8_t> secret(64);
    int secret_len = wolfSSL_ECDH_compute_key(secret.data(), (int)secret.size(),
                                           wolfSSL_EC_KEY_get0_public_key(ec_pub),
                                           ec_priv, nullptr);
    wolfSSL_EC_KEY_free(ec_priv);
    wolfSSL_EC_KEY_free(ec_pub);
    wolfSSL_EVP_PKEY_free(priv);
    wolfSSL_EVP_PKEY_free(pub);
    if (secret_len <= 0) return std::unexpected(CryptoError::OpenSSLError);
    secret.resize(secret_len);
    return secret;
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::extractPublicKey(const std::vector<uint8_t>& priv_der, const SecureString& passphrase) {
    std::vector<uint8_t> working_der = priv_der;
    WOLFSSL_EVP_PKEY* pkey_dec = loadPrivateKeyRobust(priv_der.data(), priv_der.size(), passphrase);
    if (pkey_dec) {
        int len = i2d_PrivateKey(pkey_dec, nullptr);
        if (len > 0) {
            working_der.assign(len, 0);
            uint8_t* p = working_der.data();
            i2d_PrivateKey(pkey_dec, &p);
        }
        wolfSSL_EVP_PKEY_free(pkey_dec);
    }
    std::vector<uint8_t> raw_key = unwrapPqcDer(working_der.data(), working_der.size(), false);
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
    int level = -1;
    if (raw_key.size() == DILITHIUM_LEVEL2_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_44_PRV_KEY_SIZE) level = 2;
    else if (raw_key.size() == DILITHIUM_LEVEL3_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_65_PRV_KEY_SIZE) level = 3;
    else if (raw_key.size() == DILITHIUM_LEVEL5_KEY_SIZE || raw_key.size() == DILITHIUM_ML_DSA_87_PRV_KEY_SIZE) level = 5;

    if (level != -1) {
        dilithium_key key;
        wc_dilithium_init(&key);
        wc_dilithium_set_level(&key, level);
        if (wc_dilithium_import_private(raw_key.data(), (word32)raw_key.size(), &key) == 0) {
            word32 pub_sz = wc_dilithium_pub_size(&key);
            std::vector<uint8_t> pub(pub_sz);
            wc_dilithium_export_public(&key, pub.data(), &pub_sz);
            wc_dilithium_free(&key);
            return wrapPqcDer(pub, (level==2?"ML-DSA-44":level==3?"ML-DSA-65":"ML-DSA-87"), true, nullptr, 0);
        }
        wc_dilithium_free(&key);
    }
#endif

#ifdef WOLFSSL_HAVE_KYBER
    int kyber_type = -1;
    if (raw_key.size() == KYBER512_PRIVATE_KEY_SIZE) kyber_type = WC_ML_KEM_512;
    else if (raw_key.size() == KYBER768_PRIVATE_KEY_SIZE) kyber_type = WC_ML_KEM_768;
    else if (raw_key.size() == KYBER1024_PRIVATE_KEY_SIZE) kyber_type = WC_ML_KEM_1024;

    if (kyber_type != -1) {
        struct KyberKey key;
        wc_KyberKey_Init(kyber_type, &key, nullptr, INVALID_DEVID);
        if (wc_KyberKey_DecodePrivateKey(&key, (unsigned char*)raw_key.data(), (word32)raw_key.size()) == 0) {
            word32 pub_sz = 0;
            wc_KyberKey_PublicKeySize(&key, &pub_sz);
            std::vector<uint8_t> pub(pub_sz);
            wc_KyberKey_EncodePublicKey(&key, pub.data(), pub_sz);
            wc_KyberKey_Free(&key);
            return wrapPqcDer(pub, (kyber_type==WC_ML_KEM_512?"ML-KEM-512":kyber_type==WC_ML_KEM_768?"ML-KEM-768":"ML-KEM-1024"), true, nullptr, 0);
        }
        wc_KyberKey_Free(&key);
    }
#endif

    WOLFSSL_EVP_PKEY* pkey = loadPrivateKeyRobust(priv_der.data(), priv_der.size(), passphrase);
    if (pkey) {
        int pub_len = i2d_PUBKEY(pkey, nullptr);
        std::vector<uint8_t> pub_v(pub_len);
        uint8_t* p_pub = pub_v.data();
        i2d_PUBKEY(pkey, &p_pub);
        wolfSSL_EVP_PKEY_free(pkey);
        return pub_v;
    }

    return std::unexpected(CryptoError::PrivateKeyLoadError);
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> WolfSslBackend::generatePqcSignKeyPair(const std::string& algo_name) {
    WC_RNG rng;
    wc_InitRng(&rng);

#ifdef WOLFSSL_HAVE_KYBER
    int kyber_type = -1;
    if (algo_name == "ML-KEM-512" || algo_name == "Kyber512") kyber_type = WC_ML_KEM_512;
    else if (algo_name == "ML-KEM-768" || algo_name == "Kyber768") kyber_type = WC_ML_KEM_768;
    else if (algo_name == "ML-KEM-1024" || algo_name == "Kyber1024") kyber_type = WC_ML_KEM_1024;

    if (kyber_type != -1) {
        struct KyberKey key;
        if (wc_KyberKey_Init(kyber_type, &key, nullptr, INVALID_DEVID) != 0) { wc_FreeRng(&rng); return std::unexpected(CryptoError::KeyGenerationInitError); }
        
        uint8_t rand_seed[64];
        wc_RNG_GenerateBlock(&rng, rand_seed, 64);
        if (wc_KyberKey_MakeKeyWithRandom(&key, rand_seed, 64) != 0) {
            wc_KyberKey_Free(&key); wc_FreeRng(&rng);
            return std::unexpected(CryptoError::KeyGenerationError);
        }
        word32 priv_sz = 0, pub_sz = 0;
        wc_KyberKey_PrivateKeySize(&key, &priv_sz);
        wc_KyberKey_PublicKeySize(&key, &pub_sz);
        std::vector<uint8_t> priv(priv_sz), pub(pub_sz);
        wc_KyberKey_EncodePrivateKey(&key, priv.data(), priv_sz);
        wc_KyberKey_EncodePublicKey(&key, pub.data(), pub_sz);
        wc_KyberKey_Free(&key); wc_FreeRng(&rng);
        return std::make_pair(wrapPqcDer(priv, algo_name, false, rand_seed, 64), wrapPqcDer(pub, algo_name, true, nullptr, 0));
    }
#endif
#if 0 // defined(HAVE_DILITHIUM) && defined(WOLFSSL_WC_DILITHIUM)
    int dsa_level = -1;
    if (algo_name == "ML-DSA-44" || algo_name == "Dilithium2") dsa_level = 2;
    else if (algo_name == "ML-DSA-65" || algo_name == "Dilithium3") dsa_level = 3;
    else if (algo_name == "ML-DSA-87" || algo_name == "Dilithium5") dsa_level = 5;

    if (dsa_level != -1) {
        dilithium_key key;
        if (wc_dilithium_init(&key) != 0) { wc_FreeRng(&rng); return std::unexpected(CryptoError::KeyGenerationInitError); }
        wc_dilithium_set_level(&key, dsa_level);
        
        uint8_t rand_seed[32];
        wc_RNG_GenerateBlock(&rng, rand_seed, 32);
        if (wc_dilithium_make_key_from_seed(&key, rand_seed) != 0) {
            wc_dilithium_free(&key); wc_FreeRng(&rng);
            return std::unexpected(CryptoError::KeyGenerationError);
        }
        word32 priv_sz = DILITHIUM_MAX_PRV_KEY_SIZE;
        word32 pub_sz = DILITHIUM_MAX_PUB_KEY_SIZE;
        std::vector<uint8_t> priv(priv_sz), pub(pub_sz);
        if (wc_dilithium_export_key(&key, priv.data(), &priv_sz, pub.data(), &pub_sz) != 0) {
            wc_dilithium_free(&key); wc_FreeRng(&rng);
            return std::unexpected(CryptoError::OpenSSLError);
        }
        priv.resize(priv_sz);
        pub.resize(pub_sz);
        wc_dilithium_free(&key); wc_FreeRng(&rng);
        return std::make_pair(wrapPqcDer(priv, algo_name, false, rand_seed, 32), wrapPqcDer(pub, algo_name, true, nullptr, 0));
    }
#endif
    wc_FreeRng(&rng);
    return std::unexpected(CryptoError::OpenSSLError);
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> WolfSslBackend::pqcEncap(const std::vector<uint8_t>& pub_key_der) {
#ifdef WOLFSSL_HAVE_KYBER
    struct KyberKey key;
    std::vector<uint8_t> raw_key = unwrapPqcDer(pub_key_der.data(), pub_key_der.size(), true);
    int kyber_type = -1;
    if (raw_key.size() == KYBER512_PUBLIC_KEY_SIZE) kyber_type = WC_ML_KEM_512;
    else if (raw_key.size() == KYBER768_PUBLIC_KEY_SIZE) kyber_type = WC_ML_KEM_768;
    else if (raw_key.size() == KYBER1024_PUBLIC_KEY_SIZE) kyber_type = WC_ML_KEM_1024;

    if (kyber_type == -1) kyber_type = WC_ML_KEM_768;

    if (wc_KyberKey_Init(kyber_type, &key, nullptr, INVALID_DEVID) != 0) return std::unexpected(CryptoError::OpenSSLError);
    if (wc_KyberKey_DecodePublicKey(&key, (unsigned char*)raw_key.data(), (word32)raw_key.size()) != 0) {
        wc_KyberKey_Free(&key); return std::unexpected(CryptoError::PublicKeyLoadError);
    }
    word32 ct_sz = 0, ss_sz = 0;
    wc_KyberKey_CipherTextSize(&key, &ct_sz);
    wc_KyberKey_SharedSecretSize(&key, &ss_sz);
    std::vector<uint8_t> ct(ct_sz), ss(ss_sz);
    WC_RNG rng; wc_InitRng(&rng);
    if (wc_KyberKey_Encapsulate(&key, ct.data(), ss.data(), &rng) != 0) {
        wc_KyberKey_Free(&key); wc_FreeRng(&rng); return std::unexpected(CryptoError::OpenSSLError);
    }
    wc_KyberKey_Free(&key); wc_FreeRng(&rng);
    return std::make_pair(ss, ct);
#endif
    return std::unexpected(CryptoError::OpenSSLError);
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::pqcDecap(const std::vector<uint8_t>& priv_key_der, const std::vector<uint8_t>& kem_ct, const SecureString& passphrase) {
#ifdef WOLFSSL_HAVE_KYBER
    struct KyberKey key;
    std::vector<uint8_t> working_der = priv_key_der;
    WOLFSSL_EVP_PKEY* pkey_dec = loadPrivateKeyRobust(priv_key_der.data(), priv_key_der.size(), passphrase);
    if (pkey_dec) {
        int len = i2d_PrivateKey(pkey_dec, nullptr);
        if (len > 0) {
            working_der.assign(len, 0);
            uint8_t* p = working_der.data();
            i2d_PrivateKey(pkey_dec, &p);
        }
        wolfSSL_EVP_PKEY_free(pkey_dec);
    }

    std::vector<uint8_t> raw_key = unwrapPqcDer(working_der.data(), working_der.size(), false);
    int kyber_type = -1;
    if (raw_key.size() == KYBER512_PRIVATE_KEY_SIZE) kyber_type = WC_ML_KEM_512;
    else if (raw_key.size() == KYBER768_PRIVATE_KEY_SIZE) kyber_type = WC_ML_KEM_768;
    else if (raw_key.size() == KYBER1024_PRIVATE_KEY_SIZE) kyber_type = WC_ML_KEM_1024;

    if (kyber_type == -1) kyber_type = WC_ML_KEM_768;

    if (wc_KyberKey_Init(kyber_type, &key, nullptr, INVALID_DEVID) != 0) return std::unexpected(CryptoError::OpenSSLError);
    if (wc_KyberKey_DecodePrivateKey(&key, (unsigned char*)raw_key.data(), (word32)raw_key.size()) != 0) {
        wc_KyberKey_Free(&key); return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    word32 ss_sz = 0;
    wc_KyberKey_SharedSecretSize(&key, &ss_sz);
    std::vector<uint8_t> ss(ss_sz);
    if (wc_KyberKey_Decapsulate(&key, ss.data(), (unsigned char*)kem_ct.data(), (word32)kem_ct.size()) != 0) {
        wc_KyberKey_Free(&key); return std::unexpected(CryptoError::OpenSSLError);
    }
    wc_KyberKey_Free(&key);
    return ss;
#endif
    return std::unexpected(CryptoError::OpenSSLError);
}

std::vector<uint8_t> WolfSslBackend::hkdf(const std::vector<uint8_t>& secret, size_t out_len, const std::vector<uint8_t>& salt, const std::string& info, const std::string& md_name) {
    std::vector<uint8_t> out(out_len);
    int hash_type = -1;
    if (md_name.find("3-256") != std::string::npos) hash_type = WC_SHA3_256;
    else if (md_name.find("3-512") != std::string::npos) hash_type = WC_SHA3_512;
    else if (md_name.find("512") != std::string::npos) hash_type = WC_SHA512;
    else if (md_name.find("256") != std::string::npos) hash_type = WC_SHA256;
    else if (md_name.find("SHA3") != std::string::npos) hash_type = WC_SHA3_256;
    else hash_type = WC_SHA256;
    
    wolfssl_hkdf_manual(hash_type, secret.data(), secret.size(), salt.data(), salt.size(), (const uint8_t*)info.data(), info.size(), out.data(), out_len);
    return out;
}

std::expected<void, CryptoError> WolfSslBackend::randomBytes(uint8_t* out, size_t len) {
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) return std::unexpected(CryptoError::OpenSSLError);
    wc_RNG_GenerateBlock(&rng, out, (word32)len);
    wc_FreeRng(&rng);
    return {};
}

void WolfSslBackend::cleanse(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) *p++ = 0;
    }
}

std::string WolfSslBackend::base64Encode(const std::vector<uint8_t>& data) {
    word32 out_len = 0;
    Base64_Encode_NoNl(data.data(), (word32)data.size(), nullptr, &out_len);
    std::string res(out_len, '\0');
    Base64_Encode_NoNl(data.data(), (word32)data.size(), (byte*)res.data(), &out_len);
    if (!res.empty() && res.back() == '\0') res.pop_back();
    return res;
}

std::vector<uint8_t> WolfSslBackend::base64Decode(const std::string& base64_str) {
    std::string stripped;
    stripped.reserve(base64_str.size());
    for (char c : base64_str) if (!std::isspace(static_cast<unsigned char>(c))) stripped += c;
    if (stripped.empty()) return {};
    word32 out_len = (word32)stripped.size();
    std::vector<uint8_t> res(out_len);
    if (Base64_Decode((const byte*)stripped.data(), (word32)stripped.size(), res.data(), &out_len) != 0) return {};
    res.resize(out_len);
    return res;
}

} // namespace nk::backend

#ifdef USE_BACKEND_WOLFSSL
std::shared_ptr<nk::backend::ICryptoBackend> get_nk_backend() {
    static bool initialized = false;
    if (!initialized) {
        wolfCrypt_Init();
        wolfSSL_library_init();
        wolfSSL_ERR_load_crypto_strings();
        wolfSSL_EVP_add_cipher(wolfSSL_EVP_aes_256_gcm());
        wolfSSL_EVP_add_cipher(wolfSSL_EVP_aes_128_gcm());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha256());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_224());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_256());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_384());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_512());
        wolfSSL_OBJ_create("1.2.840.10045.3.1.7", "prime256v1", "ASN1 prime256v1");
        initialized = true;
    }
    static auto instance = std::make_shared<nk::backend::WolfSslBackend>();
    return instance;
}
#endif
