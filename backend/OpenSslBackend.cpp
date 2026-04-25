#include "OpenSslBackend.hpp"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdexcept>
#include <cstring>
#include <iostream>

namespace nk::backend {

// --- OpenSslAeadBackend ---

OpenSslAeadBackend::OpenSslAeadBackend(std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter> ctx)
    : ctx_(std::move(ctx)) {}

std::expected<size_t, CryptoError> OpenSslAeadBackend::update(const uint8_t* in, size_t in_len, uint8_t* out) {
    int out_l = 0;
    if (EVP_CipherUpdate(ctx_.get(), out, &out_l, in, (int)in_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return (size_t)out_l;
}

std::expected<size_t, CryptoError> OpenSslAeadBackend::finalize(uint8_t* out) {
    int out_l = 0;
    if (EVP_CipherFinal_ex(ctx_.get(), out, &out_l) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return (size_t)out_l;
}

std::expected<void, CryptoError> OpenSslAeadBackend::getTag(uint8_t* tag, size_t tag_len) {
    if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::expected<void, CryptoError> OpenSslAeadBackend::setTag(const uint8_t* tag, size_t tag_len) {
    if (EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

// --- OpenSslHashBackend ---

OpenSslHashBackend::OpenSslHashBackend(std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter> ctx, const EVP_MD* md)
    : ctx_(std::move(ctx)), md_(md) {}

std::expected<void, CryptoError> OpenSslHashBackend::update(const uint8_t* data, size_t len) {
    // ストリーミングがサポートされていない場合に備え、バッファにも蓄積する
    buffer_.insert(buffer_.end(), data, data + len);
    
    // ストリーミング可能な場合は Update も呼んでおく（ECDSA用）
    // エラーは一旦無視する（PQCでは失敗するため）
    EVP_DigestSignUpdate(ctx_.get(), data, len);
    EVP_DigestVerifyUpdate(ctx_.get(), data, len);
    
    return {};
}

std::expected<void, CryptoError> OpenSslHashBackend::initSign(const std::vector<uint8_t>& priv_key_der) {
    const uint8_t* p = priv_key_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)priv_key_der.size());
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    pkey_ = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    
    EVP_MD_CTX_reset(ctx_.get());
    buffer_.clear();
    
    // PQC (ML-DSA) の場合は MD を指定せずに Init する必要がある場合がある
    // ここではストラテジーが指定した MD を試みる
    if (EVP_DigestSignInit(ctx_.get(), nullptr, md_, nullptr, pkey_.get()) <= 0) {
        // 失敗した場合は MD なしで試行
        if (EVP_DigestSignInit(ctx_.get(), nullptr, nullptr, nullptr, pkey_.get()) <= 0) {
            return std::unexpected(CryptoError::OpenSSLError);
        }
    }
    return {};
}

std::expected<std::vector<uint8_t>, CryptoError> OpenSslHashBackend::finalizeSign() {
    size_t slen = 0;
    // まずストリーミングでの完了を試みる
    if (EVP_DigestSignFinal(ctx_.get(), nullptr, &slen) > 0) {
        std::vector<uint8_t> sig(slen);
        if (EVP_DigestSignFinal(ctx_.get(), sig.data(), &slen) > 0) {
            sig.resize(slen);
            return sig;
        }
    }
    
    // ストリーミングが失敗した（PQC等）場合は、一括（One-shot）で署名する
    if (EVP_DigestSign(ctx_.get(), nullptr, &slen, buffer_.data(), buffer_.size()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    std::vector<uint8_t> sig(slen);
    if (EVP_DigestSign(ctx_.get(), sig.data(), &slen, buffer_.data(), buffer_.size()) <= 0) {
        return std::unexpected(CryptoError::OpenSSLError);
    }
    sig.resize(slen);
    return sig;
}

std::expected<void, CryptoError> OpenSslHashBackend::initVerify(const std::vector<uint8_t>& pub_key_der) {
    const uint8_t* p = pub_key_der.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)pub_key_der.size());
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    pkey_ = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    
    EVP_MD_CTX_reset(ctx_.get());
    buffer_.clear();
    
    if (EVP_DigestVerifyInit(ctx_.get(), nullptr, md_, nullptr, pkey_.get()) <= 0) {
        if (EVP_DigestVerifyInit(ctx_.get(), nullptr, nullptr, nullptr, pkey_.get()) <= 0) {
            return std::unexpected(CryptoError::OpenSSLError);
        }
    }
    return {};
}

std::expected<bool, CryptoError> OpenSslHashBackend::finalizeVerify(const std::vector<uint8_t>& signature) {
    // ストリーミングでの検証を試みる
    if (EVP_DigestVerifyFinal(ctx_.get(), signature.data(), signature.size()) == 1) return true;
    
    // 失敗した場合は一括検証を試みる
    int res = EVP_DigestVerify(ctx_.get(), signature.data(), signature.size(), buffer_.data(), buffer_.size());
    if (res == 1) return true;
    if (res == 0) return false;
    return std::unexpected(CryptoError::OpenSSLError);
}

// --- OpenSslBackend ---

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

std::expected<std::vector<uint8_t>, CryptoError> OpenSslBackend::eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der) {
    const uint8_t* p1 = priv_der.data();
    EVP_PKEY* priv = d2i_AutoPrivateKey(nullptr, &p1, (long)priv_der.size());
    const uint8_t* p2 = pub_der.data();
    EVP_PKEY* pub = d2i_PUBKEY(nullptr, &p2, (long)pub_der.size());
    if (!priv || !pub) return std::unexpected(CryptoError::KeyGenerationError);
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

std::expected<std::vector<uint8_t>, CryptoError> OpenSslBackend::extractPublicKey(const std::vector<uint8_t>& priv_der) {
    const uint8_t* p = priv_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)priv_der.size());
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);
    
    uint8_t *pub = nullptr;
    int pub_len = i2d_PUBKEY(spkey.get(), &pub);
    if (pub_len <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> pub_v(pub, pub + pub_len);
    OPENSSL_free(pub);
    return pub_v;
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> OpenSslBackend::generatePqcSignKeyPair(const std::string& algo_name) {
    std::string name = algo_name;
    if (name == "ML-DSA-87") name = "mldsa87";
    else if (name == "ML-DSA-65") name = "mldsa65";
    else if (name == "ML-DSA-44") name = "mldsa44";
    else if (name == "ML-KEM-1024") name = "mlkem1024";
    else if (name == "ML-KEM-768") name = "mlkem768";
    else if (name == "ML-KEM-512") name = "mlkem512";

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> pctx(EVP_PKEY_CTX_new_from_name(nullptr, name.c_str(), nullptr));
    if (!pctx) return std::unexpected(CryptoError::OpenSSLError);
    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) return std::unexpected(CryptoError::KeyGenerationInitError);
    
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

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> OpenSslBackend::pqcEncap(const std::vector<uint8_t>& pub_key_der) {
    const uint8_t* p = pub_key_der.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)pub_key_der.size());
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(spkey.get(), nullptr));
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    size_t secret_len, ct_len;
    if (EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &secret_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> secret(secret_len), ct(ct_len);
    if (EVP_PKEY_encapsulate(ctx.get(), ct.data(), &ct_len, secret.data(), &secret_len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    return std::make_pair(secret, ct);
}

std::expected<std::vector<uint8_t>, CryptoError> OpenSslBackend::pqcDecap(const std::vector<uint8_t>& priv_key_der, const std::vector<uint8_t>& kem_ct) {
    const uint8_t* p = priv_key_der.data();
    EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)priv_key_der.size());
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> spkey(pkey);

    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter> ctx(EVP_PKEY_CTX_new(spkey.get(), nullptr));
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    size_t secret_len;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &secret_len, (const unsigned char*)kem_ct.data(), kem_ct.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_decapsulate(ctx.get(), secret.data(), &secret_len, (const unsigned char*)kem_ct.data(), kem_ct.size()) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    
    return secret;
}

std::vector<uint8_t> OpenSslBackend::hkdf(const std::vector<uint8_t>& secret, size_t out_len, const std::vector<uint8_t>& salt, const std::string& info, const std::string& md_name) {
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
    std::vector<uint8_t> out(out_len);
    EVP_KDF_derive(kctx.get(), out.data(), out_len, params);
    return out;
}

std::expected<void, CryptoError> OpenSslBackend::randomBytes(uint8_t* out, size_t len) {
    if (RAND_bytes(out, (int)len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::shared_ptr<ICryptoBackend> getBackend() {
    static auto instance = std::make_shared<OpenSslBackend>();
    return instance;
}

} // namespace nk::backend
