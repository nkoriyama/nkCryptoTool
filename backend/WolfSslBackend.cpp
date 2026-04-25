#include "WolfSslBackend.hpp"
#include <wolfssl/options.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/evp.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace nk::backend {

static void printWolfCryptError(const std::string& context, int ret) {
    if (ret == 0) return;
    char err_buf[80];
    wc_ErrorString(ret, err_buf);
    std::cerr << "[WolfCrypt Trace] " << context << " FAILED: " << err_buf << " (" << ret << ")" << std::endl;
}

static int loadEccPubKeyNative(const uint8_t* der, size_t len, ecc_key* key) {
    if (!der || len == 0) return -1;
    word32 idx = 0;
    int ret = wc_EccPublicKeyDecode(der, &idx, key, (word32)len);
    if (ret == 0) return 0;
    ret = wc_ecc_import_x963(der, (word32)len, key);
    return ret;
}

static int loadEccPrivKeyNative(const uint8_t* der, size_t len, ecc_key* key) {
    if (!der || len == 0) return -1;
    word32 idx = 0;
    return wc_EccPrivateKeyDecode(der, &idx, key, (word32)len);
}

// --- WolfSslAeadBackend ---

WolfSslAeadBackend::WolfSslAeadBackend(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt)
    : encrypt_(encrypt) {
    wc_AesGcmInit(&aes_, key.data(), (word32)key.size(), iv.data(), (word32)iv.size());
}

WolfSslAeadBackend::~WolfSslAeadBackend() {
    // No explicit free for Aes struct needed in standard wolfCrypt unless hardware used
}

std::expected<size_t, CryptoError> WolfSslAeadBackend::update(const uint8_t* in, size_t in_len, uint8_t* out) {
    int ret;
    if (encrypt_) {
        ret = wc_AesGcmEncryptUpdate(&aes_, out, in, (word32)in_len, nullptr, 0);
    } else {
        ret = wc_AesGcmDecryptUpdate(&aes_, out, in, (word32)in_len, nullptr, 0);
    }
    if (ret != 0) {
        printWolfCryptError("AES-GCM Update", ret);
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return in_len;
}

std::expected<size_t, CryptoError> WolfSslAeadBackend::finalize(uint8_t*) {
    return (size_t)0;
}

std::expected<void, CryptoError> WolfSslAeadBackend::getTag(uint8_t* tag, size_t tag_len) {
    int ret = wc_AesGcmEncryptFinal(&aes_, tag, (word32)tag_len);
    if (ret != 0) {
        printWolfCryptError("AES-GCM getTag", ret);
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

std::expected<void, CryptoError> WolfSslAeadBackend::setTag(const uint8_t* tag, size_t tag_len) {
    tag_.assign(tag, tag + tag_len);
    int ret = wc_AesGcmDecryptFinal(&aes_, tag_.data(), (word32)tag_.size());
    if (ret != 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

// --- WolfSslHashBackend ---

WolfSslHashBackend::WolfSslHashBackend(WOLFSSL_EVP_MD_CTX* ctx, const WOLFSSL_EVP_MD* md) : ctx_(ctx), md_(md), is_sign_(false) {}
WolfSslHashBackend::~WolfSslHashBackend() {
    wolfSSL_EVP_MD_CTX_free(ctx_);
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
}

std::expected<void, CryptoError> WolfSslHashBackend::update(const uint8_t* data, size_t len) {
    if (is_sign_) {
        if (wolfSSL_EVP_DigestSignUpdate(ctx_, data, len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    } else {
        if (wolfSSL_EVP_DigestVerifyUpdate(ctx_, data, len) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

std::expected<void, CryptoError> WolfSslHashBackend::initSign(const std::vector<uint8_t>& priv_key_der) {
    const uint8_t* p = priv_key_der.data();
    WOLFSSL_EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)priv_key_der.size());
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
    pkey_ = pkey;
    is_sign_ = true;
    if (wolfSSL_EVP_DigestSignInit(ctx_, nullptr, md_, nullptr, pkey_) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslHashBackend::finalizeSign() {
    size_t slen = 0;
    if (wolfSSL_EVP_DigestSignFinal(ctx_, nullptr, &slen) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    std::vector<uint8_t> sig(slen);
    if (wolfSSL_EVP_DigestSignFinal(ctx_, sig.data(), &slen) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    sig.resize(slen);
    return sig;
}

std::expected<void, CryptoError> WolfSslHashBackend::initVerify(const std::vector<uint8_t>& pub_key_der) {
    const uint8_t* p = pub_key_der.data();
    WOLFSSL_EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)pub_key_der.size());
    if (!pkey) {
        ecc_key tmp_key;
        wc_ecc_init(&tmp_key);
        if (loadEccPubKeyNative(pub_key_der.data(), pub_key_der.size(), &tmp_key) == 0) {
            pkey = wolfSSL_EVP_PKEY_new();
            WOLFSSL_EC_KEY* eckey = wolfSSL_EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            p = pub_key_der.data();
            if (wolfSSL_o2i_ECPublicKey(&eckey, &p, (long)pub_key_der.size())) {
                wolfSSL_EVP_PKEY_assign_EC_KEY(pkey, eckey);
            } else {
                wolfSSL_EC_KEY_free(eckey);
                wolfSSL_EVP_PKEY_free(pkey);
                pkey = nullptr;
            }
        }
        wc_ecc_free(&tmp_key);
    }
    if (!pkey) return std::unexpected(CryptoError::PublicKeyLoadError);
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
    pkey_ = pkey;
    is_sign_ = false;
    if (wolfSSL_EVP_DigestVerifyInit(ctx_, nullptr, md_, nullptr, pkey_) <= 0) return std::unexpected(CryptoError::OpenSSLError);
    return {};
}

std::expected<bool, CryptoError> WolfSslHashBackend::finalizeVerify(const std::vector<uint8_t>& signature) {
    return wolfSSL_EVP_DigestVerifyFinal(ctx_, (unsigned char*)signature.data(), signature.size()) == 1;
}

// --- WolfSslBackend ---

std::expected<std::unique_ptr<IAeadBackend>, CryptoError> WolfSslBackend::createAead(const std::string&, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt) {
    return std::make_unique<WolfSslAeadBackend>(key, iv, encrypt);
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
    int priv_len = wc_EccKeyToDer(&key, priv_v.data(), (word32)priv_v.size());
    priv_v.resize(priv_len);

    std::vector<uint8_t> pub_v(1024);
    int pub_len = wc_EccPublicKeyToDer(&key, pub_v.data(), (word32)pub_v.size(), 1); // 1 = SPKI
    pub_v.resize(pub_len);

    wc_ecc_free(&key); wc_FreeRng(&rng);
    return std::make_pair(priv_v, pub_v);
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der) {
    ecc_key priv, pub;
    wc_ecc_init(&priv);
    wc_ecc_init(&pub);

    if (loadEccPrivKeyNative(priv_der.data(), priv_der.size(), &priv) != 0) { wc_ecc_free(&priv); wc_ecc_free(&pub); return std::unexpected(CryptoError::PrivateKeyLoadError); }
    if (loadEccPubKeyNative(pub_der.data(), pub_der.size(), &pub) != 0) { wc_ecc_free(&priv); wc_ecc_free(&pub); return std::unexpected(CryptoError::PublicKeyLoadError); }

    std::vector<uint8_t> secret(64);
    word32 secret_sz = (word32)secret.size();
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_set_rng(&priv, &rng);
    int ret = wc_ecc_shared_secret(&priv, &pub, secret.data(), &secret_sz);
    wc_FreeRng(&rng);
    
    wc_ecc_free(&priv); wc_ecc_free(&pub);

    if (ret != 0) return std::unexpected(CryptoError::OpenSSLError);
    secret.resize(secret_sz);
    return secret;
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::extractPublicKey(const std::vector<uint8_t>& priv_der) {
    ecc_key key;
    wc_ecc_init(&key);
    if (loadEccPrivKeyNative(priv_der.data(), priv_der.size(), &key) != 0) { wc_ecc_free(&key); return std::unexpected(CryptoError::PrivateKeyLoadError); }
    std::vector<uint8_t> pub_v(1024);
    int pub_len = wc_EccPublicKeyToDer(&key, pub_v.data(), (word32)pub_v.size(), 1);
    wc_ecc_free(&key);
    pub_v.resize(pub_len);
    return pub_v;
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> WolfSslBackend::generatePqcSignKeyPair(const std::string&) {
    return std::unexpected(CryptoError::OpenSSLError);
}
std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> WolfSslBackend::pqcEncap(const std::vector<uint8_t>&) {
    return std::unexpected(CryptoError::OpenSSLError);
}
std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::pqcDecap(const std::vector<uint8_t>&, const std::vector<uint8_t>&) {
    return std::unexpected(CryptoError::OpenSSLError);
}

std::vector<uint8_t> WolfSslBackend::hkdf(const std::vector<uint8_t>& secret, size_t out_len, const std::vector<uint8_t>& salt, const std::string& info, const std::string& md_name) {
    std::vector<uint8_t> out(out_len);
    int type = WC_SHA256;
    if (md_name == "SHA3-256") type = WC_SHA3_256;
    else if (md_name == "SHA3-512") type = WC_SHA3_512;
    wc_HKDF(type, secret.data(), (word32)secret.size(), salt.data(), (word32)salt.size(), (const byte*)info.data(), (word32)info.size(), out.data(), (word32)out_len);
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

#ifdef USE_BACKEND_WOLFSSL
std::shared_ptr<ICryptoBackend> getBackend() {
    static bool initialized = false;
    if (!initialized) {
        wolfCrypt_Init();
        wolfSSL_library_init();
        wolfSSL_ERR_load_crypto_strings();
        wolfSSL_EVP_add_cipher(wolfSSL_EVP_aes_256_gcm());
        wolfSSL_EVP_add_cipher(wolfSSL_EVP_aes_128_gcm());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha256());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_256());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_512());
        wolfSSL_OBJ_create("1.2.840.10045.3.1.7", "prime256v1", "ASN1 prime256v1");
        initialized = true;
    }
    static auto instance = std::make_shared<WolfSslBackend>();
    return instance;
}
#endif

} // namespace nk::backend
