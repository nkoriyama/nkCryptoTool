#include "WolfSslBackend.hpp"
#include <wolfssl/options.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/bn.h>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace nk::backend {

// エラー詳細を表示するヘルパー
static void printWolfError(const std::string& context) {
    unsigned long err = wolfSSL_ERR_get_error();
    char err_buf[256];
    wolfSSL_ERR_error_string_n(err, err_buf, sizeof(err_buf));
    std::cerr << "[WolfSSL Error] " << context << ": " << err_buf << " (code: " << err << ")" << std::endl;
}

// --- WolfSslAeadBackend ---

WolfSslAeadBackend::WolfSslAeadBackend(WOLFSSL_EVP_CIPHER_CTX* ctx) : ctx_(ctx) {}
WolfSslAeadBackend::~WolfSslAeadBackend() { wolfSSL_EVP_CIPHER_CTX_free(ctx_); }

std::expected<size_t, CryptoError> WolfSslAeadBackend::update(const uint8_t* in, size_t in_len, uint8_t* out) {
    int out_l = 0;
    if (wolfSSL_EVP_CipherUpdate(ctx_, out, &out_l, in, (int)in_len) <= 0) {
        printWolfError("AEAD Update");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return (size_t)out_l;
}

std::expected<size_t, CryptoError> WolfSslAeadBackend::finalize(uint8_t* out) {
    int out_l = 0;
    // Decryption final might fail if tag is not yet set, which is handled in getTag/setTag
    wolfSSL_EVP_CipherFinal(ctx_, out, &out_l);
    return (size_t)out_l;
}

std::expected<void, CryptoError> WolfSslAeadBackend::getTag(uint8_t* tag, size_t tag_len) {
    if (wolfSSL_EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag) <= 0) {
        printWolfError("AEAD GetTag");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

std::expected<void, CryptoError> WolfSslAeadBackend::setTag(const uint8_t* tag, size_t tag_len) {
    if (wolfSSL_EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void*)tag) <= 0) {
        printWolfError("AEAD SetTag");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

// --- WolfSslHashBackend ---

WolfSslHashBackend::WolfSslHashBackend(WOLFSSL_EVP_MD_CTX* ctx, const WOLFSSL_EVP_MD* md) : ctx_(ctx), md_(md) {}
WolfSslHashBackend::~WolfSslHashBackend() {
    wolfSSL_EVP_MD_CTX_free(ctx_);
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
}

std::expected<void, CryptoError> WolfSslHashBackend::update(const uint8_t* data, size_t len) {
    if (pkey_) {
        if (wolfSSL_EVP_DigestSignUpdate(ctx_, data, len) <= 0 && 
            wolfSSL_EVP_DigestVerifyUpdate(ctx_, data, len) <= 0) {
            return std::unexpected(CryptoError::OpenSSLError);
        }
    }
    return {};
}

std::expected<void, CryptoError> WolfSslHashBackend::initSign(const std::vector<uint8_t>& priv_key_der) {
    const uint8_t* p = priv_key_der.data();
    WOLFSSL_EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)priv_key_der.size());
    if (!pkey) {
        p = priv_key_der.data();
        pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, (long)priv_key_der.size());
    }
    if (!pkey) {
        printWolfError("Sign Key Load");
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
    pkey_ = pkey;

    wolfSSL_EVP_MD_CTX_cleanup(ctx_);
    wolfSSL_EVP_MD_CTX_init(ctx_);
    if (wolfSSL_EVP_DigestSignInit(ctx_, nullptr, md_, nullptr, pkey_) <= 0) {
        printWolfError("DigestSignInit");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslHashBackend::finalizeSign() {
    size_t slen = 0;
    wolfSSL_EVP_DigestSignFinal(ctx_, nullptr, &slen);
    std::vector<uint8_t> sig(slen);
    if (wolfSSL_EVP_DigestSignFinal(ctx_, sig.data(), &slen) <= 0) {
        printWolfError("DigestSignFinal");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    sig.resize(slen);
    return sig;
}

std::expected<void, CryptoError> WolfSslHashBackend::initVerify(const std::vector<uint8_t>& pub_key_der) {
    const uint8_t* p = pub_key_der.data();
    WOLFSSL_EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, (long)pub_key_der.size());
    if (!pkey) {
        printWolfError("Verify Key Load");
        return std::unexpected(CryptoError::PublicKeyLoadError);
    }
    if (pkey_) wolfSSL_EVP_PKEY_free(pkey_);
    pkey_ = pkey;

    wolfSSL_EVP_MD_CTX_cleanup(ctx_);
    wolfSSL_EVP_MD_CTX_init(ctx_);
    if (wolfSSL_EVP_DigestVerifyInit(ctx_, nullptr, md_, nullptr, pkey_) <= 0) {
        printWolfError("DigestVerifyInit");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    return {};
}

std::expected<bool, CryptoError> WolfSslHashBackend::finalizeVerify(const std::vector<uint8_t>& signature) {
    int res = wolfSSL_EVP_DigestVerifyFinal(ctx_, (unsigned char*)signature.data(), signature.size());
    if (res == 1) return true;
    if (res == 0) return false;
    printWolfError("DigestVerifyFinal");
    return std::unexpected(CryptoError::OpenSSLError);
}

// --- WolfSslBackend ---

std::expected<std::unique_ptr<IAeadBackend>, CryptoError> WolfSslBackend::createAead(const std::string& cipher_name, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, bool encrypt) {
    const WOLFSSL_EVP_CIPHER* cipher = wolfSSL_EVP_get_cipherbyname(cipher_name.c_str());
    if (!cipher) return std::unexpected(CryptoError::OpenSSLError);
    
    WOLFSSL_EVP_CIPHER_CTX* ctx = wolfSSL_EVP_CIPHER_CTX_new();
    if (encrypt) {
        wolfSSL_EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
        wolfSSL_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        if (wolfSSL_EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) <= 0) {
            printWolfError("EncryptInit");
            return std::unexpected(CryptoError::OpenSSLError);
        }
    } else {
        wolfSSL_EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
        wolfSSL_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        if (wolfSSL_EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) <= 0) {
            printWolfError("DecryptInit");
            return std::unexpected(CryptoError::OpenSSLError);
        }
    }
    return std::make_unique<WolfSslAeadBackend>(ctx);
}

std::expected<std::unique_ptr<IHashBackend>, CryptoError> WolfSslBackend::createHash(const std::string& algo_name) {
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_get_digestbyname(algo_name.c_str());
    if (!md) return std::unexpected(CryptoError::OpenSSLError);
    return std::make_unique<WolfSslHashBackend>(wolfSSL_EVP_MD_CTX_new(), md);
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, CryptoError> WolfSslBackend::generateEccKeyPair(const std::string& curve_name) {
    int nid = wolfSSL_OBJ_sn2nid(curve_name.c_str());
    if (nid == NID_undef && curve_name == "prime256v1") nid = wolfSSL_OBJ_sn2nid("P-256");
    if (nid == NID_undef) return std::unexpected(CryptoError::ParameterError);

    WOLFSSL_EC_KEY* eckey = wolfSSL_EC_KEY_new_by_curve_name(nid);
    if (!eckey || wolfSSL_EC_KEY_generate_key(eckey) <= 0) {
        if (eckey) wolfSSL_EC_KEY_free(eckey);
        printWolfError("ECC KeyGen");
        return std::unexpected(CryptoError::KeyGenerationError);
    }
    
    // NKCT互換のために PKCS#8 形式を目指すが、まずは EVP_PKEY 経由での出力を試す
    WOLFSSL_EVP_PKEY* pkey = wolfSSL_EVP_PKEY_new();
    wolfSSL_EVP_PKEY_assign_EC_KEY(pkey, eckey); 

    int priv_len = i2d_PrivateKey(pkey, nullptr);
    if (priv_len <= 0) {
        printWolfError("i2d_PrivateKey (len)");
        wolfSSL_EVP_PKEY_free(pkey);
        return std::unexpected(CryptoError::OpenSSLError);
    }
    std::vector<uint8_t> priv_v(priv_len);
    uint8_t* p_priv = priv_v.data();
    i2d_PrivateKey(pkey, &p_priv);

    int pub_len = i2d_PUBKEY(pkey, nullptr);
    std::vector<uint8_t> pub_v(pub_len);
    uint8_t* p_pub = pub_v.data();
    i2d_PUBKEY(pkey, &p_pub);
    
    wolfSSL_EVP_PKEY_free(pkey);
    return std::make_pair(priv_v, pub_v);
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::eccDh(const std::vector<uint8_t>& priv_der, const std::vector<uint8_t>& pub_der) {
    const uint8_t* p1 = priv_der.data();
    WOLFSSL_EVP_PKEY* priv = d2i_AutoPrivateKey(nullptr, &p1, (long)priv_der.size());
    if (!priv) {
        p1 = priv_der.data();
        priv = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p1, (long)priv_der.size());
    }
    const uint8_t* p2 = pub_der.data();
    WOLFSSL_EVP_PKEY* pub = d2i_PUBKEY(nullptr, &p2, (long)pub_der.size());
    
    if (!priv || !pub) {
        if (priv) wolfSSL_EVP_PKEY_free(priv);
        if (pub) wolfSSL_EVP_PKEY_free(pub);
        printWolfError("DH Key Load");
        return std::unexpected(CryptoError::PrivateKeyLoadError);
    }

    WOLFSSL_EVP_PKEY_CTX* ctx = wolfSSL_EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx || wolfSSL_EVP_PKEY_derive_init(ctx) <= 0 || wolfSSL_EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        if (ctx) wolfSSL_EVP_PKEY_CTX_free(ctx);
        wolfSSL_EVP_PKEY_free(priv); wolfSSL_EVP_PKEY_free(pub);
        printWolfError("DH Derive Init");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    size_t slen = 0; 
    wolfSSL_EVP_PKEY_derive(ctx, nullptr, &slen);
    std::vector<uint8_t> secret(slen);
    if (wolfSSL_EVP_PKEY_derive(ctx, secret.data(), &slen) <= 0) {
        wolfSSL_EVP_PKEY_CTX_free(ctx);
        wolfSSL_EVP_PKEY_free(priv); wolfSSL_EVP_PKEY_free(pub);
        printWolfError("DH Derive Exec");
        return std::unexpected(CryptoError::OpenSSLError);
    }
    secret.resize(slen);
    
    wolfSSL_EVP_PKEY_free(priv); wolfSSL_EVP_PKEY_free(pub);
    wolfSSL_EVP_PKEY_CTX_free(ctx);
    return secret;
}

std::expected<std::vector<uint8_t>, CryptoError> WolfSslBackend::extractPublicKey(const std::vector<uint8_t>& priv_der) {
    const uint8_t* p = priv_der.data();
    WOLFSSL_EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)priv_der.size());
    if (!pkey) {
        p = priv_der.data();
        pkey = d2i_PrivateKey(EVP_PKEY_EC, nullptr, &p, (long)priv_der.size());
    }
    if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
    
    int pub_len = i2d_PUBKEY(pkey, nullptr);
    std::vector<uint8_t> pub_v(pub_len);
    uint8_t* p_pub = pub_v.data();
    i2d_PUBKEY(pkey, &p_pub);
    wolfSSL_EVP_PKEY_free(pkey);
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
    const WOLFSSL_EVP_MD* md = wolfSSL_EVP_get_digestbyname(md_name.c_str());
    if (!md) md = wolfSSL_EVP_sha256();
    wc_HKDF(wolfSSL_EVP_MD_type(md), secret.data(), (word32)secret.size(), salt.data(), (word32)salt.size(), (const byte*)info.data(), (word32)info.size(), out.data(), (word32)out_len);
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
    for (char c : base64_str) {
        if (!std::isspace(static_cast<unsigned char>(c))) stripped += c;
    }
    
    word32 out_len = 0;
    if (Base64_Decode((const byte*)stripped.data(), (word32)stripped.size(), nullptr, &out_len) != 0) return {};
    std::vector<uint8_t> res(out_len);
    if (Base64_Decode((const byte*)stripped.data(), (word32)stripped.size(), res.data(), &out_len) != 0) return {};
    res.resize(out_len);
    return res;
}

#ifdef USE_BACKEND_WOLFSSL
std::shared_ptr<ICryptoBackend> getBackend() {
    static bool initialized = false;
    if (!initialized) {
        wolfSSL_library_init();
        wolfSSL_ERR_load_crypto_strings(); // エラー文字列をロード
        wolfSSL_EVP_add_cipher(wolfSSL_EVP_aes_256_gcm());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha256());
        wolfSSL_EVP_add_digest(wolfSSL_EVP_sha3_256());
        initialized = true;
    }
    static auto instance = std::make_shared<WolfSslBackend>();
    return instance;
}
#endif

} // namespace nk::backend
