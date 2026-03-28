#ifndef TPM_UTILS_HPP
#define TPM_UTILS_HPP

#include <vector>
#include <string>
#include <expected>
#include <cstring>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include "CryptoError.hpp"
#include "ICryptoStrategy.hpp"

extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

class TPMUtils {
public:
    static constexpr const char* TPM_WRAPPED_HEADER = "-----BEGIN TPM WRAPPED PRIVATE KEY-----";
    static constexpr const char* TPM_WRAPPED_FOOTER = "-----END TPM WRAPPED PRIVATE KEY-----";
    static constexpr const char* TPM_WRAPPED_ENC_HEADER = "-----BEGIN TPM WRAPPED ENCRYPTED PRIVATE KEY-----";
    static constexpr const char* TPM_WRAPPED_ENC_FOOTER = "-----END TPM WRAPPED ENCRYPTED PRIVATE KEY-----";

    static std::expected<std::string, CryptoError> wrapKey(EVP_PKEY* raw_pkey, const std::string& passphrase = "") {
        if (!raw_pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        std::unique_ptr<BIO, BIO_Deleter> mem_bio(BIO_new(BIO_s_mem()));
        
        const EVP_CIPHER* cipher = passphrase.empty() ? nullptr : EVP_aes_256_cbc();
        void* pwd = passphrase.empty() ? nullptr : (void*)passphrase.c_str();

        // 1. TPM2プロバイダ経由でのインポートを試みる
        unsigned char* der = nullptr;
        int der_len = i2d_PrivateKey(raw_pkey, &der);
        if (der_len > 0) {
            const unsigned char* p = der;
            EVP_PKEY* tpm_pkey = d2i_PrivateKey_ex(EVP_PKEY_NONE, nullptr, &p, (long)der_len, nullptr, "provider=tpm2");
            if (tpm_pkey) {
                std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> tpm_key_ptr(tpm_pkey);
                PEM_write_bio_PKCS8PrivateKey(mem_bio.get(), tpm_key_ptr.get(), cipher, (char*)pwd, (int)passphrase.length(), nullptr, nullptr);
            }
            OPENSSL_free(der);
        }

        // 2. 失敗した場合は通常のPEM書き出し (PQC用)
        if (BIO_ctrl_pending(mem_bio.get()) == 0) {
            PEM_write_bio_PKCS8PrivateKey(mem_bio.get(), raw_pkey, cipher, (char*)pwd, (int)passphrase.length(), nullptr, nullptr);
        }

        BUF_MEM* bptr;
        BIO_get_mem_ptr(mem_bio.get(), &bptr);
        std::string pem(bptr->data, bptr->length);

        // 文字列置換 (長いものから順に行う)
        auto replace_header = [&](std::string& target, const std::string& from, const std::string& to) {
            size_t p = target.find(from);
            if (p != std::string::npos) target.replace(p, from.length(), to);
        };

        if (!passphrase.empty()) {
            // パスフレーズがある場合
            replace_header(pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----", TPM_WRAPPED_ENC_HEADER);
            replace_header(pem, "-----BEGIN PRIVATE KEY-----", TPM_WRAPPED_ENC_HEADER);
            replace_header(pem, "-----END ENCRYPTED PRIVATE KEY-----", TPM_WRAPPED_ENC_FOOTER);
            replace_header(pem, "-----END PRIVATE KEY-----", TPM_WRAPPED_ENC_FOOTER);
        } else {
            // パスフレーズがない場合
            replace_header(pem, "-----BEGIN PRIVATE KEY-----", TPM_WRAPPED_HEADER);
            replace_header(pem, "-----BEGIN TSS2 PRIVATE KEY-----", TPM_WRAPPED_HEADER);
            replace_header(pem, "-----END PRIVATE KEY-----", TPM_WRAPPED_FOOTER);
            replace_header(pem, "-----END TSS2 PRIVATE KEY-----", TPM_WRAPPED_FOOTER);
        }

        return pem;
    }

    static std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> unwrapKey(const std::string& wrapped_pem, const std::string& passphrase = "") {
        void* pwd = passphrase.empty() ? nullptr : (void*)passphrase.c_str();
        
        auto try_load = [&](const std::string& target_pem) -> EVP_PKEY* {
            std::unique_ptr<BIO, BIO_Deleter> mem_bio(BIO_new_mem_buf(target_pem.data(), (int)target_pem.size()));
            return PEM_read_bio_PrivateKey(mem_bio.get(), nullptr, pem_passwd_cb, pwd);
        };

        std::string pem = wrapped_pem;
        // 文字列長の変化によるズレを防ぐため、常に新しい文字列を作るか、慎重に置換する
        auto multi_replace = [&](std::string s) -> std::string {
            auto r = [&](std::string& target, const std::string& from, const std::string& to) {
                size_t p = target.find(from);
                if (p != std::string::npos) target.replace(p, from.length(), to);
            };
            // 暗号化ヘッダーの復元
            r(s, TPM_WRAPPED_ENC_HEADER, "-----BEGIN ENCRYPTED PRIVATE KEY-----");
            r(s, TPM_WRAPPED_ENC_FOOTER, "-----END ENCRYPTED PRIVATE KEY-----");
            // 通常ヘッダーの復元
            r(s, TPM_WRAPPED_HEADER, "-----BEGIN PRIVATE KEY-----");
            r(s, TPM_WRAPPED_FOOTER, "-----END PRIVATE KEY-----");
            return s;
        };

        // 1. まず復元を試みる
        EVP_PKEY* pkey = try_load(multi_replace(pem));
        
        // 2. 失敗した場合は TSS2 形式（TPMネイティブ）として試行
        if (!pkey) {
            std::string tss_pem = pem;
            size_t pos = tss_pem.find(TPM_WRAPPED_HEADER);
            if (pos != std::string::npos) tss_pem.replace(pos, strlen(TPM_WRAPPED_HEADER), "-----BEGIN TSS2 PRIVATE KEY-----");
            size_t fpos = tss_pem.find(TPM_WRAPPED_FOOTER);
            if (fpos != std::string::npos) tss_pem.replace(fpos, strlen(TPM_WRAPPED_FOOTER), "-----END TSS2 PRIVATE KEY-----");
            pkey = try_load(tss_pem);
        }

        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    }

    static bool isTPMAvailable() {
        return OSSL_PROVIDER_available(nullptr, "tpm2");
    }
};

#endif // TPM_UTILS_HPP
