#ifndef TPM_KEY_PROVIDER_HPP
#define TPM_KEY_PROVIDER_HPP

#include <vector>
#include <string>
#include <expected>
#include <iostream>
#include <sstream>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "IKeyProvider.hpp"
#include "TPMConstants.hpp"
#include "TpmSecure.hpp"

namespace nk {

class TpmKeyProvider : public IKeyProvider {
public:
    static constexpr const char* TPM2_CREATEPRIMARY = "/usr/bin/tpm2_createprimary";
    static constexpr const char* TPM2_CREATE        = "/usr/bin/tpm2_create";
    static constexpr const char* TPM2_LOAD          = "/usr/bin/tpm2_load";
    static constexpr const char* TPM2_UNSEAL        = "/usr/bin/tpm2_unseal";
    static constexpr const char* TPM2_GETCAP        = "/usr/bin/tpm2_getcap";

    std::expected<SecureString, CryptoError> wrapKey(EVP_PKEY* pkey, const SecureString& passphrase = "") override {
        std::unique_ptr<BIO, void(*)(BIO*)> mem_bio(BIO_new(BIO_s_mem()), [](BIO* b){ BIO_free(b); });
        i2d_PrivateKey_bio(mem_bio.get(), pkey);
        BUF_MEM* bptr;
        BIO_get_mem_ptr(mem_bio.get(), &bptr);
        std::vector<unsigned char> key_der((unsigned char*)bptr->data, (unsigned char*)bptr->data + bptr->length);

        std::vector<unsigned char> aes_key(32);
        std::vector<unsigned char> iv(12);
        RAND_bytes(aes_key.data(), 32);
        RAND_bytes(iv.data(), 12);

        std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX* c){ EVP_CIPHER_CTX_free(c); });
        EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, aes_key.data(), iv.data());
        std::vector<unsigned char> ciphertext(key_der.size());
        int len, flen;
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, key_der.data(), (int)key_der.size());
        EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &flen);
        std::vector<unsigned char> tag(16);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data());

        char temp_aes[] = "/tmp/nk_a_XXXXXX"; char primary_ctx[] = "/tmp/nk_p_XXXXXX";
        char pub_f[] = "/tmp/nk_u_XXXXXX"; char priv_f[] = "/tmp/nk_r_XXXXXX";
        int fds[] = { mkstemp(temp_aes), mkstemp(primary_ctx), mkstemp(pub_f), mkstemp(priv_f) };
        for(int fd : fds) { fchmod(fd, 0600); }
        write(fds[0], aes_key.data(), 32); for(int fd : fds) close(fd);

        try {
            nk::TpmSession session;
            nk::run_cmd_secure({TPM2_CREATEPRIMARY, "-C", "o", "-c", primary_ctx, "-Q"});

            std::vector<std::string> create_args = {
                TPM2_CREATE, "-C", primary_ctx, "-i", temp_aes, "-u", pub_f, "-r", priv_f, 
                "-P", session.getSessionArg(), "-Q"
            };

            SecureString stdin_data;
            if (!passphrase.empty()) {
                create_args.push_back("-p");
                create_args.push_back("-");
                stdin_data = passphrase;
            }

            auto res = nk::run_cmd_secure(create_args, stdin_data);
            if (res.exit_code != 0) throw std::runtime_error("tpm2_create failed");

        } catch (...) {
            for(const char* f : {temp_aes, primary_ctx, pub_f, priv_f}) unlink(f);
            return std::unexpected(CryptoError::KeyProtectionError);
        }

        auto read_f = [](const char* path) -> std::vector<unsigned char> {
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs) return {};
            return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        };

        std::stringstream ss;
        ss << TPMUtils::TPM_BLOB_HEADER << "\n"
           << "P=" << TPMUtils::base64_encode(read_f(pub_f)) << "\n"
           << "R=" << TPMUtils::base64_encode(read_f(priv_f)) << "\n"
           << "E=" << TPMUtils::base64_encode(ciphertext) << "\n"
           << "I=" << TPMUtils::base64_encode(iv) << "\n"
           << "T=" << TPMUtils::base64_encode(tag) << "\n"
           << TPMUtils::TPM_BLOB_FOOTER << "\n";

        for(const char* f : {temp_aes, primary_ctx, pub_f, priv_f}) unlink(f);
        std::string res = ss.str();
        return SecureString(res.begin(), res.end());
    }

    std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> unwrapKey(const SecureString& wrapped_pem, const SecureString& passphrase = "") override {
        std::string content(wrapped_pem.c_str());
        std::string p_b64, r_b64, e_b64, i_b64, t_b64;
        std::stringstream css(content); std::string line;
        while (std::getline(css, line)) {
            if (line.empty() || line[0] == '-') continue;
            if (line.find("P=") == 0) p_b64 = line.substr(2);
            else if (line.find("R=") == 0) r_b64 = line.substr(2);
            else if (line.find("E=") == 0) e_b64 = line.substr(2);
            else if (line.find("I=") == 0) i_b64 = line.substr(2);
            else if (line.find("T=") == 0) t_b64 = line.substr(2);
        }
        auto trim = [](std::string& s) {
            s.erase(0, s.find_first_not_of(" \t\r\n"));
            s.erase(s.find_last_not_of(" \t\r\n") + 1);
        };
        trim(p_b64); trim(r_b64); trim(e_b64); trim(i_b64); trim(t_b64);

        if (p_b64.empty() || r_b64.empty() || e_b64.empty()) return std::unexpected(CryptoError::PrivateKeyLoadError);

        char pub_f[] = "/tmp/nk_up_XXXXXX"; char priv_f[] = "/tmp/nk_ur_XXXXXX"; 
        char aes_f[] = "/tmp/nk_ua_XXXXXX"; char primary_ctx[] = "/tmp/nk_pc_XXXXXX";
        char key_ctx[] = "/tmp/nk_kc_XXXXXX";
        int fds[] = { mkstemp(pub_f), mkstemp(priv_f), mkstemp(aes_f), mkstemp(primary_ctx), mkstemp(key_ctx) };
        for(int fd : fds) { fchmod(fd, 0600); close(fd); }

        try {
            {
                std::ofstream op(pub_f, std::ios::binary); auto d = TPMUtils::base64_decode(p_b64); op.write((char*)d.data(), d.size());
                std::ofstream orr(priv_f, std::ios::binary); auto d2 = TPMUtils::base64_decode(r_b64); orr.write((char*)d2.data(), d2.size());
            }

            nk::run_cmd_secure({TPM2_CREATEPRIMARY, "-C", "o", "-c", primary_ctx, "-Q"});
            nk::TpmSession hmac_session;
            
            if (nk::run_cmd_secure({TPM2_LOAD, "-C", primary_ctx, "-u", pub_f, "-r", priv_f, "-c", key_ctx, "-P", hmac_session.getSessionArg(), "-Q"}).exit_code != 0) {
                throw std::runtime_error("tpm2_load failed");
            }

            std::string auth_arg = hmac_session.getSessionArg();
            SecureString stdin_data;
            if (!passphrase.empty()) {
                auth_arg += "+-";
                stdin_data = passphrase;
            }

            if (nk::run_cmd_secure({TPM2_UNSEAL, "-c", key_ctx, "-o", aes_f, "-p", auth_arg, "-Q"}, stdin_data).exit_code != 0) {
                throw std::runtime_error("tpm2_unseal failed");
            }

        } catch (...) {
            for(const char* f : {pub_f, priv_f, aes_f, primary_ctx, key_ctx}) unlink(f);
            return std::unexpected(CryptoError::KeyProtectionError);
        }

        std::ifstream ifs(aes_f, std::ios::binary);
        std::vector<unsigned char> aes_key((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        for(const char* f : {pub_f, priv_f, aes_f, primary_ctx, key_ctx}) unlink(f);

        auto ciphertext = TPMUtils::base64_decode(e_b64);
        auto iv = TPMUtils::base64_decode(i_b64);
        auto tag = TPMUtils::base64_decode(t_b64);

        std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX* c){ EVP_CIPHER_CTX_free(c); });
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, aes_key.data(), iv.data());
        
        std::vector<unsigned char> decrypted(ciphertext.size() + 16);
        int len, flen;
        EVP_DecryptUpdate(ctx.get(), decrypted.data(), &len, ciphertext.data(), (int)ciphertext.size());
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        if (EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + len, &flen) <= 0) return std::unexpected(CryptoError::KeyProtectionError);
        decrypted.resize(len + flen);

        const unsigned char* p = decrypted.data();
        EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)decrypted.size());
        if (!pkey) {
            p = decrypted.data();
            pkey = d2i_PrivateKey(EVP_PKEY_NONE, nullptr, &p, (long)decrypted.size());
        }
        ERR_clear_error();
        OPENSSL_cleanse(aes_key.data(), aes_key.size());
        OPENSSL_cleanse(decrypted.data(), decrypted.size());

        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    }

    bool isAvailable() override {
        try {
            return nk::run_cmd_secure({TPM2_GETCAP, "properties-fixed"}).exit_code == 0;
        } catch (...) {
            return false;
        }
    }
};

} // namespace nk

#endif // TPM_KEY_PROVIDER_HPP
