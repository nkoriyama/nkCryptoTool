#ifndef TPM_UTILS_HPP
#define TPM_UTILS_HPP

#include <vector>
#include <string>
#include <expected>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <memory>
#include <array>
#include <filesystem>
#include <fstream>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include "CryptoError.hpp"
#include "ICryptoStrategy.hpp"
#include "SecureMemory.hpp"

extern int ossl_passphrase_cb(char *pass, size_t pass_max, size_t *pass_len, const OSSL_PARAM params[], void *arg);
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

class TPMUtils {
public:
    static constexpr const char* TPM_BLOB_HEADER = "-----BEGIN TPM WRAPPED BLOB-----";
    static constexpr const char* TPM_BLOB_FOOTER = "-----END TPM WRAPPED BLOB-----";
    static constexpr const char* TPM_HANDLE_HEADER = "-----BEGIN TPM PERSISTENT HANDLE-----";
    static constexpr const char* TPM_HANDLE_FOOTER = "-----END TPM PERSISTENT HANDLE-----";
    static constexpr const char* TPM_WRAPPED_HEADER = "-----BEGIN TPM WRAPPED PRIVATE KEY-----";
    static constexpr const char* TPM_WRAPPED_ENC_HEADER = "-----BEGIN TPM WRAPPED ENCRYPTED PRIVATE KEY-----";

    static constexpr const char* DEFAULT_TCTI = "device:/dev/tpmrm0";

    static int run_cmd(const std::string& cmd) {
        std::string full_cmd = "TCTI=" + std::string(DEFAULT_TCTI) + " " + cmd;
        return system(full_cmd.c_str());
    }

    static std::string base64_encode(const std::vector<unsigned char>& data) {
        if (data.empty()) return "";
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new(BIO_s_mem());
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(b64, data.data(), (int)data.size());
        BIO_flush(b64);
        BUF_MEM *bptr;
        BIO_get_mem_ptr(b64, &bptr);
        std::string res(bptr->data, bptr->length);
        BIO_free_all(b64);
        return res;
    }

    static std::vector<unsigned char> base64_decode(const std::string& b64_str) {
        if (b64_str.empty()) return {};
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new_mem_buf(b64_str.data(), (int)b64_str.size());
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        std::vector<unsigned char> decoded(b64_str.size());
        int len = BIO_read(b64, decoded.data(), (int)decoded.size());
        if (len > 0) decoded.resize(len); else decoded.clear();
        BIO_free_all(b64);
        return decoded;
    }

    static std::expected<SecureString, CryptoError> wrapKey(EVP_PKEY* pkey, const SecureString& passphrase = "") {
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
        write(fds[0], aes_key.data(), 32); for(int fd : fds) close(fd);

        run_cmd("tpm2_createprimary -C o -c " + std::string(primary_ctx) + " -Q");
        std::string auth = passphrase.empty() ? "" : "-p \"" + std::string(passphrase.c_str()) + "\"";
        std::string cmd = "tpm2_create -C " + std::string(primary_ctx) + " -i " + std::string(temp_aes) + " -u " + std::string(pub_f) + " -r " + std::string(priv_f) + " " + auth + " -Q";
        if (run_cmd(cmd) != 0) {
            for(const char* f : {temp_aes, primary_ctx, pub_f, priv_f}) remove(f);
            return std::unexpected(CryptoError::TPMError);
        }

        auto read_f = [](const char* path) -> std::vector<unsigned char> {
            std::ifstream ifs(path, std::ios::binary);
            if (!ifs) return {};
            return std::vector<unsigned char>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        };

        std::stringstream ss;
        ss << TPM_BLOB_HEADER << "\n"
           << "P=" << base64_encode(read_f(pub_f)) << "\n"
           << "R=" << base64_encode(read_f(priv_f)) << "\n"
           << "E=" << base64_encode(ciphertext) << "\n"
           << "I=" << base64_encode(iv) << "\n"
           << "T=" << base64_encode(tag) << "\n"
           << TPM_BLOB_FOOTER << "\n";

        for(const char* f : {temp_aes, primary_ctx, pub_f, priv_f}) remove(f);
        std::string res = ss.str();
        return SecureString(res.begin(), res.end());
    }

    static std::expected<std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>, CryptoError> unwrapKey(const SecureString& wrapped_pem, const SecureString& passphrase = "") {
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
        for(int fd : fds) close(fd);

        {
            std::ofstream op(pub_f, std::ios::binary); auto d = base64_decode(p_b64); op.write((char*)d.data(), d.size());
            std::ofstream orr(priv_f, std::ios::binary); auto d2 = base64_decode(r_b64); orr.write((char*)d2.data(), d2.size());
        }

        run_cmd("tpm2_createprimary -C o -c " + std::string(primary_ctx) + " -Q");
        std::string auth = passphrase.empty() ? "" : "-p \"" + std::string(passphrase.c_str()) + "\"";
        
        // tpm2_load does NOT need authorization for the objects being loaded, but it needs authorization for the PARENT
        if (run_cmd("tpm2_load -C " + std::string(primary_ctx) + " -u " + std::string(pub_f) + " -r " + std::string(priv_f) + " -c " + std::string(key_ctx) + " -Q") != 0) {
            for(const char* f : {pub_f, priv_f, aes_f, primary_ctx, key_ctx}) remove(f);
            return std::unexpected(CryptoError::TPMError);
        }
        if (run_cmd("tpm2_unseal -c " + std::string(key_ctx) + " -o " + std::string(aes_f) + " " + auth + " -Q") != 0) {
            for(const char* f : {pub_f, priv_f, aes_f, primary_ctx, key_ctx}) remove(f);
            return std::unexpected(CryptoError::TPMError);
        }

        std::ifstream ifs(aes_f, std::ios::binary);
        std::vector<unsigned char> aes_key((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        for(const char* f : {pub_f, priv_f, aes_f, primary_ctx, key_ctx}) remove(f);

        auto ciphertext = base64_decode(e_b64);
        auto iv = base64_decode(i_b64);
        auto tag = base64_decode(t_b64);

        std::unique_ptr<EVP_CIPHER_CTX, void(*)(EVP_CIPHER_CTX*)> ctx(EVP_CIPHER_CTX_new(), [](EVP_CIPHER_CTX* c){ EVP_CIPHER_CTX_free(c); });
        EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr);
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, aes_key.data(), iv.data());
        
        std::vector<unsigned char> decrypted(ciphertext.size() + 16);
        int len, flen;
        EVP_DecryptUpdate(ctx.get(), decrypted.data(), &len, ciphertext.data(), (int)ciphertext.size());
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data());
        if (EVP_DecryptFinal_ex(ctx.get(), decrypted.data() + len, &flen) <= 0) return std::unexpected(CryptoError::TPMError);
        decrypted.resize(len + flen);

        const unsigned char* p = decrypted.data();
        EVP_PKEY* pkey = d2i_AutoPrivateKey(nullptr, &p, (long)decrypted.size());
        if (!pkey) {
            p = decrypted.data();
            pkey = d2i_PrivateKey(EVP_PKEY_NONE, nullptr, &p, (long)decrypted.size());
        }
        ERR_clear_error();
        if (!pkey) return std::unexpected(CryptoError::PrivateKeyLoadError);
        return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(pkey);
    }

    static bool isTPMAvailable() { return run_cmd("tpm2_getcap properties-fixed > /dev/null 2>&1") == 0; }
    static std::string extractHandle(const std::string&) { return ""; }
};

#endif // TPM_UTILS_HPP
