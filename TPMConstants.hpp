#ifndef TPM_CONSTANTS_HPP
#define TPM_CONSTANTS_HPP

#include <vector>
#include <string>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

class TPMUtils {
public:
    static constexpr const char* TPM_BLOB_HEADER = "-----BEGIN TPM WRAPPED BLOB-----";
    static constexpr const char* TPM_BLOB_FOOTER = "-----END TPM WRAPPED BLOB-----";
    static constexpr const char* TPM_HANDLE_HEADER = "-----BEGIN TPM PERSISTENT HANDLE-----";
    static constexpr const char* TPM_HANDLE_FOOTER = "-----END TPM PERSISTENT HANDLE-----";
    static constexpr const char* TPM_WRAPPED_HEADER = "-----BEGIN TPM WRAPPED PRIVATE KEY-----";
    static constexpr const char* TPM_WRAPPED_ENC_HEADER = "-----BEGIN TPM WRAPPED ENCRYPTED PRIVATE KEY-----";

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
};

#endif // TPM_CONSTANTS_HPP
