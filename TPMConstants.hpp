#ifndef TPM_CONSTANTS_HPP
#define TPM_CONSTANTS_HPP

#include <vector>
#include <string>
#include "backend/IBackend.hpp"

class TPMUtils {
public:
    static constexpr const char* TPM_BLOB_HEADER = "-----BEGIN TPM WRAPPED BLOB-----";
    static constexpr const char* TPM_BLOB_FOOTER = "-----END TPM WRAPPED BLOB-----";

    static std::string base64_encode(const std::vector<unsigned char>& data) {
        return nk::backend::getBackend()->base64Encode(data);
    }

    static std::vector<unsigned char> base64_decode(const std::string& base64_str) {
        return nk::backend::getBackend()->base64Decode(base64_str);
    }
};

#endif // TPM_CONSTANTS_HPP
