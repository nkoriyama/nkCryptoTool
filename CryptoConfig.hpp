#ifndef CRYPTOCONFIG_HPP
#define CRYPTOCONFIG_HPP

#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <stdexcept>

enum class Operation {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    GenerateEncKey,
    GenerateSignKey,
    RegeneratePubKey,
    None
};

enum class CryptoMode {
    ECC,
    PQC,
    Hybrid
};

inline CryptoMode get_mode_from_string(const std::string& mode_str) {
    if (mode_str == "ecc") return CryptoMode::ECC;
    if (mode_str == "pqc") return CryptoMode::PQC;
    if (mode_str == "hybrid") return CryptoMode::Hybrid;
    throw std::invalid_argument("Invalid crypto mode: " + mode_str);
}

inline std::string to_string(CryptoMode mode) {
    switch (mode) {
        case CryptoMode::ECC: return "ecc";
        case CryptoMode::PQC: return "pqc";
        case CryptoMode::Hybrid: return "hybrid";
    }
    return "unknown";
}


struct CryptoConfig {
    Operation operation = Operation::None;
    CryptoMode mode = CryptoMode::ECC;

    // Paths
    std::vector<std::string> input_files;
    std::string output_file;
    std::string input_dir;
    std::string output_dir;
    std::string key_dir;
    std::string signature_file;

    // Key paths
    std::map<std::string, std::string> key_paths;

    // Options
    std::string passphrase;
    bool passphrase_was_provided = false;
    std::string digest_algo = "SHA256";
    bool sync_mode = false;
    bool is_recursive = false;

    // For regenerate-pubkey
    std::string regenerate_privkey_path;
    std::string regenerate_pubkey_path;
};

#endif // CRYPTOCONFIG_HPP
