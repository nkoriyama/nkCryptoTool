#ifndef CRYPTOCONFIG_HPP
#define CRYPTOCONFIG_HPP

#include "SecureMemory.hpp"
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
    WrapKey,
    UnwrapKey,
    Info,
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
    SecureString passphrase;
    bool passphrase_was_provided = false;
    bool use_tpm = false;
    std::string digest_algo = "SHA3-512";
    std::string pqc_kem_algo = "ML-KEM-1024";
    std::string pqc_dsa_algo = "ML-DSA-87";
    bool sync_mode = false;
    bool use_parallel = false;
    bool is_recursive = false;

    // For regenerate-pubkey
    std::string regenerate_privkey_path;
    std::string regenerate_pubkey_path;
};

#endif // CRYPTOCONFIG_HPP
