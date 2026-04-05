#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <cxxopts.hpp>
#include "CryptoConfig.hpp"
#include "CryptoProcessor.hpp"
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolUtils.hpp"
#include <openssl/provider.h>

// This function now populates the CryptoConfig struct
CryptoConfig parse_command_line(int argc, char* argv[]) {
    CryptoConfig config;

    cxxopts::Options options("nkCryptoTool", 
        "A command-line tool for advanced cryptographic operations including ECC, PQC, and hybrid modes.");

    options.add_options("General")
        ("h,help", "Display this help message")
        ("m,mode", "Specify the cryptographic mode: 'ecc', 'pqc', or 'hybrid'", cxxopts::value<std::string>()->default_value("ecc"))
        ("o,output-file", "Path to the output file (for single file operations)", cxxopts::value<std::string>())
        ("input", "Input file(s)", cxxopts::value<std::vector<std::string>>())
        ("input-dir", "Path to the input directory for recursive processing", cxxopts::value<std::string>())
        ("output-dir", "Path to the output directory for recursive processing", cxxopts::value<std::string>())
        ("sync", "Use synchronous processing instead of the pipeline");

    options.add_options("Key Generation")
        ("gen-enc-key", "Generate a key pair for encryption")
        ("gen-sign-key", "Generate a key pair for signing")
        ("regenerate-pubkey", "Regenerate a public key from a private key. Expects <private_key_path> and <public_key_path> as positional arguments.")
        ("wrap-existing", "Wrap an existing raw private key with TPM.", cxxopts::value<std::string>())
        ("unwrap-key", "Unwrap a TPM-protected key back to a raw private key.", cxxopts::value<std::string>())
        ("key-dir", "Directory to save the generated keys (default: './keys')", cxxopts::value<std::string>()->default_value("./keys"))
        ("p,passphrase", "Passphrase for the private key. Use '' for no passphrase.", cxxopts::value<std::string>());

    options.add_options("Operations")
        ("encrypt", "Encrypt the input file")
        ("decrypt", "Decrypt the input file")
        ("sign", "Sign the input file")
        ("verify", "Verify the signature of the input file")
        ("recipient-pubkey", "Recipient's public key file", cxxopts::value<std::string>())
        ("user-privkey", "Your private key file", cxxopts::value<std::string>())
        ("recipient-mlkem-pubkey", "Recipient's ML-KEM public key file (Hybrid)", cxxopts::value<std::string>())
        ("recipient-ecdh-pubkey", "Recipient's ECDH public key file (Hybrid)", cxxopts::value<std::string>())
        ("recipient-mlkem-privkey", "Your ML-KEM private key file (Hybrid)", cxxopts::value<std::string>())
        ("recipient-ecdh-privkey", "Your ECDH private key file (Hybrid)", cxxopts::value<std::string>())
        ("signing-privkey", "Your private key for signing", cxxopts::value<std::string>())
        ("signing-pubkey", "The singer's public key for verification", cxxopts::value<std::string>())
        ("signature", "Path to the signature file", cxxopts::value<std::string>())
        ("digest-algo,digest", "Hashing algorithm (e.g., SHA256, SHA3-512)", cxxopts::value<std::string>()->default_value("SHA3-512"))
        ("pqc-kem-algo", "PQC KEM algorithm (e.g., ML-KEM-768)", cxxopts::value<std::string>()->default_value("ML-KEM-1024"))
        ("pqc-dsa-algo", "PQC DSA algorithm (e.g., ML-DSA-65)", cxxopts::value<std::string>()->default_value("ML-DSA-87"))
        ("tpm", "Use TPM (Trusted Platform Module) to protect private keys");
    
    options.parse_positional({"input"});
    auto result = options.parse(argc, argv);

    if (result.count("help") || argc == 1) {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    // First, determine the crypto mode
    config.mode = get_mode_from_string(result["mode"].as<std::string>());

    std::string key_dir = result.count("key-dir") ? result["key-dir"].as<std::string>() : "./keys";
    config.key_dir = key_dir;
    if (!key_dir.empty()) {
        std::error_code ec;
        if (!std::filesystem::exists(key_dir, ec)) std::filesystem::create_directories(key_dir, ec);
    }

    auto resolve_key_path = [&](const std::string& key_path_arg) -> std::string {
        if (key_path_arg.empty()) return "";
        std::filesystem::path key_path(key_path_arg);
        
        // If it's a relative path and we have a key_dir, try to resolve it within key_dir first
        if (key_path.is_relative() && !key_dir.empty()) {
            std::filesystem::path combined = std::filesystem::path(key_dir) / key_path;
            // For reading (private key), we check if it exists. 
            // For writing (public key during regeneration), we want it to go to key_dir regardless.
            return std::filesystem::absolute(combined).string();
        }
        
        // Absolute path or no key_dir: use as is
        return std::filesystem::absolute(key_path).string();
    };

    // Determine operation
    if (result.count("encrypt")) config.operation = Operation::Encrypt;
    else if (result.count("decrypt")) config.operation = Operation::Decrypt;
    else if (result.count("sign")) config.operation = Operation::Sign;
    else if (result.count("verify")) config.operation = Operation::Verify;
    else if (result.count("gen-enc-key")) config.operation = Operation::GenerateEncKey;
    else if (result.count("gen-sign-key")) config.operation = Operation::GenerateSignKey;
    else if (result.count("regenerate-pubkey")) config.operation = Operation::RegeneratePubKey;
    else if (result.count("wrap-existing")) {
        config.operation = Operation::WrapKey;
        config.input_files.push_back(resolve_key_path(result["wrap-existing"].as<std::string>()));
    }
    else if (result.count("unwrap-key")) {
        config.operation = Operation::UnwrapKey;
        config.input_files.push_back(resolve_key_path(result["unwrap-key"].as<std::string>()));
    } else {
        config.operation = Operation::None;
    }

    // Populate common config
    config.sync_mode = result.count("sync") > 0;
    config.is_recursive = result.count("input-dir") > 0;
    config.digest_algo = result["digest-algo"].as<std::string>();
    config.pqc_kem_algo = result["pqc-kem-algo"].as<std::string>();
    config.pqc_dsa_algo = result["pqc-dsa-algo"].as<std::string>();
    config.use_tpm = result.count("tpm") > 0;

    if (result.count("input") && config.input_files.empty()) {
        config.input_files = result["input"].as<std::vector<std::string>>();
    }
    if (result.count("output-file")) config.output_file = result["output-file"].as<std::string>();
    if (result.count("input-dir")) config.input_dir = result["input-dir"].as<std::string>();
    if (result.count("output-dir")) config.output_dir = result["output-dir"].as<std::string>();
    if (result.count("signature")) config.signature_file = result["signature"].as<std::string>();
    if (result.count("passphrase")) {
        config.passphrase = result["passphrase"].as<std::string>();
        config.passphrase_was_provided = true;
    }

    if (result.count("recipient-pubkey")) config.key_paths["recipient-pubkey"] = resolve_key_path(result["recipient-pubkey"].as<std::string>());
    if (result.count("user-privkey")) config.key_paths["user-privkey"] = resolve_key_path(result["user-privkey"].as<std::string>());
    if (result.count("recipient-mlkem-pubkey")) config.key_paths["recipient-mlkem-pubkey"] = resolve_key_path(result["recipient-mlkem-pubkey"].as<std::string>());
    if (result.count("recipient-ecdh-pubkey")) config.key_paths["recipient-ecdh-pubkey"] = resolve_key_path(result["recipient-ecdh-pubkey"].as<std::string>());
    if (result.count("recipient-mlkem-privkey")) config.key_paths["recipient-mlkem-privkey"] = resolve_key_path(result["recipient-mlkem-privkey"].as<std::string>());
    if (result.count("recipient-ecdh-privkey")) config.key_paths["recipient-ecdh-privkey"] = resolve_key_path(result["recipient-ecdh-privkey"].as<std::string>());
    if (result.count("signing-privkey")) config.key_paths["signing-privkey"] = resolve_key_path(result["signing-privkey"].as<std::string>());
    if (result.count("signing-pubkey")) config.key_paths["signing-pubkey"] = resolve_key_path(result["signing-pubkey"].as<std::string>());
    config.key_paths["pqc-kem-algo"] = config.pqc_kem_algo;
    config.key_paths["pqc-dsa-algo"] = config.pqc_dsa_algo;

    if (config.operation == Operation::RegeneratePubKey && config.input_files.size() >= 2) {
        config.regenerate_privkey_path = resolve_key_path(config.input_files[0]);
        config.regenerate_pubkey_path = resolve_key_path(config.input_files[1]);
    }
    
    if (config.operation == Operation::GenerateEncKey) {
        if (config.mode == CryptoMode::Hybrid) {
            config.key_paths["public-mlkem-key"] = resolve_key_path("public_enc_hybrid_mlkem.key");
            config.key_paths["private-mlkem-key"] = resolve_key_path("private_enc_hybrid_mlkem.key");
            config.key_paths["public-ecdh-key"] = resolve_key_path("public_enc_hybrid_ecdh.key");
            config.key_paths["private-ecdh-key"] = resolve_key_path("private_enc_hybrid_ecdh.key");
            config.key_paths["public-key"] = config.key_paths["public-mlkem-key"];
            config.key_paths["private-key"] = config.key_paths["private-mlkem-key"];
        } else {
            std::string suffix = "_" + to_string(config.mode) + ".key";
            config.key_paths["public-key"] = resolve_key_path("public_enc" + suffix);
            config.key_paths["private-key"] = resolve_key_path("private_enc" + suffix);
        }
    } else if (config.operation == Operation::GenerateSignKey) {
        std::string suffix = "_" + to_string(config.mode) + ".key";
        config.key_paths["public-key"] = resolve_key_path("public_sign" + suffix);
        config.key_paths["private-key"] = resolve_key_path("private_sign" + suffix);
    }

    return config;
}

auto progress_cb = [](double progress) {
    const int bar_width = 50;
    std::cout << "\r[";
    int pos = static_cast<int>(bar_width * progress);
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cout << "#";
        else std::cout << "-";
    }
    std::cout << "] " << std::fixed << std::setprecision(1) << (progress * 100.0) << "% " << std::flush;
    if (progress >= 1.0) std::cout << std::endl;
};

bool needs_passphrase(const CryptoConfig& config) {
    std::vector<std::string> keys_to_check;
    if (config.operation == Operation::Decrypt) {
        if (config.mode == CryptoMode::ECC) {
            if (config.key_paths.count("user-privkey"))
                keys_to_check.push_back(config.key_paths.at("user-privkey"));
        } else if (config.mode == CryptoMode::PQC) {
            if (config.key_paths.count("user-privkey"))
                keys_to_check.push_back(config.key_paths.at("user-privkey"));
            if (config.key_paths.count("recipient-mlkem-privkey"))
                keys_to_check.push_back(config.key_paths.at("recipient-mlkem-privkey"));
        } else if (config.mode == CryptoMode::Hybrid) {
            if (config.key_paths.count("recipient-mlkem-privkey"))
                keys_to_check.push_back(config.key_paths.at("recipient-mlkem-privkey"));
            if (config.key_paths.count("recipient-ecdh-privkey"))
                keys_to_check.push_back(config.key_paths.at("recipient-ecdh-privkey"));
        }
    } else if (config.operation == Operation::Sign) {
        if (config.key_paths.count("signing-privkey"))
            keys_to_check.push_back(config.key_paths.at("signing-privkey"));
    } else if (config.operation == Operation::RegeneratePubKey) {
        keys_to_check.push_back(config.regenerate_privkey_path);
    } else if (config.operation == Operation::WrapKey || config.operation == Operation::UnwrapKey) {
        for (const auto& f : config.input_files) keys_to_check.push_back(f);
    }
    for (const auto& key_path : keys_to_check) {
        if (!key_path.empty() && std::filesystem::exists(key_path)) {
            if (nkCryptoToolBase::isPrivateKeyEncrypted(key_path)) return true;
        }
    }
    return false;
}

int main(int argc, char* argv[]) {
    OSSL_PROVIDER_load(nullptr, "default");
    int return_code = 0;
    try {
        CryptoConfig config = parse_command_line(argc, argv);
        if (config.use_tpm) {
            if (OSSL_PROVIDER_load(nullptr, "tpm2") == nullptr) {
                std::cerr << "Warning: Failed to load TPM2 provider. Operations requiring TPM might fail." << std::endl;
            } else {
                config.key_paths["use-tpm"] = "true";
            }
        }
        if (config.is_recursive) {
            if (config.operation == Operation::Encrypt || config.operation == Operation::Decrypt) {
                 asio::io_context recursive_io_context;
                 auto main_work_guard = asio::make_work_guard(recursive_io_context.get_executor());
                 std::atomic<int> files_to_process = 0;
                 for (const auto& entry : std::filesystem::recursive_directory_iterator(config.input_dir)) {
                     if (entry.is_regular_file()) files_to_process++;
                 }
                if (files_to_process == 0) {
                    std::cout << "No files to process in the input directory." << std::endl;
                    return 0;
                }
                auto file_operation = [&](const std::filesystem::path& input_path, const std::filesystem::path& output_path) {
                    CryptoConfig file_config = config;
                    file_config.input_files = {input_path.string()};
                    file_config.output_file = output_path.string();
                    CryptoProcessor processor(std::move(file_config));
                    processor.set_progress_callback(progress_cb);
                    auto future = processor.run();
                    try {
                        future.get();
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing file " << input_path.string() << ": " << e.what() << std::endl;
                        return_code = 1;
                    }
                    if (--files_to_process == 0) main_work_guard.reset();
                };
                processDirectory(recursive_io_context, config.input_dir, config.output_dir, file_operation);
                recursive_io_context.run();
            } else {
                 std::cerr << "Recursive operation is not yet supported." << std::endl;
                 return 1;
            }
        } else {
             if (config.passphrase.empty() && !config.passphrase_was_provided) {
                 if (config.operation == Operation::Decrypt || config.operation == Operation::Sign || config.operation == Operation::RegeneratePubKey || config.operation == Operation::WrapKey || config.operation == Operation::UnwrapKey) {
                     if (needs_passphrase(config)) {
                         std::cout << "Passphrase required for private key: ";
                         std::cout.flush();
                         config.passphrase = get_masked_passphrase();
                     }
                 } else if (config.operation == Operation::GenerateEncKey || config.operation == Operation::GenerateSignKey) {
                     config.passphrase = get_and_verify_passphrase("Enter passphrase for new private key (leave empty for no passphrase): ");
                 }
             }
             CryptoProcessor processor(std::move(config));
             processor.set_progress_callback(progress_cb);
             auto future = processor.run();
             future.get();
        }
    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return_code = 1;
    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return_code = 1;
    }
    return return_code;
}
