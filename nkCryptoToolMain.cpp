#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <cxxopts.hpp>
#include "CryptoConfig.hpp"
#include "CryptoProcessor.hpp"
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
        ("key-dir", "Directory to save the generated keys (default: './keys')", cxxopts::value<std::string>())
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
        ("signing-pubkey", "The signer's public key for verification", cxxopts::value<std::string>())
        ("signature", "Path to the signature file", cxxopts::value<std::string>())
        ("digest-algo", "Hashing algorithm (e.g., SHA256, SHA3-256)", cxxopts::value<std::string>()->default_value("SHA256"));
    
    options.parse_positional({"input"});
    auto result = options.parse(argc, argv);

    if (result.count("help") || argc == 1) {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    // Determine operation
    if (result.count("encrypt")) config.operation = Operation::Encrypt;
    else if (result.count("decrypt")) config.operation = Operation::Decrypt;
    else if (result.count("sign")) config.operation = Operation::Sign;
    else if (result.count("verify")) config.operation = Operation::Verify;
    else if (result.count("gen-enc-key")) config.operation = Operation::GenerateEncKey;
    else if (result.count("gen-sign-key")) config.operation = Operation::GenerateSignKey;
    else if (result.count("regenerate-pubkey")) config.operation = Operation::RegeneratePubKey;

    // Populate config
    config.mode = get_mode_from_string(result["mode"].as<std::string>());
    config.sync_mode = result.count("sync") > 0;
    config.is_recursive = result.count("input-dir") > 0;
    config.digest_algo = result["digest-algo"].as<std::string>();

    if (result.count("input")) config.input_files = result["input"].as<std::vector<std::string>>();
    if (result.count("output-file")) config.output_file = result["output-file"].as<std::string>();
    if (result.count("input-dir")) config.input_dir = result["input-dir"].as<std::string>();
    if (result.count("output-dir")) config.output_dir = result["output-dir"].as<std::string>();
    if (result.count("key-dir")) config.key_dir = result["key-dir"].as<std::string>();
    if (result.count("signature")) config.signature_file = result["signature"].as<std::string>();
    if (result.count("passphrase")) {
        config.passphrase = result["passphrase"].as<std::string>();
        config.passphrase_was_provided = true;
    }
    
    auto resolve_key_path = [&](const std::string& key_path_arg) -> std::string {
        if (key_path_arg.empty()) return "";
        std::filesystem::path key_path(key_path_arg);
        if (key_path.is_relative() && !config.key_dir.empty()) {
            return std::filesystem::absolute(std::filesystem::path(config.key_dir) / key_path).string();
        }
        return std::filesystem::absolute(key_path).string();
    };

    if (result.count("recipient-pubkey")) config.key_paths["recipient-pubkey"] = resolve_key_path(result["recipient-pubkey"].as<std::string>());
    if (result.count("user-privkey")) config.key_paths["user-privkey"] = resolve_key_path(result["user-privkey"].as<std::string>());
    if (result.count("recipient-mlkem-pubkey")) config.key_paths["recipient-mlkem-pubkey"] = resolve_key_path(result["recipient-mlkem-pubkey"].as<std::string>());
    if (result.count("recipient-ecdh-pubkey")) config.key_paths["recipient-ecdh-pubkey"] = resolve_key_path(result["recipient-ecdh-pubkey"].as<std::string>());
    if (result.count("recipient-mlkem-privkey")) config.key_paths["recipient-mlkem-privkey"] = resolve_key_path(result["recipient-mlkem-privkey"].as<std::string>());
    if (result.count("recipient-ecdh-privkey")) config.key_paths["recipient-ecdh-privkey"] = resolve_key_path(result["recipient-ecdh-privkey"].as<std::string>());
    if (result.count("signing-privkey")) config.key_paths["signing-privkey"] = resolve_key_path(result["signing-privkey"].as<std::string>());
    if (result.count("signing-pubkey")) config.key_paths["signing-pubkey"] = resolve_key_path(result["signing-pubkey"].as<std::string>());

    if (config.operation == Operation::RegeneratePubKey && config.input_files.size() >= 2) {
        config.regenerate_privkey_path = resolve_key_path(config.input_files[0]);
        config.regenerate_pubkey_path = std::filesystem::absolute(config.input_files[1]).string();
    }
    
    // TODO: Add validation logic here or in CryptoProcessor

    return config;
}

auto progress_cb = [](double progress) {
    const int bar_width = 50;
    std::cout << "\r["; // \r で行頭に戻る
    int pos = static_cast<int>(bar_width * progress);
    for (int i = 0; i < bar_width; ++i) {
        if (i < pos) std::cout << "#";
        else std::cout << "-";
    }
    std::cout << "] " << std::fixed << std::setprecision(1) 
              << (progress * 100.0) << "% " << std::flush; // flush で即座に反映
    
    if (progress >= 1.0) std::cout << std::endl; // 完了時のみ改行
};

int main(int argc, char* argv[]) {
    OSSL_PROVIDER_load(nullptr, "default");
    int return_code = 0;

    try {
        CryptoConfig config = parse_command_line(argc, argv);
        
        // Recursive operations are a bit special and handled outside the processor for now.
        // This could be moved into the CryptoProcessor in the future.
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
                    processor.set_progress_callback(progress_cb); // コールバックを登録 [cite: 1, 18, 19]
                                                                  //
                    auto future = processor.run();
                    try {
                        future.get(); // Wait for this file to complete
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing file " << input_path.string() << ": " << e.what() << std::endl;
                        return_code = 1;
                    }
                    if (--files_to_process == 0) {
                        main_work_guard.reset();
                    }
                };

                processDirectory(recursive_io_context, config.input_dir, config.output_dir, file_operation);
                recursive_io_context.run();
            } else {
                 std::cerr << "Recursive signing/verification is not yet supported." << std::endl;
                 return 1;
            }
        } else {
             CryptoProcessor processor(std::move(config));
             // 【重要】ここに進捗コールバックの登録を追加します
             processor.set_progress_callback(progress_cb);
             auto future = processor.run();
             future.get(); // Wait for the operation to complete
        }

    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return_code = 1;
    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return_code = 1;
    }

    OSSL_PROVIDER_unload(nullptr);
    return return_code;
}
