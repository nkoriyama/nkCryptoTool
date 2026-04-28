/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "CryptoProcessor.hpp"
#include "TpmKeyProvider.hpp"
#include "nkCryptoToolUtils.hpp"
#include <iostream>
#include <memory>
#include <cxxopts.hpp>

int main(int argc, char* argv[]) {
    cxxopts::Options options("nkCryptoTool", "A command-line tool for advanced cryptographic operations");
    
    options.add_options()
        ("m,mode", "Specify the cryptographic mode: 'ecc', 'pqc', or 'hybrid'", cxxopts::value<std::string>()->default_value("ecc"))
        ("o,output-file", "Path to the output file", cxxopts::value<std::string>())
        ("encrypt", "Perform encryption")
        ("decrypt", "Perform decryption")
        ("sign", "Perform signing")
        ("verify", "Perform verification")
        ("gen-enc-key", "Generate encryption key pair")
        ("gen-sign-key", "Generate signing key pair")
        ("key-dir", "Directory to store generated keys", cxxopts::value<std::string>()->default_value("keys"))
        ("recipient-pubkey", "The recipient's public key for encryption", cxxopts::value<std::string>())
        ("recipient-ecdh-pubkey", "The recipient's ECDH public key", cxxopts::value<std::string>())
        ("recipient-mlkem-pubkey", "The recipient's ML-KEM public key", cxxopts::value<std::string>())
        ("user-privkey", "The user's private key for decryption", cxxopts::value<std::string>())
        ("user-ecdh-privkey", "The user's ECDH private key", cxxopts::value<std::string>())
        ("user-mlkem-privkey", "The user's ML-KEM private key", cxxopts::value<std::string>())
        ("signing-privkey", "The signer's private key for signing", cxxopts::value<std::string>())
        ("signing-pubkey", "The signer's public key for verification", cxxopts::value<std::string>())
        ("signature", "Path to the signature file", cxxopts::value<std::string>())
        ("digest-algo", "Hashing algorithm", cxxopts::value<std::string>()->default_value("SHA3-512"))
        ("kem-algo", "PQC KEM algorithm", cxxopts::value<std::string>()->default_value("ML-KEM-768"))
        ("dsa-algo", "PQC DSA algorithm", cxxopts::value<std::string>()->default_value("ML-DSA-65"))
        ("tpm", "Use TPM to protect private keys")
        ("r,recursive", "Process directories recursively")
        ("input-dir", "Directory for recursive input", cxxopts::value<std::string>())
        ("output-dir", "Directory for recursive output", cxxopts::value<std::string>())
        ("input-files", "Input files", cxxopts::value<std::vector<std::string>>());

    options.parse_positional({"input-files"});

    try {
        auto result = options.parse(argc, argv);

        CryptoConfig config;
        config.mode = get_mode_from_string(result["mode"].as<std::string>());
        
        if (result.count("encrypt")) config.operation = Operation::Encrypt;
        else if (result.count("decrypt")) config.operation = Operation::Decrypt;
        else if (result.count("sign")) config.operation = Operation::Sign;
        else if (result.count("verify")) config.operation = Operation::Verify;
        else if (result.count("gen-enc-key")) config.operation = Operation::GenerateEncKey;
        else if (result.count("gen-sign-key")) config.operation = Operation::GenerateSignKey;

        if (result.count("output-file")) config.output_file = result["output-file"].as<std::string>();
        if (result.count("signature")) config.signature_file = result["signature"].as<std::string>();
        
        std::string key_dir = result.count("key-dir") ? result["key-dir"].as<std::string>() : "keys";
        config.key_paths["key-dir"] = key_dir;

        if (result.count("recipient-pubkey")) config.key_paths["recipient-pubkey"] = result["recipient-pubkey"].as<std::string>();
        if (result.count("recipient-ecdh-pubkey")) config.key_paths["recipient-ecdh-pubkey"] = result["recipient-ecdh-pubkey"].as<std::string>();
        if (result.count("recipient-mlkem-pubkey")) config.key_paths["recipient-mlkem-pubkey"] = result["recipient-mlkem-pubkey"].as<std::string>();
        if (result.count("user-privkey")) config.key_paths["user-privkey"] = result["user-privkey"].as<std::string>();
        if (result.count("user-ecdh-privkey")) config.key_paths["user-ecdh-privkey"] = result["user-ecdh-privkey"].as<std::string>();
        if (result.count("user-mlkem-privkey")) config.key_paths["user-mlkem-privkey"] = result["user-mlkem-privkey"].as<std::string>();
        
        // CryptoProcessor.cpp の期待名 (signing-privkey / signing-pubkey) に合わせる
        if (result.count("signing-privkey")) config.key_paths["signing-privkey"] = result["signing-privkey"].as<std::string>();
        if (result.count("signing-pubkey")) config.key_paths["signing-pubkey"] = result["signing-pubkey"].as<std::string>();
        
        if (config.mode == CryptoMode::Hybrid) {
            if (!result.count("recipient-ecdh-pubkey") && !result.count("recipient-pubkey"))
                config.key_paths["recipient-ecdh-pubkey"] = key_dir + "/public_enc_ecc.key";
            if (!result.count("recipient-mlkem-pubkey"))
                config.key_paths["recipient-mlkem-pubkey"] = key_dir + "/public_enc_pqc.key";
            if (!result.count("user-ecdh-privkey") && !result.count("user-privkey"))
                config.key_paths["user-ecdh-privkey"] = key_dir + "/private_enc_ecc.key";
            if (!result.count("user-mlkem-privkey"))
                config.key_paths["user-mlkem-privkey"] = key_dir + "/private_enc_pqc.key";
            
            if (!result.count("signing-privkey"))
                config.key_paths["signing-privkey"] = key_dir + "/private_sign_pqc.key";
            if (!result.count("signing-pubkey"))
                config.key_paths["signing-pubkey"] = key_dir + "/public_sign_pqc.key";
        }

        if (result.count("kem-algo")) {
            config.pqc_kem_algo = result["kem-algo"].as<std::string>();
            config.key_paths["kem-algo"] = config.pqc_kem_algo;
        }
        if (result.count("dsa-algo")) {
            config.pqc_dsa_algo = result["dsa-algo"].as<std::string>();
            config.key_paths["dsa-algo"] = config.pqc_dsa_algo;
        }

        if (config.operation == Operation::GenerateEncKey) {
            if (config.mode == CryptoMode::Hybrid) {
                config.key_paths["public-ecdh-key"] = key_dir + "/public_enc_ecc.key";
                config.key_paths["private-ecdh-key"] = key_dir + "/private_enc_ecc.key";
                config.key_paths["public-mlkem-key"] = key_dir + "/public_enc_pqc.key";
                config.key_paths["private-mlkem-key"] = key_dir + "/private_enc_pqc.key";
                config.key_paths["recipient-ecdh-pubkey"] = config.key_paths["public-ecdh-key"];
                config.key_paths["recipient-mlkem-pubkey"] = config.key_paths["public-mlkem-key"];
                config.key_paths["recipient-pubkey"] = config.key_paths["public-ecdh-key"]; // Fallback
            } else {
                std::string prefix = (config.mode == CryptoMode::PQC) ? "pqc" : "ecc";
                config.key_paths["public-key"] = key_dir + "/public_enc_" + prefix + ".key";
                config.key_paths["private-key"] = key_dir + "/private_enc_" + prefix + ".key";
                config.key_paths["recipient-pubkey"] = config.key_paths["public-key"];
                config.key_paths["user-privkey"] = config.key_paths["private-key"];
            }
        } else if (config.operation == Operation::GenerateSignKey) {
            if (config.mode == CryptoMode::Hybrid) {
                // ハイブリッド署名は現在 PQC 署名のみを想定 (または PQC + ECC)
                // ここでは PQC 署名鍵をデフォルトとする
                config.key_paths["public-key"] = key_dir + "/public_sign_pqc.key";
                config.key_paths["private-key"] = key_dir + "/private_sign_pqc.key";
                config.key_paths["signing-pubkey"] = config.key_paths["public-key"];
                config.key_paths["signing-privkey"] = config.key_paths["private-key"];
            } else {
                std::string prefix = (config.mode == CryptoMode::PQC) ? "pqc" : "ecc";
                config.key_paths["public-key"] = key_dir + "/public_sign_" + prefix + ".key";
                config.key_paths["private-key"] = key_dir + "/private_sign_" + prefix + ".key";
                config.key_paths["signing-pubkey"] = config.key_paths["public-key"];
                config.key_paths["signing-privkey"] = config.key_paths["private-key"];
            }
        }

        if (result.count("digest-algo")) config.digest_algo = result["digest-algo"].as<std::string>();
        
        bool tpm = result.count("tpm") > 0;
        if (tpm) config.key_paths["use-tpm"] = "true";

        if (config.operation == Operation::GenerateEncKey || 
            config.operation == Operation::GenerateSignKey) {
             config.passphrase = get_and_verify_passphrase("Enter passphrase for new key pair: ");
             config.passphrase_was_provided = true;
        }

        if (result.count("input-files")) {
            config.input_files = result["input-files"].as<std::vector<std::string>>();
        }

        if (config.input_files.empty() && (config.operation == Operation::Encrypt || config.operation == Operation::Decrypt || config.operation == Operation::Sign || config.operation == Operation::Verify)) {
            std::cerr << "Error: No input files specified" << std::endl;
            return 1;
        }

        CryptoProcessor processor(config);
        
        std::shared_ptr<nk::IKeyProvider> provider;
        if (tpm) {
            auto tpm_provider = std::make_shared<nk::TpmKeyProvider>();
            if (tpm_provider->isAvailable()) {
                provider = tpm_provider;
            } else {
                std::cerr << "Warning: TPM not available, falling back to software provider" << std::endl;
            }
        }
        processor.setKeyProvider(provider);

        if (result.count("recursive")) {
            asio::io_context recursive_io_context;
            config.input_dir = result["input-dir"].as<std::string>();
            config.output_dir = result["output-dir"].as<std::string>();
            
            auto file_operation = [&](const std::filesystem::path& in, const std::filesystem::path& out) {
                CryptoConfig single_config = config;
                single_config.input_files = {in.string()};
                single_config.output_file = out.string();
                CryptoProcessor single_processor(single_config);
                single_processor.setKeyProvider(provider);
                auto future = single_processor.run();
                future.get();
            };

            processDirectory(recursive_io_context, config.input_dir, config.output_dir, file_operation);
        } else {
            auto future = processor.run();
            future.get();
        }

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
