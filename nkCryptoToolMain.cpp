// nkCryptoToolMain.cpp
/*
 * Copyright (c) 2024-2025 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * nkCryptoTool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nkCryptoTool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nkCryptoTool. If not, see <https://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <mutex>
#include <map>
#include <functional>
#include <format>

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

#include <cxxopts.hpp>

#include <openssl/provider.h>
#include <openssl/conf.h>
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"
#include "nkCryptoToolUtils.hpp"

int main(int argc, char* argv[]) {
    OSSL_PROVIDER_load(nullptr, "default");
    // OSSL_PROVIDER_load(nullptr, "oqsprovider"); // Add oqsprovider for PQC functions
    int return_code = 0;

    try {
        cxxopts::Options options("nkCryptoTool", 
            "A command-line tool for advanced cryptographic operations including ECC, PQC, and hybrid modes.\n\n"
            "Usage examples:\n"
            "  # Generate a hybrid encryption key pair\n"
            "  nkCryptoTool --mode hybrid --gen-enc-key\n\n"
            "  # Encrypt a file using hybrid mode\n"
            "  nkCryptoTool --mode hybrid --encrypt -o out.enc file.txt --recipient-mlkem-pubkey mlkem.pub --recipient-ecdh-pubkey ecdh.pub\n\n"
            "  # Decrypt a file using hybrid mode\n"
            "  nkCryptoTool --mode hybrid --decrypt -o file.txt out.enc --recipient-mlkem-privkey mlkem.priv --recipient-ecdh-privkey ecdh.priv"
        );

        options.add_options("General")
            ("h,help", "Display this help message")
            ("m,mode", "Specify the cryptographic mode: 'ecc', 'pqc', or 'hybrid'", cxxopts::value<std::string>()->default_value("ecc"))
            ("o,output-file", "Path to the output file", cxxopts::value<std::string>())
            ("input", "Input file(s)", cxxopts::value<std::vector<std::string>>());

        options.add_options("Key Generation")
            ("gen-enc-key", "Generate a key pair for encryption")
            ("gen-sign-key", "Generate a key pair for signing (for 'ecc' or 'pqc' modes)")
            ("regenerate-pubkey", "Regenerate a public key from a private key. Expects <private_key_path> and <public_key_path> as positional arguments.")
            ("key-dir", "Directory to save the generated keys (default: './keys')", cxxopts::value<std::string>())
            ("p,passphrase", "Passphrase for the private key. Use '''' for no passphrase.", cxxopts::value<std::string>());

        options.add_options("Encryption (ECC/PQC)")
            ("encrypt", "Encrypt the input file")
            ("recipient-pubkey", "Recipient's public key file", cxxopts::value<std::string>());

        options.add_options("Decryption (ECC/PQC)")
            ("decrypt", "Decrypt the input file")
            ("user-privkey", "Your private key file", cxxopts::value<std::string>());

        options.add_options("Encryption (Hybrid)")
            ("recipient-mlkem-pubkey", "Recipient's ML-KEM public key file", cxxopts::value<std::string>())
            ("recipient-ecdh-pubkey", "Recipient's ECDH public key file", cxxopts::value<std::string>());

        options.add_options("Decryption (Hybrid)")
            ("recipient-mlkem-privkey", "Your ML-KEM private key file", cxxopts::value<std::string>())
            ("recipient-ecdh-privkey", "Your ECDH private key file", cxxopts::value<std::string>());

        options.add_options("Digital Signature (ECC/PQC)")
            ("sign", "Sign the input file")
            ("verify", "Verify the signature of the input file")
            ("signing-privkey", "Your private key for signing", cxxopts::value<std::string>())
            ("signing-pubkey", "The signer's public key for verification", cxxopts::value<std::string>())
            ("signature", "Path to the signature file (for signing and verification)", cxxopts::value<std::string>())
            ("digest-algo", "Hashing algorithm (e.g., SHA256, SHA3-256)", cxxopts::value<std::string>()->default_value("SHA256"));

        options.parse_positional({"input"});
        auto result = options.parse(argc, argv);

        if (result.count("help") || argc == 1) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        // --- 引数検証 ---
        bool is_encrypt = result.count("encrypt") > 0;
        bool is_decrypt = result.count("decrypt") > 0;
        bool is_sign = result.count("sign") > 0;
        bool is_verify = result.count("verify") > 0;
        bool is_gen_enc_key = result.count("gen-enc-key") > 0;
        bool is_gen_sign_key = result.count("gen-sign-key") > 0;
        bool is_regenerate = result.count("regenerate-pubkey") > 0;
        bool needs_input_file = is_encrypt || is_decrypt || is_sign || is_verify;

        std::vector<std::string> input_files;
        if (result.count("input")) {
            input_files = result["input"].as<std::vector<std::string>>();
        }

        if (needs_input_file) {
            if (input_files.empty()) {
                std::cerr << "Error: Input file must be specified for this operation." << std::endl; return 1;
            }
            if (input_files.size() > 1) {
                std::cerr << "Error: Too many input files specified. Please provide only one." << std::endl; return 1;
            }
        }
        
        if (is_regenerate) {
            if (input_files.size() < 2) {
                std::cerr << "Error: --regenerate-pubkey requires <private_key_path> and <public_key_path>." << std::endl;
                return 1;
            }
        }

        if ((is_encrypt || is_decrypt) && !result.count("output-file")) {
            std::cerr << "Error: --output-file must be specified for encryption/decryption." << std::endl; return 1;
        }
        if (is_sign && !result.count("signature")) {
            std::cerr << "Error: --signature file path must be specified for signing." << std::endl; return 1;
        }
        if (is_verify && !result.count("signature")) {
            std::cerr << "Error: --signature file path must be specified for verification." << std::endl; return 1;
        }

        std::string mode = result["mode"].as<std::string>();
        if (mode == "hybrid") {
            if (is_encrypt && (!result.count("recipient-mlkem-pubkey") || !result.count("recipient-ecdh-pubkey"))) {
                std::cerr << "Error: For hybrid encryption, both --recipient-mlkem-pubkey and --recipient-ecdh-pubkey are required." << std::endl; return 1;
            }
            if (is_decrypt && (!result.count("recipient-mlkem-privkey") || !result.count("recipient-ecdh-privkey"))) {
                std::cerr << "Error: For hybrid decryption, both --recipient-mlkem-privkey and --recipient-ecdh-privkey are required." << std::endl; return 1;
            }
        }

        // --- パスを絶対パスに変換 ---
        auto get_absolute_path = [](const std::string& path_str) -> std::string {
            if (path_str.empty()) return "";
            try {
                return std::filesystem::absolute(path_str).string();
            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << std::format("Error resolving path for '{}': {}\n", path_str, e.what());
                throw;
            }
        };
        
        std::filesystem::path input_filepath = !input_files.empty() ? get_absolute_path(input_files[0]) : "";
        std::string output_filepath = result.count("output-file") ? get_absolute_path(result["output-file"].as<std::string>()) : "";
        std::string recipient_pubkey_path = result.count("recipient-pubkey") ? get_absolute_path(result["recipient-pubkey"].as<std::string>()) : "";
        std::string user_privkey_path = result.count("user-privkey") ? get_absolute_path(result["user-privkey"].as<std::string>()) : "";
        std::string recipient_mlkem_pubkey_path = result.count("recipient-mlkem-pubkey") ? get_absolute_path(result["recipient-mlkem-pubkey"].as<std::string>()) : "";
        std::string recipient_ecdh_pubkey_path = result.count("recipient-ecdh-pubkey") ? get_absolute_path(result["recipient-ecdh-pubkey"].as<std::string>()) : "";
        std::string recipient_mlkem_privkey_path = result.count("recipient-mlkem-privkey") ? get_absolute_path(result["recipient-mlkem-privkey"].as<std::string>()) : "";
        std::string recipient_ecdh_privkey_path = result.count("recipient-ecdh-privkey") ? get_absolute_path(result["recipient-ecdh-privkey"].as<std::string>()) : "";
        std::string signing_privkey_path = result.count("signing-privkey") ? get_absolute_path(result["signing-privkey"].as<std::string>()) : "";
        std::string signing_pubkey_path = result.count("signing-pubkey") ? get_absolute_path(result["signing-pubkey"].as<std::string>()) : "";
        std::string signature_path = result.count("signature") ? get_absolute_path(result["signature"].as<std::string>()) : "";
        std::string key_dir_path = result.count("key-dir") ? get_absolute_path(result["key-dir"].as<std::string>()) : "";
        std::string regenerate_privkey_path = is_regenerate && input_files.size() > 0 ? get_absolute_path(input_files[0]) : "";
        std::string regenerate_pubkey_path = is_regenerate && input_files.size() > 1 ? get_absolute_path(input_files[1]) : "";


        // --- モードに応じて暗号化ハンドラを生成 ---
        std::unique_ptr<nkCryptoToolBase> crypto_handler;
        if (mode == "ecc") { crypto_handler = std::make_unique<nkCryptoToolECC>(); } 
        else if (mode == "pqc" || mode == "hybrid") { crypto_handler = std::make_unique<nkCryptoToolPQC>(); } 
        else { std::cerr << std::format("Error: Invalid mode '{}'.\n", mode); return 1; }

        if (!key_dir_path.empty()) {
            crypto_handler->setKeyBaseDirectory(key_dir_path);
        }

        // --- 処理の実行 ---
        if (is_gen_enc_key || is_gen_sign_key) {
            std::string passphrase_from_args = result.count("passphrase") ? result["passphrase"].as<std::string>() : "";
            bool passphrase_was_provided = result.count("passphrase") > 0;
            
            auto handle_result = [&](const std::expected<void, CryptoError>& res) {
                if (res) {
                    std::cout << std::format("Key pair generated successfully in {}\n", crypto_handler->getKeyBaseDirectory().string());
                } else {
                    std::cerr << std::format("Error: Key pair generation failed. Reason: {}\n", toString(res.error()));
                    return_code = 1;
                }
            };

            if (is_gen_enc_key && mode == "hybrid") {
                std::string mlkem_passphrase, ecdh_passphrase;
                if (passphrase_was_provided) {
                    mlkem_passphrase = passphrase_from_args;
                    ecdh_passphrase = passphrase_from_args;
                    std::cout << "Using provided passphrase for both ML-KEM and ECDH keys." << std::endl;
                } else {
                    mlkem_passphrase = get_and_verify_passphrase("Enter passphrase for ML-KEM private key (press Enter to save unencrypted): ");
                    ecdh_passphrase = get_and_verify_passphrase("Enter passphrase for ECDH private key (press Enter to save unencrypted): ");
                }
                auto pqc_handler = static_cast<nkCryptoToolPQC*>(crypto_handler.get());
                auto res_pqc = pqc_handler->generateEncryptionKeyPair(pqc_handler->getKeyBaseDirectory() / "public_enc_hybrid_mlkem.key", pqc_handler->getKeyBaseDirectory() / "private_enc_hybrid_mlkem.key", mlkem_passphrase);
                if(res_pqc) {
                    nkCryptoToolECC ecc_handler;
                    ecc_handler.setKeyBaseDirectory(crypto_handler->getKeyBaseDirectory());
                    auto res_ecc = ecc_handler.generateEncryptionKeyPair(ecc_handler.getKeyBaseDirectory() / "public_enc_hybrid_ecdh.key", ecc_handler.getKeyBaseDirectory() / "private_enc_hybrid_ecdh.key", ecdh_passphrase);
                    handle_result(res_ecc);
                } else {
                    handle_result(res_pqc);
                }
            } else {
                std::string passphrase_to_use = passphrase_was_provided ? passphrase_from_args : get_and_verify_passphrase("Enter passphrase to encrypt " + std::string(is_gen_enc_key ? "encryption" : "signing") + " private key (press Enter to save unencrypted): ");
                if (is_gen_enc_key) {
                    handle_result(crypto_handler->generateEncryptionKeyPair(crypto_handler->getEncryptionPublicKeyPath(), crypto_handler->getEncryptionPrivateKeyPath(), passphrase_to_use));
                } else {
                    handle_result(crypto_handler->generateSigningKeyPair(crypto_handler->getSigningPublicKeyPath(), crypto_handler->getSigningPrivateKeyPath(), passphrase_to_use));
                }
            }
        }
        else if (is_regenerate) {
            std::string passphrase_from_args = result.count("passphrase") ? result["passphrase"].as<std::string>() : "";
            bool passphrase_was_provided = result.count("passphrase") > 0;
            std::string passphrase_to_use = passphrase_was_provided ? passphrase_from_args : get_and_verify_passphrase("Enter passphrase for private key (press Enter if unencrypted): ");
            auto res = crypto_handler->regeneratePublicKey(regenerate_privkey_path, regenerate_pubkey_path, passphrase_to_use);
            if (res) {
                std::cout << std::format("Public key successfully regenerated and saved to: {}\n", regenerate_pubkey_path);
            } else {
                std::cerr << std::format("Failed to regenerate public key. Reason: {}\n", toString(res.error()));
                return_code = 1;
            }
        }
        else if (needs_input_file) {
            asio::io_context main_io_context;
            if (is_encrypt) {
                std::cout << std::format("Starting {} encryption...\n", mode);
                std::map<std::string, std::string> key_paths;
                if (mode == "hybrid") {
                    key_paths["recipient-mlkem-pubkey"] = recipient_mlkem_pubkey_path;
                    key_paths["recipient-ecdh-pubkey"] = recipient_ecdh_pubkey_path;
                } else {
                    key_paths["recipient-pubkey"] = recipient_pubkey_path;
                }
                crypto_handler->encryptFileWithPipeline(main_io_context, input_filepath.string(), output_filepath, key_paths, [&](std::error_code ec){ if(ec) return_code = 1; });
            } else if (is_decrypt) {
                std::cout << std::format("Starting {} decryption...\n", mode);
                std::map<std::string, std::string> key_paths;
                    if (mode == "hybrid") {
                    key_paths["recipient-mlkem-privkey"] = recipient_mlkem_privkey_path;
                    key_paths["recipient-ecdh-privkey"] = recipient_ecdh_privkey_path;
                } else {
                    key_paths["user-privkey"] = user_privkey_path;
                }
                crypto_handler->decryptFileWithPipeline(main_io_context, input_filepath.string(), output_filepath, key_paths, [&](std::error_code ec){ if(ec) return_code = 1; });
            } else if (is_sign) {
                std::cout << "Starting file signing..." << std::endl;
                asio::co_spawn(main_io_context, crypto_handler->signFile(
                    main_io_context,
                    input_filepath,
                    signature_path,
                    signing_privkey_path,
                    result["digest-algo"].as<std::string>()
                ), [&](std::exception_ptr p) {
                    try {
                        if (p) {
                            std::rethrow_exception(p);
                        }
                        // Success message is already printed inside the coroutine
                    } catch (const std::exception& e) {
                        std::cerr << "\nAn error occurred during signing: " << e.what() << std::endl;
                        return_code = 1;
                    }
                });
            } else if (is_verify) {
                std::cout << "Starting signature verification..." << std::endl;
                asio::co_spawn(main_io_context, crypto_handler->verifySignature(
                    main_io_context,
                    input_filepath,
                    signature_path,
                    signing_pubkey_path
                ), [&](std::exception_ptr p, std::expected<void, CryptoError> result) {
                    try {
                        if (p) {
                            std::rethrow_exception(p);
                        }
                        if (result) {
                            std::cout << "\nSignature verified successfully." << std::endl;
                        } else {
                            std::cerr << std::format("\nSignature verification failed. Reason: {}\n", toString(result.error()));
                            return_code = 1;
                        }
                    } catch (const std::exception& e) {
                        std::cerr << "\nAn error occurred during verification: " << e.what() << std::endl;
                        return_code = 1;
                    }
                });
            }
            main_io_context.run();
        }

    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return_code = 1;
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return_code = 1;
    }

    OSSL_PROVIDER_unload(nullptr);
    return return_code;
}