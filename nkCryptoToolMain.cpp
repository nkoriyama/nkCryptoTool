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
#include <thread>
#include <asio.hpp>
#include <asio/co_spawn.hpp>

#include <cxxopts.hpp>

#include <openssl/provider.h>
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#include <cstdio>
#endif

// パスフレーズをコンソールから安全に入力するための関数
std::string get_masked_passphrase() {
    std::string passphrase_input;
#if defined(_WIN32) || defined(_WIN64)
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!passphrase_input.empty()) {
                passphrase_input.pop_back();
                std::cout << "\b \b";
            }
        } else {
            passphrase_input.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    if (!isatty(STDIN_FILENO)) {
        std::getline(std::cin, passphrase_input);
        return passphrase_input;
    }
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, passphrase_input);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    return passphrase_input;
}

// パスフレーズを2回入力させ、一致を確認する関数
std::string get_and_verify_passphrase(const std::string& prompt) {
    std::string pass1, pass2;
    do {
        std::cout << prompt;
        std::cout.flush();
        pass1 = get_masked_passphrase();
        if (pass1.empty()) {
            return "";
        }
        std::cout << "Verifying - Enter same passphrase again: ";
        std::cout.flush();
        pass2 = get_masked_passphrase();
        if (pass1 != pass2) {
            std::cerr << "\nPassphrases do not match. Please try again." << std::endl;
        }
    } while (pass1 != pass2);
    return pass1;
}

// OpenSSLが秘密鍵のパスフレーズを要求する際に呼び出すコールバック関数
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag;
    const char* key_description = static_cast<const char*>(userdata);
    if (key_description && *key_description) {
        std::cout << "Enter passphrase for " << key_description << ": ";
    } else {
        std::cout << "Enter passphrase for private key: ";
    }
    std::cout.flush();
    std::string final_passphrase = get_masked_passphrase();
    if (std::cin.eof()) { return 0; }
    if (final_passphrase.length() >= (unsigned int)size) {
        std::cerr << "\nError: Passphrase is too long." << std::endl;
        return 0;
    }
    strncpy(buf, final_passphrase.c_str(), size);
    buf[size - 1] = '\0';
    return static_cast<int>(strlen(buf));
}

int main(int argc, char* argv[]) {
    OSSL_PROVIDER_load(nullptr, "default");
    int return_code = 0;

    try {
        cxxopts::Options options("nkCryptoTool", "Encrypt, decrypt, sign, or verify files using ECC, PQC, or Hybrid mode.");
        options.positional_help("[FILE] [private_key_path] [public_key_path]");

        options.add_options()
            ("m,mode", "Use 'ecc', 'pqc', or 'hybrid'", cxxopts::value<std::string>()->default_value("ecc"))
            ("p,passphrase", "Passphrase for private key. For hybrid key generation, this is applied to BOTH keys.", cxxopts::value<std::string>())
            ("o,output-file", "Output file path", cxxopts::value<std::string>())
            ("h,help", "Display this help message")
            ("gen-enc-key", "Generate encryption key pair(s)")
            ("gen-sign-key", "Generate signing key pair ('ecc' or 'pqc' mode)")
            ("encrypt", "Encrypt input file")
            ("decrypt", "Decrypt input file")
            ("sign", "Sign input file")
            ("verify", "Verify signature of input file")
            ("regenerate-pubkey", "Regenerate public key from private key. Expects <private_key_path> and <public_key_path> as positional arguments.")
            ("recipient-pubkey", "Recipient's public key (for ecc/pqc)", cxxopts::value<std::string>())
            ("user-privkey", "Your private key (for ecc/pqc)", cxxopts::value<std::string>())
            ("recipient-mlkem-pubkey", "Recipient's ML-KEM public key (for hybrid)", cxxopts::value<std::string>())
            ("recipient-ecdh-pubkey", "Recipient's ECDH public key (for hybrid)", cxxopts::value<std::string>())
            ("recipient-mlkem-privkey", "Your ML-KEM private key (for hybrid)", cxxopts::value<std::string>())
            ("recipient-ecdh-privkey", "Your ECDH private key (for hybrid)", cxxopts::value<std::string>())
            ("signing-privkey", "Your private signing key", cxxopts::value<std::string>())
            ("signing-pubkey", "Signer's public key", cxxopts::value<std::string>())
            ("signature", "Path to the signature file", cxxopts::value<std::string>())
            ("digest-algo", "Hashing algorithm (e.g., SHA256, SHA3-256)", cxxopts::value<std::string>()->default_value("SHA256"))
            ("key-dir", "Base directory for keys (default: 'keys')", cxxopts::value<std::string>())
            ("input", "Input file", cxxopts::value<std::vector<std::string>>());

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
                std::cerr << "Error resolving path for '" << path_str << "': " << e.what() << std::endl;
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
        else if (mode == "pqc" || mode == "hybrid") { crypto_handler = std::make_unique<nkCryptoToolPQC>(); if (mode == "pqc") options.add_options()("digest-algo", "", cxxopts::value<std::string>()->default_value("SHA3-256")); } 
        else { std::cerr << "Error: Invalid mode '" << mode << "'." << std::endl; return 1; }

        if (!key_dir_path.empty()) {
            crypto_handler->setKeyBaseDirectory(key_dir_path);
        }

        // --- 処理の実行 ---
        if (is_gen_enc_key || is_gen_sign_key) {
            bool success = false;
            std::string passphrase_from_args = result.count("passphrase") ? result["passphrase"].as<std::string>() : "";
            bool passphrase_was_provided = result.count("passphrase") > 0;

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
                success = pqc_handler->generateEncryptionKeyPair(pqc_handler->getKeyBaseDirectory()/"public_enc_hybrid_mlkem.key", pqc_handler->getKeyBaseDirectory()/"private_enc_hybrid_mlkem.key", mlkem_passphrase);
                if(success) {
                    nkCryptoToolECC ecc_handler;
                    ecc_handler.setKeyBaseDirectory(crypto_handler->getKeyBaseDirectory());
                    success = ecc_handler.generateEncryptionKeyPair(ecc_handler.getKeyBaseDirectory()/"public_enc_hybrid_ecdh.key", ecc_handler.getKeyBaseDirectory()/"private_enc_hybrid_ecdh.key", ecdh_passphrase);
                }
            } else {
                std::string passphrase_to_use = passphrase_was_provided ? passphrase_from_args : get_and_verify_passphrase("Enter passphrase to encrypt " + std::string(is_gen_enc_key ? "encryption" : "signing") + " private key (press Enter to save unencrypted): ");
                if (is_gen_enc_key) {
                    success = crypto_handler->generateEncryptionKeyPair(crypto_handler->getEncryptionPublicKeyPath(), crypto_handler->getEncryptionPrivateKeyPath(), passphrase_to_use);
                } else {
                    success = crypto_handler->generateSigningKeyPair(crypto_handler->getSigningPublicKeyPath(), crypto_handler->getSigningPrivateKeyPath(), passphrase_to_use);
                }
            }
            if (success) { std::cout << "Key pair generated successfully in " << crypto_handler->getKeyBaseDirectory().string() << std::endl; } 
            else { std::cerr << "Error: Key pair generation failed." << std::endl; return_code = 1; }
        }
        else if (is_regenerate) {
            std::string passphrase_from_args = result.count("passphrase") ? result["passphrase"].as<std::string>() : "";
            bool passphrase_was_provided = result.count("passphrase") > 0;
            std::string passphrase_to_use = passphrase_was_provided ? passphrase_from_args : get_and_verify_passphrase("Enter passphrase for private key (press Enter if unencrypted): ");
            if (crypto_handler->regeneratePublicKey(regenerate_privkey_path, regenerate_pubkey_path, passphrase_to_use)) {
                std::cout << "Public key successfully regenerated and saved to: " << regenerate_pubkey_path << std::endl;
            } else {
                std::cerr << "Failed to regenerate public key." << std::endl;
                return_code = 1;
            }
        }
        else if (needs_input_file) {
            asio::io_context main_io_context;
            if (is_encrypt) {
                std::cout << "Starting " << mode << " encryption..." << std::endl;
                std::map<std::string, std::string> key_paths;
                if (mode == "hybrid") {
                    key_paths["recipient-mlkem-pubkey"] = recipient_mlkem_pubkey_path;
                    key_paths["recipient-ecdh-pubkey"] = recipient_ecdh_pubkey_path;
                } else {
                    key_paths["recipient-pubkey"] = recipient_pubkey_path;
                }
                crypto_handler->encryptFileWithPipeline(main_io_context, input_filepath.string(), output_filepath, key_paths, [&](std::error_code ec){ if(ec) return_code = 1; });
            } else if (is_decrypt) {
                std::cout << "Starting " << mode << " decryption..." << std::endl;
                std::map<std::string, std::string> key_paths;
                    if (mode == "hybrid") {
                    key_paths["recipient-mlkem-privkey"] = recipient_mlkem_privkey_path;
                    key_paths["recipient-ecdh-privkey"] = recipient_ecdh_privkey_path;
                } else {
                    key_paths["user-privkey"] = user_privkey_path;
                }
                crypto_handler->decryptFileWithPipeline(main_io_context, input_filepath.string(), output_filepath, key_paths, [&](std::error_code ec){ if(ec) return_code = 1; });
            } else if (is_sign) {
                crypto_handler->signFile(main_io_context, input_filepath, signature_path, signing_privkey_path, result["digest-algo"].as<std::string>(), [&](std::error_code ec){ if(ec) return_code = 1; });
            } else if (is_verify) {
                crypto_handler->verifySignature(main_io_context, input_filepath, signature_path, signing_pubkey_path,
                    [&](std::error_code ec, bool res){ if(ec) { std::cerr << "\nError during verification: " << ec.message() << std::endl; return_code = 1; } else if (res) { std::cout << "\nSignature verified successfully." << std::endl; } else { std::cerr << "\nSignature verification failed." << std::endl; return_code = 1;} });
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