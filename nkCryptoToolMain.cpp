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

#include <getopt.h>

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

// 使用方法を表示する関数
void display_usage() {
    std::cout << "Usage: nkCryptoTool [OPTIONS] [FILE]\n"
              << "Encrypt, decrypt, sign, or verify files using ECC, PQC, or Hybrid mode.\n\n"
              << "Modes of operation (choose one):\n"
              << "  --mode <type>       Use 'ecc', 'pqc', or 'hybrid'. Default: ecc\n\n"
              << "Key Generation:\n"
              << "  --gen-enc-key       Generate encryption key pair(s).\n"
              << "  --gen-sign-key      Generate signing key pair ('ecc' or 'pqc' mode).\n"
              << "  --passphrase <pwd>  Passphrase for private key encryption. For hybrid key generation, this passphrase is applied to BOTH keys.\n"
              << "                      If not provided, or empty, you will be prompted.\n\n"
              << "Encryption:\n"
              << "  --encrypt           Encrypt input file.\n"
              << "  --parallel          Use coroutine-based parallel processing.\n"
              << "  --pipeline          Use pipeline-based parallel processing.\n"
              << "  -o, --output-file <path>   Output file path.\n"
              << "  --recipient-pubkey <path>      Recipient's public key (for ecc/pqc).\n"
              << "  --recipient-mlkem-pubkey <path> Recipient's ML-KEM public key (for hybrid).\n"
              << "  --recipient-ecdh-pubkey <path>  Recipient's ECDH public key (for hybrid).\n\n"
              << "Decryption:\n"
              << "  --decrypt           Decrypt input file.\n"
              << "  -o, --output-file <path>   Output file path.\n"
              << "  --user-privkey <path>           Your private key (for ecc/pqc).\n"
              << "  --recipient-mlkem-privkey <path> Your ML-KEM private key (for hybrid).\n"
              << "  --recipient-ecdh-privkey <path>  Your ECDH private key (for hybrid).\n\n"
              << "Signing/Verification ('ecc' or 'pqc' mode only):\n"
              << "  --sign              Sign input file.\n"
              << "  --verify            Verify signature of input file.\n"
              << "  --signing-privkey <path> Your private signing key.\n"
              << "  --signing-pubkey <path>  Signer's public key.\n"
              << "  --signature <path>  Path to the signature file.\n"
              << "  --digest-algo <algo> Hashing algorithm (e.g., SHA256, SHA3-256).\n\n"
              << "Other Options:\n"
              << "  --key-dir <path>    Base directory for keys (default: 'keys').\n"
              << "  --regenerate-pubkey <private_key_path> <public_key_path> [passphrase] - Regenerate public key from private key.\n"
              << "  -h, --help          Display this help message.\n";
}

int main(int argc, char* argv[]) {
    OSSL_PROVIDER_load(nullptr, "default");

    std::map<std::string, bool> flags;
    std::map<std::string, std::string> options;
    std::vector<std::string> non_option_args;
    std::string passphrase_from_args;
    bool passphrase_was_provided = false;

    // デフォルト値の設定
    options["mode"] = "ecc";
    options["digest-algo"] = "SHA256";
    options["output-file"] = "";
    options["signature"] = "";
    flags["parallel"] = false;
    flags["pipeline"] = false;

    enum { 
        OPT_GEN_ENC_KEY = 256, OPT_GEN_SIGN_KEY, OPT_ENCRYPT, OPT_DECRYPT, 
        OPT_SIGN, OPT_VERIFY, OPT_RECIPIENT_PUBKEY, OPT_USER_PRIVKEY, 
        OPT_RECIPIENT_MLKEM_PUBKEY, OPT_RECIPIENT_ECDH_PUBKEY, 
        OPT_RECIPIENT_MLKEM_PRIVKEY, OPT_RECIPIENT_ECDH_PRIVKEY, 
        OPT_SIGNING_PRIVKEY, OPT_SIGNING_PUBKEY, OPT_SIGNATURE, 
        OPT_DIGEST_ALGO, OPT_KEY_DIR, OPT_PARALLEL, OPT_PIPELINE, OPT_REGENERATE_PUBKEY 
    };
    
    static struct option long_options[] = {
        {"mode", required_argument, nullptr, 'm'},
        {"passphrase", required_argument, nullptr, 'p'},
        {"output-file", required_argument, nullptr, 'o'},
        {"help", no_argument, nullptr, 'h'},
        {"gen-enc-key", no_argument, nullptr, OPT_GEN_ENC_KEY},
        {"gen-sign-key", no_argument, nullptr, OPT_GEN_SIGN_KEY},
        {"encrypt", no_argument, nullptr, OPT_ENCRYPT},
        {"decrypt", no_argument, nullptr, OPT_DECRYPT},
        {"sign", no_argument, nullptr, OPT_SIGN},
        {"verify", no_argument, nullptr, OPT_VERIFY},
        {"parallel", no_argument, nullptr, OPT_PARALLEL},
        {"pipeline", no_argument, nullptr, OPT_PIPELINE}, 
        {"regenerate-pubkey", no_argument, nullptr, OPT_REGENERATE_PUBKEY},
        {"recipient-pubkey", required_argument, nullptr, OPT_RECIPIENT_PUBKEY},
        {"user-privkey", required_argument, nullptr, OPT_USER_PRIVKEY},
        {"recipient-mlkem-pubkey", required_argument, nullptr, OPT_RECIPIENT_MLKEM_PUBKEY},
        {"recipient-ecdh-pubkey", required_argument, nullptr, OPT_RECIPIENT_ECDH_PUBKEY},
        {"recipient-mlkem-privkey", required_argument, nullptr, OPT_RECIPIENT_MLKEM_PRIVKEY},
        {"recipient-ecdh-privkey", required_argument, nullptr, OPT_RECIPIENT_ECDH_PRIVKEY},
        {"signing-privkey", required_argument, nullptr, OPT_SIGNING_PRIVKEY},
        {"signing-pubkey", required_argument, nullptr, OPT_SIGNING_PUBKEY},
        {"signature", required_argument, nullptr, OPT_SIGNATURE},
        {"digest-algo", required_argument, nullptr, OPT_DIGEST_ALGO},
        {"key-dir", required_argument, nullptr, OPT_KEY_DIR},
        {nullptr, 0, nullptr, 0}
    };
    
    int return_code = 0;

    // コマンドライン引数のパース
    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:o:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'p': passphrase_from_args = optarg; passphrase_was_provided = true; break;
            case 'm': options["mode"] = optarg; break;
            case 'o': options["output-file"] = optarg; break;
            case 'h': display_usage(); return 0;
            case OPT_GEN_ENC_KEY: flags["gen-enc-key"] = true; break;
            case OPT_GEN_SIGN_KEY: flags["gen-sign-key"] = true; break;
            case OPT_ENCRYPT: flags["encrypt"] = true; break;
            case OPT_DECRYPT: flags["decrypt"] = true; break;
            case OPT_SIGN: flags["sign"] = true; break;
            case OPT_VERIFY: flags["verify"] = true; break;
            case OPT_PARALLEL: flags["parallel"] = true; break;
            case OPT_PIPELINE: flags["pipeline"] = true; break;
            case OPT_RECIPIENT_PUBKEY: options["recipient-pubkey"] = optarg; break;
            case OPT_USER_PRIVKEY: options["user-privkey"] = optarg; break;
            case OPT_RECIPIENT_MLKEM_PUBKEY: options["recipient-mlkem-pubkey"] = optarg; break;
            case OPT_RECIPIENT_ECDH_PUBKEY: options["recipient-ecdh-pubkey"] = optarg; break;
            case OPT_RECIPIENT_MLKEM_PRIVKEY: options["recipient-mlkem-privkey"] = optarg; break;
            case OPT_RECIPIENT_ECDH_PRIVKEY: options["recipient-ecdh-privkey"] = optarg; break;
            case OPT_SIGNING_PRIVKEY: options["signing-privkey"] = optarg; break;
            case OPT_SIGNING_PUBKEY: options["signing-pubkey"] = optarg; break;
            case OPT_SIGNATURE: options["signature"] = optarg; break;
            case OPT_DIGEST_ALGO: options["digest-algo"] = optarg; break;
            case OPT_KEY_DIR: options["key-dir"] = optarg; break;
            case OPT_REGENERATE_PUBKEY: flags["regenerate-pubkey"] = true; break;
            default: display_usage(); return 1;
        }
    }

    for (int i = optind; i < argc; ++i) { non_option_args.push_back(argv[i]); }
    
    // 引数検証
    bool needs_input_file = flags["encrypt"] || flags["decrypt"] || flags["sign"] || flags["verify"];
    bool is_key_gen = flags["gen-enc-key"] || flags["gen-sign-key"];
    bool is_regenerate_pubkey = flags["regenerate-pubkey"];

    if (flags["parallel"] && flags["pipeline"]) {
        std::cerr << "Error: --parallel and --pipeline cannot be used at the same time." << std::endl;
        return 1;
    }
    if (needs_input_file) {
        if (non_option_args.empty()) {
            std::cerr << "Error: Input file must be specified for this operation." << std::endl; return 1;
        }
        if (non_option_args.size() > 1) {
            std::cerr << "Error: Too many input files specified. Please provide only one." << std::endl; return 1;
        }
    } else if (!is_key_gen && !is_regenerate_pubkey && argc <= 1) {
        display_usage();
        return 0;
    }
    if (is_regenerate_pubkey) {
        if (non_option_args.size() < 2) {
            std::cerr << "Error: --regenerate-pubkey requires private_key_path and public_key_path." << std::endl;
            return 1;
        }
        options["regenerate-privkey-path"] = non_option_args[0];
        options["regenerate-pubkey-path"] = non_option_args[1];
        non_option_args.erase(non_option_args.begin(), non_option_args.begin() + 2);
    }
    if ((flags["encrypt"] || flags["decrypt"]) && options["output-file"].empty()) {
        std::cerr << "Error: --output-file must be specified for encryption/decryption." << std::endl; return 1;
    }
    if (flags["sign"] && options["signature"].empty()) {
        std::cerr << "Error: --signature file path must be specified for signing." << std::endl; return 1;
    }
    if (flags["verify"] && options["signature"].empty()) {
        std::cerr << "Error: --signature file path must be specified for verification." << std::endl; return 1;
    }
    if (options["mode"] == "hybrid") {
        if (flags["encrypt"] && (options["recipient-mlkem-pubkey"].empty() || options["recipient-ecdh-pubkey"].empty())) {
            std::cerr << "Error: For hybrid encryption, both --recipient-mlkem-pubkey and --recipient-ecdh-pubkey are required." << std::endl; return 1;
        }
        if (flags["decrypt"] && (options["recipient-mlkem-privkey"].empty() || options["recipient-ecdh-privkey"].empty())) {
            std::cerr << "Error: For hybrid decryption, both --recipient-mlkem-privkey and --recipient-ecdh-privkey are required." << std::endl; return 1;
        }
    }

    // パス関連のオプションを絶対パスに変換
    std::vector<std::string> path_option_keys = {
        "output-file", "recipient-pubkey", "user-privkey", "recipient-mlkem-pubkey",
        "recipient-ecdh-pubkey", "recipient-mlkem-privkey", "recipient-ecdh-privkey",
        "signing-privkey", "signing-pubkey", "signature",
        "regenerate-privkey-path", "regenerate-pubkey-path"
    };
    for(const auto& key : path_option_keys) {
        if (options.count(key) && !options.at(key).empty()) {
            try {
                options[key] = std::filesystem::absolute(options.at(key)).string();
            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "Error resolving path for --" << key << " '" << options.at(key) << "': " << e.what() << std::endl;
                return 1;
            }
        }
    }
    
    // 入力ファイルを絶対パスに変換
    std::filesystem::path input_filepath;
    if (!non_option_args.empty()) {
        try {
            input_filepath = std::filesystem::absolute(non_option_args[0]);
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error resolving input file path '" << non_option_args[0] << "': " << e.what() << std::endl;
            return 1;
        }
    }

    // モードに応じて暗号化ハンドラを生成
    std::unique_ptr<nkCryptoToolBase> crypto_handler;
    if (options["mode"] == "ecc") { crypto_handler = std::make_unique<nkCryptoToolECC>(); } 
    else if (options["mode"] == "pqc" || options["mode"] == "hybrid") { crypto_handler = std::make_unique<nkCryptoToolPQC>(); if (options["mode"] == "pqc") options["digest-algo"] = "SHA3-256"; } 
    else { std::cerr << "Error: Invalid mode '" << options["mode"] << "'." << std::endl; return 1; }

    if (options.count("key-dir")) {
        try {
            crypto_handler->setKeyBaseDirectory(std::filesystem::absolute(options["key-dir"]));
        } catch (const std::filesystem::filesystem_error& e) {
            std::cerr << "Error resolving path for --key-dir '" << options["key-dir"] << "': " << e.what() << std::endl;
            return 1;
        }
    }

    // --- 処理の実行 ---
    try {
        if (flags["gen-enc-key"] || flags["gen-sign-key"]) {
            bool success = false;
            if (flags["gen-enc-key"] && options["mode"] == "hybrid") {
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
                std::string passphrase_to_use = passphrase_was_provided ? passphrase_from_args : get_and_verify_passphrase("Enter passphrase to encrypt " + std::string(flags["gen-enc-key"] ? "encryption" : "signing") + " private key (press Enter to save unencrypted): ");
                if (flags["gen-enc-key"]) {
                    success = crypto_handler->generateEncryptionKeyPair(crypto_handler->getEncryptionPublicKeyPath(), crypto_handler->getEncryptionPrivateKeyPath(), passphrase_to_use);
                } else {
                    success = crypto_handler->generateSigningKeyPair(crypto_handler->getSigningPublicKeyPath(), crypto_handler->getSigningPrivateKeyPath(), passphrase_to_use);
                }
            }
            if (success) { std::cout << "Key pair generated successfully in " << crypto_handler->getKeyBaseDirectory().string() << std::endl; } 
            else { std::cerr << "Error: Key pair generation failed." << std::endl; return_code = 1; }
        }
        else if (is_regenerate_pubkey) {
            std::string passphrase_to_use = passphrase_was_provided ? passphrase_from_args : get_and_verify_passphrase("Enter passphrase for private key (press Enter if unencrypted): ");
            if (crypto_handler->regeneratePublicKey(options["regenerate-privkey-path"], options["regenerate-pubkey-path"], passphrase_to_use)) {
                std::cout << "Public key successfully regenerated and saved to: " << options["regenerate-pubkey-path"] << std::endl;
            } else {
                std::cerr << "Failed to regenerate public key." << std::endl;
                return_code = 1;
            }
        }
        else if (flags["parallel"] && (flags["encrypt"] || flags["decrypt"])) {
            asio::io_context main_io_context;
            asio::io_context worker_context;
            auto work_guard = asio::make_work_guard(worker_context.get_executor());
            std::vector<std::thread> threads;
            const auto num_threads = std::max(1u, std::thread::hardware_concurrency());
            for (unsigned i = 0; i < num_threads; ++i) {
                threads.emplace_back([&]() {
                    try {
                        worker_context.run();
                    } catch (const std::exception& e) {
                        std::cerr << "FATAL: Unhandled exception in worker thread: " << e.what() << std::endl;
                    } catch (...) {
                        std::cerr << "FATAL: Unknown unhandled exception in worker thread." << std::endl;
                    }
                });
            }

            if(flags["encrypt"]) {
                std::cout << "Starting parallel " << options["mode"] << " encryption..." << std::endl;
                if (options["mode"] == "hybrid") {
                    auto pqc_handler = static_cast<nkCryptoToolPQC*>(crypto_handler.get());
                    asio::co_spawn(main_io_context, pqc_handler->encryptFileParallelHybrid(
                        worker_context, 
                        input_filepath.string(), 
                        options["output-file"], 
                        options["recipient-mlkem-pubkey"], 
                        options["recipient-ecdh-pubkey"]),
                        [&](std::exception_ptr p) { if (p) { try { std::rethrow_exception(p); } catch (const std::exception& e) { std::cerr << "\nParallel encryption failed: " << e.what() << std::endl; return_code = 1; } } });
                } else {
                    asio::co_spawn(main_io_context, crypto_handler->encryptFileParallel(
                        worker_context, 
                        input_filepath.string(), 
                        options["output-file"], 
                        options["recipient-pubkey"]), 
                        [&](std::exception_ptr p) { if (p) { try { std::rethrow_exception(p); } catch (const std::exception& e) { std::cerr << "\nParallel encryption failed: " << e.what() << std::endl; return_code = 1; } } });
                }
            } else { // decrypt
                std::cout << "Starting parallel " << options["mode"] << " decryption..." << std::endl;
                 if (options["mode"] == "hybrid") {
                    auto pqc_handler = static_cast<nkCryptoToolPQC*>(crypto_handler.get());
                    asio::co_spawn(main_io_context, pqc_handler->decryptFileParallelHybrid(
                        worker_context,
                        input_filepath.string(),
                        options["output-file"],
                        options["recipient-mlkem-privkey"],
                        options["recipient-ecdh-privkey"]),
                        [&](std::exception_ptr p) { if (p) { try { std::rethrow_exception(p); } catch (const std::exception& e) { std::cerr << "\nParallel decryption failed: " << e.what() << std::endl; return_code = 1; } } });
                } else {
                    asio::co_spawn(main_io_context, crypto_handler->decryptFileParallel(
                        worker_context, 
                        input_filepath.string(), 
                        options["output-file"], 
                        options["user-privkey"]), 
                        [&](std::exception_ptr p) { if (p) { try { std::rethrow_exception(p); } catch (const std::exception& e) { std::cerr << "\nParallel decryption failed: " << e.what() << std::endl; return_code = 1; } } });
                }
            }
            main_io_context.run();
            work_guard.reset(); 
            worker_context.stop();
            for(auto& t : threads) { if (t.joinable()) { t.join(); } }
        }
        else if (needs_input_file) {
            asio::io_context main_io_context;
            if (flags["encrypt"]) {
                if (flags["pipeline"]) {
                    std::cout << "Starting pipeline " << options["mode"] << " encryption..." << std::endl;
                    std::map<std::string, std::string> key_paths;
                    if (options["mode"] == "hybrid") {
                        key_paths["recipient-mlkem-pubkey"] = options["recipient-mlkem-pubkey"];
                        key_paths["recipient-ecdh-pubkey"] = options["recipient-ecdh-pubkey"];
                    } else if (options["mode"] == "pqc") {
                        key_paths["recipient-pubkey"] = options["recipient-pubkey"];
                    } else { // ecc
                        key_paths["recipient-pubkey"] = options["recipient-pubkey"];
                    }
                    crypto_handler->encryptFileWithPipeline(main_io_context, input_filepath.string(), options["output-file"], key_paths, [&](std::error_code ec){ if(ec) return_code = 1; });

                } else {
                    if (options["mode"] == "hybrid") { 
                        crypto_handler->encryptFileHybrid(main_io_context, input_filepath, options["output-file"], options["recipient-mlkem-pubkey"], options["recipient-ecdh-pubkey"], [&](std::error_code ec){ if(ec) return_code = 1; }); 
                    } else { 
                        crypto_handler->encryptFile(main_io_context, input_filepath, options["output-file"], options["recipient-pubkey"], [&](std::error_code ec){ if(ec) return_code = 1; }); 
                    }
                }
            } else if (flags["decrypt"]) {
                if (flags["pipeline"]) {
                    std::cout << "Starting pipeline " << options["mode"] << " decryption..." << std::endl;
                    std::map<std::string, std::string> key_paths;
                     if (options["mode"] == "hybrid") {
                        key_paths["recipient-mlkem-privkey"] = options["recipient-mlkem-privkey"];
                        key_paths["recipient-ecdh-privkey"] = options["recipient-ecdh-privkey"];
                    } else if (options["mode"] == "pqc") {
                        key_paths["user-privkey"] = options["user-privkey"];
                    } else { // ecc
                        key_paths["user-privkey"] = options["user-privkey"];
                    }
                    crypto_handler->decryptFileWithPipeline(main_io_context, input_filepath.string(), options["output-file"], key_paths, [&](std::error_code ec){ if(ec) return_code = 1; });
                } else {
                    if (options["mode"] == "hybrid") { 
                        crypto_handler->decryptFileHybrid(main_io_context, input_filepath, options["output-file"], options["recipient-mlkem-privkey"], options["recipient-ecdh-privkey"], [&](std::error_code ec){ if(ec) return_code = 1; }); 
                    } else { 
                        crypto_handler->decryptFile(main_io_context, input_filepath, options["output-file"], options["user-privkey"], "", [&](std::error_code ec){ if(ec) return_code = 1; }); 
                    }
                }
            } else if (flags["sign"]) {
                crypto_handler->signFile(main_io_context, input_filepath, options["signature"], options["signing-privkey"], options["digest-algo"], [&](std::error_code ec){ if(ec) return_code = 1; });
            } else if (flags["verify"]) {
                crypto_handler->verifySignature(main_io_context, input_filepath, options["signature"], options["signing-pubkey"],
                    [&](std::error_code ec, bool result){ if(ec) { std::cerr << "\nError during verification: " << ec.message() << std::endl; return_code = 1; } else if (result) { std::cout << "\nSignature verified successfully." << std::endl; } else { std::cerr << "\nSignature verification failed." << std::endl; return_code = 1;} });
            }
            main_io_context.run();
        }
    } catch (const std::exception& e) {
        std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
        return_code = 1;
    }

    OSSL_PROVIDER_unload(nullptr);
    return return_code;
}
