// nkCryptoToolMain.cpp (同期版から非同期対応版へ)

// --- Required Environment ---
// - C++17 compiler (for std::filesystem, std::shared_ptr, std::function, std::bind)
// - OpenSSL library and headers (e.g., libssl-dev on Debian/Ubuntu, or pre-built for Windows)
//   - Requires OpenSSL 3.0+ for PQC features.
// - Asio library (header-only or compiled, e.g., from https://think-async.com/Asio/)
//   - For async file I/O, needs a recent Asio version with `asio::stream_file`.
// - On Windows: MinGW or Cygwin environment recommended for getopt_long.
//   MSVC users will need a getopt implementation or replacement.

// --- Compilation Note ---
// Compile with C++17 or later and link against OpenSSL and potentially Asio if not header-only.
// Example for g++ (Linux):
// g++ nkCryptoToolMain.cpp nkCryptoToolBase.cpp nkCryptoToolECC.cpp nkCryptoToolPQC.cpp -o nkCryptoTool -lssl -lcrypto -std=c++17 -I/path/to/asio/include
// Make sure to include Asio headers path (-I).

#include <iostream>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr, std::shared_ptr
#include <filesystem> // For std::filesystem::path
#include <mutex> // For std::mutex
#include <map> // For std::map to store options
#include <functional> // For std::function

// Asio headers
#include <asio.hpp>

// For getopt_long
#ifdef _WIN32
#include "getopt_long.h" // Assuming you have getopt_long.h for Windows if not using MinGW/Cygwin
#else
#include <getopt.h>
#endif

// OpenSSL provider for OpenSSL 3.0+
#include <openssl/provider.h>

// Custom tool classes
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"

// Global passphrase variable for OpenSSL PEM callbacks
std::string global_passphrase_for_pem_cb;
std::mutex passphrase_mutex;

// OpenSSL PEM passphrase callback function
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag; // Unused parameter
    std::string *passphrase_ptr = static_cast<std::string*>(userdata);
    std::string input_passphrase;

    if (passphrase_ptr && !passphrase_ptr->empty()) {
        input_passphrase = *passphrase_ptr;
    } else {
        std::cout << "Enter passphrase: ";
        // For security, disable echo in a real application.
        std::getline(std::cin, input_passphrase);
    }

    if (input_passphrase.length() > (unsigned int)size) {
        std::cerr << "Error: Passphrase too long." << std::endl;
        return 0;
    }
    memcpy(buf, input_passphrase.c_str(), input_passphrase.length());
    return static_cast<int>(input_passphrase.length());
}

// Function to display usage information
void display_usage() {
    std::cout << "Usage: nkCryptoTool [OPTIONS] [FILE]\n"
              << "Encrypt, decrypt, sign, or verify files using ECC, PQC, or Hybrid mode.\n\n"
              << "Modes of operation (choose one):\n"
              << "  --mode ecc          Use Elliptic Curve Cryptography (default if not specified)\n"
              << "  --mode pqc          Use Post-Quantum Cryptography (ML-KEM and ML-DSA)\n"
              << "  --mode hybrid       Use Hybrid PQC (ML-KEM) + ECC (ECDH)\n\n"
              << "Key Generation Options:\n"
              << "  --gen-enc-key       Generate encryption key pair(s).\n"
              << "                      - For 'ecc' and 'pqc' modes, generates one key pair.\n"
              << "                      - For 'hybrid' mode, generates both PQC and ECC key pairs.\n"
              << "  --gen-sign-key      Generate signing key pair (for 'ecc' or 'pqc' mode).\n"
              << "  --passphrase <pwd>  Passphrase for private key encryption (optional, prompted if omitted).\n\n"
              << "Encryption Options:\n"
              << "  --encrypt           Encrypt input file.\n"
              << "  -o <path>           Output file for encrypted data.\n"
              << "  For ECC/PQC modes:\n"
              << "    --recipient-pubkey <path>  Public key of the recipient.\n"
              << "  For Hybrid mode:\n"
              << "    --recipient-mlkem-pubkey <path> Recipient's ML-KEM public key.\n"
              << "    --recipient-ecdh-pubkey <path>  Recipient's ECDH public key.\n\n"
              << "Decryption Options:\n"
              << "  --decrypt           Decrypt input file.\n"
              << "  -o <path>           Output file for decrypted data.\n"
              << "  For ECC/PQC modes:\n"
              << "    --user-privkey <path>      Your private key for decryption.\n"
              << "  For Hybrid mode:\n"
              << "    --recipient-mlkem-privkey <path> Your ML-KEM private key.\n"
              << "    --recipient-ecdh-privkey <path>  Your ECDH private key.\n\n"
              << "Signing/Verification Options (ECC or PQC mode only):\n"
              << "  --sign              Sign input file.\n"
              << "  --signing-privkey <path> Your private signing key.\n"
              << "  --signature <path>  Output file for the signature.\n"
              << "  --digest-algo <algo> Hashing algorithm (e.g., SHA256, SHA3-256).\n"
              << "  --verify            Verify signature of input file.\n"
              << "  --signing-pubkey <path> Signer's public key.\n\n"
              << "Other Options:\n"
              << "  --key-dir <path>    Specify base directory for keys (default: 'keys').\n"
              << "  -h, --help          Display this help message.\n";
}

int main(int argc, char* argv[]) {
    OSSL_PROVIDER* default_prov = OSSL_PROVIDER_load(nullptr, "default");
    if (!default_prov) {
        std::cerr << "Warning: Could not load OpenSSL default provider. Some algorithms might not be available." << std::endl;
    } else {
        std::cout << "OpenSSL default provider loaded." << std::endl;
    }

    std::map<std::string, bool> flags;
    std::map<std::string, std::string> options;
    std::vector<std::string> non_option_args;

    options["mode"] = "ecc";
    options["digest-algo"] = "SHA256";

    // Define integer constants for new long options without short equivalents
    constexpr int RECIPIENT_MLKEM_PUBKEY_OPT = 256;
    constexpr int RECIPIENT_ECDH_PUBKEY_OPT = 257;
    constexpr int RECIPIENT_MLKEM_PRIVKEY_OPT = 258;
    constexpr int RECIPIENT_ECDH_PRIVKEY_OPT = 259;
    constexpr int SIGNATURE_FILE_OPT = 260; // For --signature

    struct option long_options[] = {
        {"mode", required_argument, nullptr, 'm'},
        {"gen-enc-key", no_argument, nullptr, 'e'},
        {"gen-sign-key", no_argument, nullptr, 'g'},
        {"passphrase", required_argument, nullptr, 'p'},
        {"encrypt", no_argument, nullptr, 'c'},
        {"recipient-pubkey", required_argument, nullptr, 'r'},
        {"decrypt", no_argument, nullptr, 'd'},
        {"user-privkey", required_argument, nullptr, 'u'},
        {"output-file", required_argument, nullptr, 'o'},
        {"sign", no_argument, nullptr, 'n'},
        {"signing-privkey", required_argument, nullptr, 'i'},
        {"signature", required_argument, nullptr, SIGNATURE_FILE_OPT},
        {"digest-algo", required_argument, nullptr, 'a'},
        {"verify", no_argument, nullptr, 'v'},
        {"signing-pubkey", required_argument, nullptr, 'b'},
        {"key-dir", required_argument, nullptr, 'k'},
        {"help", no_argument, nullptr, 'h'},
        // New options for hybrid mode
        {"recipient-mlkem-pubkey", required_argument, nullptr, RECIPIENT_MLKEM_PUBKEY_OPT},
        {"recipient-ecdh-pubkey", required_argument, nullptr, RECIPIENT_ECDH_PUBKEY_OPT},
        {"recipient-mlkem-privkey", required_argument, nullptr, RECIPIENT_MLKEM_PRIVKEY_OPT},
        {"recipient-ecdh-privkey", required_argument, nullptr, RECIPIENT_ECDH_PRIVKEY_OPT},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "o:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'm': options["mode"] = optarg; break;
            case 'e': flags["gen_enc_key"] = true; break;
            case 'g': flags["gen_sign_key"] = true; break;
            case 'p': {
                std::lock_guard<std::mutex> lock(passphrase_mutex);
                global_passphrase_for_pem_cb = optarg;
            } break;
            case 'c': flags["encrypt"] = true; break;
            case 'r': options["recipient-pubkey"] = optarg; break;
            case 'd': flags["decrypt"] = true; break;
            case 'u': options["user-privkey"] = optarg; break;
            case 'o': options["output-file"] = optarg; break;
            case 'n': flags["sign"] = true; break;
            case 'i': options["signing-privkey"] = optarg; break;
            case 'a': options["digest-algo"] = optarg; break;
            case 'v': flags["verify"] = true; break;
            case 'b': options["signing-pubkey"] = optarg; break;
            case 'k': options["key-dir"] = optarg; break;
            case 'h': display_usage(); return 0;
            // Handle new hybrid options
            case RECIPIENT_MLKEM_PUBKEY_OPT: options["recipient-mlkem-pubkey"] = optarg; break;
            case RECIPIENT_ECDH_PUBKEY_OPT: options["recipient-ecdh-pubkey"] = optarg; break;
            case RECIPIENT_MLKEM_PRIVKEY_OPT: options["recipient-mlkem-privkey"] = optarg; break;
            case RECIPIENT_ECDH_PRIVKEY_OPT: options["recipient-ecdh-privkey"] = optarg; break;
            case SIGNATURE_FILE_OPT: options["signature-file"] = optarg; break;
            default: display_usage(); return 1;
        }
    }

    for (int i = optind; i < argc; ++i) {
        non_option_args.push_back(argv[i]);
    }

    std::unique_ptr<nkCryptoToolBase> crypto_handler;
    if (options["mode"] == "ecc") {
        crypto_handler = std::make_unique<nkCryptoToolECC>();
    } else if (options["mode"] == "pqc" || options["mode"] == "hybrid") {
        // PQC handler implements both PQC and Hybrid methods
        crypto_handler = std::make_unique<nkCryptoToolPQC>();
        if (options["mode"] == "pqc") {
            options["digest-algo"] = "SHA3-256";
        }
    } else {
        std::cerr << "Error: Invalid mode specified. Choose 'ecc', 'pqc', or 'hybrid'." << std::endl;
        display_usage();
        return 1;
    }

    if (options.count("key-dir")) {
        crypto_handler->setKeyBaseDirectory(options["key-dir"]);
    }

    asio::io_context io_context;
    int return_code = 0;

    if (flags["gen_enc_key"]) {
        if (options["mode"] == "hybrid") {
            std::cout << "Generating hybrid encryption key pairs (PQC and ECC)..." << std::endl;
            auto pqc_gen_handler = std::make_unique<nkCryptoToolPQC>();
            auto ecc_gen_handler = std::make_unique<nkCryptoToolECC>();
            
            std::filesystem::path key_dir = "keys";
            if (options.count("key-dir")) {
                key_dir = options["key-dir"];
            }
            // Set the base directory for both handlers
            pqc_gen_handler->setKeyBaseDirectory(key_dir);
            ecc_gen_handler->setKeyBaseDirectory(key_dir);

            // Define explicit paths for hybrid keys
            auto mlkem_pub_path = key_dir / "public_enc_hybrid_mlkem.key";
            auto mlkem_priv_path = key_dir / "private_enc_hybrid_mlkem.key";
            auto ecdh_pub_path = key_dir / "public_enc_hybrid_ecdh.key";
            auto ecdh_priv_path = key_dir / "private_enc_hybrid_ecdh.key";
            
            bool pqc_success = pqc_gen_handler->generateEncryptionKeyPair(
                mlkem_pub_path,
                mlkem_priv_path,
                global_passphrase_for_pem_cb
            );
            if (pqc_success) {
                std::cout << "PQC keys generated successfully: " << mlkem_pub_path << " and " << mlkem_priv_path << std::endl;
            } else {
                std::cerr << "Error: PQC encryption key generation failed." << std::endl; return_code = 1;
            }

            bool ecc_success = ecc_gen_handler->generateEncryptionKeyPair(
                ecdh_pub_path,
                ecdh_priv_path,
                global_passphrase_for_pem_cb
            );
            if (ecc_success) {
                std::cout << "ECC keys generated successfully: " << ecdh_pub_path << " and " << ecdh_priv_path << std::endl;
            } else {
                std::cerr << "Error: ECC encryption key generation failed." << std::endl; return_code = 1;
            }
        } else {
            std::cout << "Generating encryption key pair for mode '" << options["mode"] << "'..." << std::endl;
            bool success = crypto_handler->generateEncryptionKeyPair(
                crypto_handler->getEncryptionPublicKeyPath(),
                crypto_handler->getEncryptionPrivateKeyPath(),
                global_passphrase_for_pem_cb
            );
            if (success) {
                std::cout << "Encryption keys generated successfully: " 
                          << crypto_handler->getEncryptionPublicKeyPath() << " and "
                          << crypto_handler->getEncryptionPrivateKeyPath() << std::endl;
            } else {
                std::cerr << "Error: Encryption key generation failed." << std::endl; return_code = 1;
            }
        }
    } else if (flags["gen_sign_key"]) {
         if (options["mode"] == "hybrid") {
            std::cerr << "Error: Key generation for signing is not applicable in 'hybrid' mode. Choose 'ecc' or 'pqc'." << std::endl;
            return_code = 1;
        } else {
            std::cout << "Generating signing key pair for mode '" << options["mode"] << "'..." << std::endl;
            bool success = crypto_handler->generateSigningKeyPair(
                crypto_handler->getSigningPublicKeyPath(),
                crypto_handler->getSigningPrivateKeyPath(),
                global_passphrase_for_pem_cb
            );
            if (success) {
                std::cout << "Signing keys generated successfully." << std::endl;
            } else {
                std::cerr << "Error: Signing key generation failed." << std::endl; return_code = 1;
            }
        }
    } else if (flags["encrypt"]) {
        if (options["mode"] == "hybrid") {
            if (!options.count("recipient-mlkem-pubkey") || !options.count("recipient-ecdh-pubkey") || !options.count("output-file") || non_option_args.size() != 1) {
                 std::cerr << "Error: Hybrid encryption mode requires --recipient-mlkem-pubkey, --recipient-ecdh-pubkey, -o, and an input file." << std::endl;
                 display_usage(); return_code = 1;
            } else {
                crypto_handler->encryptFileHybrid(io_context, non_option_args[0], options["output-file"], options["recipient-mlkem-pubkey"], options["recipient-ecdh-pubkey"],
                     [&return_code](std::error_code ec) { if (ec) {std::cerr << "Error: Hybrid encryption failed: " << ec.message() << std::endl; return_code = 1; }});
                io_context.run();
            }
        } else {
            if (!options.count("recipient-pubkey") || !options.count("output-file") || non_option_args.size() != 1) {
                std::cerr << "Error: Encryption mode requires --recipient-pubkey, -o, and exactly one input file." << std::endl;
                display_usage(); return_code = 1;
            } else {
                crypto_handler->encryptFile(io_context, non_option_args[0], options["output-file"], options["recipient-pubkey"],
                    [&return_code](std::error_code ec) { if (ec) {std::cerr << "Error: Encryption failed: " << ec.message() << std::endl; return_code = 1; }});
                io_context.run();
            }
        }
    } else if (flags["decrypt"]) {
        if (options["mode"] == "hybrid") {
            if (!options.count("recipient-mlkem-privkey") || !options.count("recipient-ecdh-privkey") || !options.count("output-file") || non_option_args.size() != 1) {
                std::cerr << "Error: Hybrid decryption mode requires --recipient-mlkem-privkey, --recipient-ecdh-privkey, -o, and an input file." << std::endl;
                display_usage(); return_code = 1;
            } else {
                crypto_handler->decryptFileHybrid(io_context, non_option_args[0], options["output-file"], options["recipient-mlkem-privkey"], options["recipient-ecdh-privkey"],
                    [&return_code](std::error_code ec) { if (ec) {std::cerr << "Error: Hybrid decryption failed: " << ec.message() << std::endl; return_code = 1;}});
                io_context.run();
            }
        } else {
            if (!options.count("user-privkey") || !options.count("output-file") || non_option_args.size() != 1) {
                std::cerr << "Error: Decryption mode requires --user-privkey, -o, and exactly one input file." << std::endl;
                display_usage(); return_code = 1;
            } else {
                crypto_handler->decryptFile(io_context, non_option_args[0], options["output-file"], options["user-privkey"], "",
                    [&return_code](std::error_code ec) { if (ec) {std::cerr << "Error: Decryption failed: " << ec.message() << std::endl; return_code = 1;}});
                io_context.run();
            }
        }
    } else if (flags["sign"]) {
        if (options["mode"] == "hybrid") {
            std::cerr << "Error: Signing is not applicable in 'hybrid' mode. Choose 'ecc' or 'pqc'." << std::endl; return_code = 1;
        } else if (!options.count("signing-privkey") || !options.count("signature-file") || non_option_args.size() != 1) {
            std::cerr << "Error: Signing mode requires --signing-privkey, --signature, and exactly one input file." << std::endl;
            display_usage(); return_code = 1;
        } else {
            crypto_handler->signFile(io_context, non_option_args[0], options["signature-file"], options["signing-privkey"], options["digest-algo"],
                [&return_code](std::error_code ec) {
                    if (ec) {
                        std::cerr << "\nError: Signing failed: " << ec.message() << std::endl;
                        return_code = 1;
                    } else {
                         std::cout << "\nFile signed successfully." << std::endl;
                    }
                });
            io_context.run();
        }
    } else if (flags["verify"]) {
        if (options["mode"] == "hybrid") {
            std::cerr << "Error: Verification is not applicable in 'hybrid' mode. Choose 'ecc' or 'pqc'." << std::endl; return_code = 1;
        } else if (!options.count("signing-pubkey") || !options.count("signature-file") || non_option_args.size() != 1) {
            std::cerr << "Error: Verification requires --signing-pubkey, --signature, and one input file." << std::endl;
            display_usage(); return_code = 1;
        } else {
            crypto_handler->verifySignature(io_context, non_option_args[0], options["signature-file"], options["signing-pubkey"],
                [&return_code](std::error_code ec, bool success) {
                    if (ec) {
                        std::cerr << "\nError: An error occurred during verification: " << ec.message() << std::endl;
                        return_code = 1;
                    } else if (success) {
                        std::cout << "\nSignature verified successfully." << std::endl;
                    } else {
                        std::cerr << "\nError: Signature verification failed. The signature does not match." << std::endl;
                        return_code = 1;
                    }
                });
            io_context.run();
        }
    } else {
        if (argc > 1 || !non_option_args.empty()) {
             std::cerr << "Error: No valid operation mode specified or missing arguments." << std::endl;
             display_usage();
             return_code = 1;
        } else {
            display_usage();
        }
    }

    if (default_prov) {
        OSSL_PROVIDER_unload(default_prov);
        std::cout << "OpenSSL provider unloaded." << std::endl;
    }

    return return_code;
}
