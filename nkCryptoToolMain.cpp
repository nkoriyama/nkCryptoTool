// nkCryptoToolMain.cpp

// --- Required Environment ---
// - C++11 compiler (for std::stoi, nullptr, std::vector, etc.)
// - OpenSSL library and headers (e.g., libssl-dev on Debian/Ubuntu, or
// pre-built for Windows) - Requires OpenSSL 1.1.0 or later for
// EVP_PKEY_derive_init/EVP_KDF, AES-GCM, and ECDSA Note: OSSL_PARAM_construct_*
// functions are used for broader compatibility
// - On Windows: MinGW or Cygwin environment recommended for getopt_long.
// MSVC users will need a getopt implementation or replacement.

// --- Compilation Note ---
// This code is written in C++ and requires a C++ compiler (like g++) to compile
// correctly. Save the file with a .cpp, .cc, or .cxx extension (e.g.,
// nkencdec_ECC.cpp) and compile using a C++ compiler command (e.g., g++
// nkencdec_ECC.cpp -o nkencdec_ECC -lssl -lcrypto). If using MinGW on Windows,
// including applink.c might be necessary for linking OpenSSL. Ensure your
// OpenSSL installation is correct and include/library paths are specified in
// the compile command. If you encounter errors related to EVP_EncryptCtl_ex or
// similar OpenSSL functions not being declared, please verify your OpenSSL
// version (1.1.0 or later is needed for GCM and ECDSA) and that include/library
// paths are correct. If you encounter unusual errors like "wrong type argument
// to bit-complement" on pointer initialization, this is likely an
// environment-specific issue with your setup or compiler version.
// For using getopt_long on Windows with MSVC, you might need to add a
// compatible implementation (e.g., from https://github.com/skyrzl/getopt).

#include <iostream>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <filesystem> // For std::filesystem::path

// For getopt_long
#ifdef _WIN32
#include "getopt_long.h" // Assuming you have getopt_long.h for Windows if not using MinGW/Cygwin
#include <conio.h>       // For _getch on Windows
#else
#include <getopt.h> // Standard for Linux/macOS
#include <termios.h> // For tcsetattr, tcgetattr (Linux/macOS)
#include <unistd.h>  // For STDIN_FILENO (Linux/macOS)
#endif

// Include necessary headers for cryptographic operations
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp" // For ECC specific operations
#include "nkCryptoToolPQC.hpp" // For PQC specific operations
#include <openssl/provider.h> // Required for OSSL_PROVIDER_load
#include <openssl/err.h> // Required for ERR_get_error, ERR_error_string_n

// --- IMPORTANT: Global variable and callback definition ---
// These should be defined ONLY ONCE in the entire project.
// If nkCryptoToolECC.cpp or nkCryptoToolPQC.cpp also define these,
// you MUST remove their definitions from those files.
// Instead, declare them as 'extern' in a common header (e.g., nkCryptoToolBase.hpp)
// if they need to be accessed from other .cpp files.

// Global variable for PEM passphrase callback
std::string global_passphrase_for_pem_cb;

// Callback function for PEM passphrase
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    // rwflag: 0 for reading, 1 for writing (not used here)
    // userdata: custom data, not used here
    if (global_passphrase_for_pem_cb.empty()) {
        std::cerr << "Error: Passphrase not set for PEM operation." << std::endl;
        return 0;
    }
    size_t len = global_passphrase_for_pem_cb.copy(buf, size - 1);
    buf[len] = '\0';
    return static_cast<int>(len);
}

// --- IMPORTANT: display_usage() function definition ---
// This function should be defined ONLY ONCE in the entire project.
// If nkCryptoToolECC.cpp or nkCryptoToolPQC.cpp also define this,
// you MUST remove its definition from those files.
// It's generally a utility for main, so keeping it here is fine.
void display_usage() {
    std::cout << "Usage: nkCryptoTool.exe --mode <mode> [options] [arguments]\n";
    std::cout << "Modes:\n";
    std::cout << "  ecc       : Use ECC (Elliptic Curve Cryptography)\n";
    std::cout << "  pqc       : Use PQC (ML_KEM/ML_DSA Cryptography)\n";
    std::cout << "  hybrid    : Use Hybrid (ML_KEM + ECDH Cryptography)\n";
    std::cout << "\n";
    std::cout << "Options for Key Generation:\n";
    std::cout << "  --gen-enc-key       : Generate ECC/KEM encryption key pair\n";
    std::cout << "  --gen-sign-key      : Generate ECC/DSA signing key pair\n";
    std::cout << "  -p, --passphrase <pass> : Passphrase for private key encryption (optional, will prompt if not provided)\n";
    std::cout << "  --key-dir <dir>     : Specify base directory for keys (default: 'keys')\n";
    std::cout << "\n";
    std::cout << "Options for Encryption (PQC/Hybrid Mode):\n";
    std::cout << "  --encrypt           : Encrypt a file\n";
    std::cout << "  -o, --output <file> : Output file path (for encryption/decryption)\n";
    std::cout << "  --recipient-mlkem-pubkey <file> : Recipient's ML-KEM public key file (for hybrid encryption)\n";
    std::cout << "  --recipient-ecdh-pubkey <file>  : Recipient's ECDH public key file (for hybrid encryption)\n";
    std::cout << "  --recipient-pubkey <file>       : Recipient's public key file (for PQC encryption)\n";
    std::cout << "  <input_file>        : Input file to encrypt\n";
    std::cout << "\n";
    std::cout << "Options for Decryption (PQC/Hybrid Mode):\n";
    std::cout << "  --decrypt           : Decrypt a file\n";
    std::cout << "  -o, --output <file> : Output file path (for encryption/decryption)\n";
    std::cout << "  --recipient-mlkem-privkey <file> : Recipient's ML-KEM private key file (for hybrid decryption)\n";
    std::cout << "  --recipient-ecdh-privkey <file>  : Recipient's ECDH private key file (for hybrid decryption)\n";
    std::cout << "  --user-privkey <file>            : Your private key file (for PQC decryption)\n";
    std::cout << "  --sender-pubkey <file>           : Sender's public key file (for PQC decryption - for key derivation, not signature)\n";
    std::cout << "  <input_file>        : Input file to decrypt\n";
    std::cout << "\n";
    std::cout << "Options for Signing:\n";
    std::cout << "  --sign              : Sign a file\n";
    std::cout << "  --signature <file>  : Output signature file path\n";
    std::cout << "  --signing-privkey <file> : Your signing private key file\n";
    std::cout << "  --digest-algo <algo> : Digest algorithm (e.g., sha256, default: sha256)\n";
    std::cout << "  <input_file>        : Input file to sign\n";
    std::cout << "\n";
    std::cout << "Options for Verification:\n";
    std::cout << "  --verify            : Verify a file's signature\n";
    std::cout << "  --signature <file>  : Input signature file path\n";
    std::cout << "  --signing-pubkey <file> : Signer's public key file\n";
    std::cout << "  <input_file>        : Input file to verify\n";
    std::cout << "\n";
}

// --- IMPORTANT: main() function definition ---
// The main function must be defined ONLY ONCE in the entire project.
// If nkCryptoToolECC.cpp or nkCryptoToolPQC.cpp also contain a main() function,
// you MUST remove them from those files.
int main(int argc, char *argv[]) {
    // OpenSSL Initialization (mostly handled internally by OpenSSL 3.0+)
    // ERR_load_crypto_strings(); // Deprecated in OpenSSL 3.0
    // OpenSSL_add_all_algorithms(); // Deprecated in OpenSSL 3.0

    // Load the default provider for PQC algorithms
    OSSL_PROVIDER* default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        std::cerr << "Error: Failed to load default OpenSSL provider. PQC algorithms may not be available." << std::endl;
        unsigned long err_code;
        while ((err_code = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            std::cerr << "OpenSSL Provider Error: " << err_buf << std::endl;
        }
    }


    std::string mode;
    std::string passphrase_str;
    std::string key_dir = "keys";
    std::string input_file, output_file, signature_file;
    std::string recipient_public_key_file; // For PQC non-hybrid
    std::string user_private_key_file;     // For PQC non-hybrid
    std::string sender_public_key_file;    // For PQC non-hybrid
    std::string recipient_mlkem_pubkey_file; // For Hybrid encryption
    std::string recipient_ecdh_pubkey_file;  // For Hybrid encryption
    std::string recipient_mlkem_privkey_file; // For Hybrid decryption
    std::string recipient_ecdh_privkey_file;  // For Hybrid decryption
    std::string signing_private_key_file, signing_public_key_file;
    std::string digest_algo = "sha256"; // Default digest algorithm

    bool gen_enc_key_mode = false;
    bool gen_sign_key_mode = false;
    bool encrypt_mode = false;
    bool decrypt_mode = false;
    bool sign_mode = false;
    bool verify_mode = false;

    // Command-line options
    static struct option long_options[] = {
        {"mode", required_argument, nullptr, 'm'},
        {"gen-enc-key", no_argument, nullptr, 0},
        {"gen-sign-key", no_argument, nullptr, 0},
        {"passphrase", required_argument, nullptr, 'p'},
        {"key-dir", required_argument, nullptr, 0},
        {"encrypt", no_argument, nullptr, 0},
        {"decrypt", no_argument, nullptr, 0},
        {"sign", no_argument, nullptr, 0},
        {"verify", no_argument, nullptr, 0},
        {"output", required_argument, nullptr, 'o'},
        {"recipient-pubkey", required_argument, nullptr, 0}, // For PQC non-hybrid
        {"user-privkey", required_argument, nullptr, 0},     // For PQC non-hybrid
        {"sender-pubkey", required_argument, nullptr, 0},    // For PQC non-hybrid
        {"recipient-mlkem-pubkey", required_argument, nullptr, 0}, // For Hybrid encryption
        {"recipient-ecdh-pubkey", required_argument, nullptr, 0},  // For Hybrid encryption
        {"recipient-mlkem-privkey", required_argument, nullptr, 0}, // For Hybrid decryption
        {"recipient-ecdh-privkey", required_argument, nullptr, 0},  // For Hybrid decryption
        {"signature", required_argument, nullptr, 0},
        {"signing-privkey", required_argument, nullptr, 0},
        {"signing-pubkey", required_argument, nullptr, 0},
        {"digest-algo", required_argument, nullptr, 0},
        {0, 0, 0, 0} // End of options
    };

    int opt;
    int long_index = 0;
    std::vector<std::string> non_option_args;

    // Parse command line arguments
    while ((opt = getopt_long(argc, argv, "m:o:p:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'm':
                mode = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'p':
                passphrase_str = optarg;
                break;
            case 0: // Long options without a short equivalent
                if (std::string(long_options[long_index].name) == "gen-enc-key") {
                    gen_enc_key_mode = true;
                } else if (std::string(long_options[long_index].name) == "gen-sign-key") {
                    gen_sign_key_mode = true;
                } else if (std::string(long_options[long_index].name) == "key-dir") {
                    key_dir = optarg;
                } else if (std::string(long_options[long_index].name) == "encrypt") {
                    encrypt_mode = true;
                } else if (std::string(long_options[long_index].name) == "decrypt") {
                    decrypt_mode = true;
                } else if (std::string(long_options[long_index].name) == "sign") {
                    sign_mode = true;
                } else if (std::string(long_options[long_index].name) == "verify") {
                    verify_mode = true;
                } else if (std::string(long_options[long_index].name) == "recipient-pubkey") {
                    recipient_public_key_file = optarg;
                } else if (std::string(long_options[long_index].name) == "user-privkey") {
                    user_private_key_file = optarg;
                } else if (std::string(long_options[long_index].name) == "sender-pubkey") {
                    sender_public_key_file = optarg;
                } else if (std::string(long_options[long_index].name) == "recipient-mlkem-pubkey") {
                    recipient_mlkem_pubkey_file = optarg;
                } else if (std::string(long_options[long_index].name) == "recipient-ecdh-pubkey") {
                    recipient_ecdh_pubkey_file = optarg;
                } else if (std::string(long_options[long_index].name) == "recipient-mlkem-privkey") {
                    recipient_mlkem_privkey_file = optarg;
                } else if (std::string(long_options[long_index].name) == "recipient-ecdh-privkey") {
                    recipient_ecdh_privkey_file = optarg;
                } else if (std::string(long_options[long_index].name) == "signature") {
                    signature_file = optarg;
                } else if (std::string(long_options[long_index].name) == "signing-privkey") {
                    signing_private_key_file = optarg;
                } else if (std::string(long_options[long_index].name) == "signing-pubkey") {
                    signing_public_key_file = optarg;
                } else if (std::string(long_options[long_index].name) == "digest-algo") {
                    digest_algo = optarg;
                }
                break;
            default:
                display_usage();
                // Unload provider before exiting
                if (default_prov) {
                    OSSL_PROVIDER_unload(default_prov);
                }
                return 1;
        }
    }

    // Collect non-option arguments (e.g., input file paths)
    while (optind < argc) {
        non_option_args.push_back(argv[optind++]);
    }

    // Determine cryptographic handler based on mode
    std::unique_ptr<nkCryptoToolBase> crypto_handler;
    if (mode == "ecc") {
        crypto_handler = std::make_unique<nkCryptoToolECC>();
    } else if (mode == "pqc" || mode == "hybrid") { // PQC and Hybrid modes use nkCryptoToolPQC
        crypto_handler = std::make_unique<nkCryptoToolPQC>();
    } else {
        std::cerr << "Error: Invalid or unsupported mode specified. Currently 'ecc', 'pqc', and 'hybrid' are supported." << std::endl;
        display_usage();
        // Unload provider before exiting
        if (default_prov) {
            OSSL_PROVIDER_unload(default_prov);
        }
        return 1;
    }

    // Set key base directory if specified
    if (!key_dir.empty()) {
        nkCryptoToolBase::setKeyBaseDirectory(key_dir);
    }

    // Process commands based on mode
    if (gen_enc_key_mode || gen_sign_key_mode) {
        if (passphrase_str.empty()) {
            std::cout << "Enter Passphrase (for new key): ";
            std::cout.flush(); // Ensure prompt is displayed immediately

            // Platform-specific secure passphrase input
#if defined(_WIN32) || defined(__WIN32__) || defined(__MINGW32__)
            char ch;
            while ((ch = _getch()) != '\r' && ch != '\n') {
                if (ch == '\b') { // Backspace
                    if (!passphrase_str.empty()) {
                        passphrase_str.pop_back();
                        std::cout << "\b \b";
                    }
                } else {
                    passphrase_str.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl; // Newline after input
#else
            struct termios oldt, newt;
            tcgetattr(STDIN_FILENO, &oldt); // Get current terminal settings
            newt = oldt;
            newt.c_lflag &= ~(ECHO | ICANON); // Disable echo and canonical mode
            tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Apply new settings

            std::getline(std::cin, passphrase_str); // Read passphrase

            tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Restore original terminal settings
            std::cout << std::endl; // Newline after input
#endif
        }
        global_passphrase_for_pem_cb = passphrase_str; // Set global passphrase for callback

        bool success = false;
        if (gen_enc_key_mode) {
            if (mode == "hybrid") {
                // Generate ML-KEM keys for hybrid mode
                nkCryptoToolPQC pqc_generator; // Use a temporary object for PQC
                success = pqc_generator.generateEncryptionKeyPair(
                    std::filesystem::path(key_dir) / "public_enc_hybrid_mlkem.key",
                    std::filesystem::path(key_dir) / "private_enc_hybrid_mlkem.key",
                    passphrase_str
                );
                if (success) {
                    std::cout << "ML-KEM encryption key pair for hybrid mode generated successfully." << std::endl;
                } else {
                    std::cerr << "Error: Failed to generate ML-KEM encryption key pair for hybrid mode." << std::endl;
                }

                // Generate ECC keys for hybrid mode
                nkCryptoToolECC ecc_generator; // Use a temporary object for ECC
                bool ecc_success = ecc_generator.generateEncryptionKeyPair(
                    std::filesystem::path(key_dir) / "public_enc_hybrid_ecdh.key",
                    std::filesystem::path(key_dir) / "private_enc_hybrid_ecdh.key",
                    passphrase_str
                );
                if (ecc_success) {
                    std::cout << "ECDH encryption key pair for hybrid mode generated successfully." << std::endl;
                } else {
                    std::cerr << "Error: Failed to generate ECDH encryption key pair for hybrid mode." << std::endl;
                    success = false; // If ECC generation fails, overall hybrid generation fails
                }
                success = success && ecc_success; // Both must succeed
            } else { // Existing PQC or ECC specific key generation
                success = crypto_handler->generateEncryptionKeyPair(
                    crypto_handler->getEncryptionPublicKeyPath(),
                    crypto_handler->getEncryptionPrivateKeyPath(),
                    passphrase_str);
                if (success) {
                    std::cout << "Encryption key pair generated successfully." << std::endl;
                } else {
                    std::cerr << "Error: Failed to generate encryption key pair." << std::endl;
                }
            }
        } else if (gen_sign_key_mode) {
            // Signing key generation remains mode-specific (ECC or PQC)
            success = crypto_handler->generateSigningKeyPair(
                crypto_handler->getSigningPublicKeyPath(),
                crypto_handler->getSigningPrivateKeyPath(),
                passphrase_str);
            if (success) {
                std::cout << "Signing key pair generated successfully." << std::endl;
            } else {
                std::cerr << "Error: Failed to generate signing key pair." << std::endl;
            }
        }
        if (!success) {
            // Unload provider before exiting
            if (default_prov) {
                OSSL_PROVIDER_unload(default_prov);
            }
            return 1;
        }
    } else if (encrypt_mode) { // Handle encryption
        if (output_file.empty() || non_option_args.size() != 1) {
            std::cerr << "Error: Encryption mode requires -o (output file) and exactly one input file." << std::endl;
            display_usage();
            if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
            return 1;
        }
        input_file = non_option_args[0];

        global_passphrase_for_pem_cb = ""; // Ensure passphrase is empty for encryption

        bool encrypt_success = false;
        if (mode == "pqc") {
            if (recipient_public_key_file.empty()) {
                std::cerr << "Error: PQC encryption mode requires --recipient-pubkey." << std::endl;
                display_usage();
                if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
                return 1;
            }
            encrypt_success = crypto_handler->encryptFile(input_file, output_file, recipient_public_key_file);
        } else if (mode == "hybrid") {
            if (recipient_mlkem_pubkey_file.empty() || recipient_ecdh_pubkey_file.empty()) {
                std::cerr << "Error: Hybrid encryption mode requires --recipient-mlkem-pubkey and --recipient-ecdh-pubkey." << std::endl;
                display_usage();
                if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
                return 1;
            }
            // Directly call encryptFileHybrid polymorphically
            encrypt_success = crypto_handler->encryptFileHybrid(input_file, output_file,
                                                                recipient_mlkem_pubkey_file,
                                                                recipient_ecdh_pubkey_file);
        } else {
            std::cerr << "Error: Encryption not supported for the selected mode or missing required keys." << std::endl;
            display_usage();
            if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
            return 1;
        }

        if (encrypt_success) {
            std::cout << "File encrypted successfully to " << output_file << std::endl;
        } else {
            std::cerr << "Error: File encryption failed. Please check the program's output for OpenSSL errors." << std::endl;
            if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
            return 1;
        }
    } else if (decrypt_mode) { // Handle decryption
        if (output_file.empty() || non_option_args.size() != 1) {
            std::cerr << "Error: Decryption mode requires -o (output file) and exactly one input file." << std::endl;
            display_usage();
            if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
            return 1;
        }
        input_file = non_option_args[0];

        // Decryption requires the user's private key passphrase
        // Prompt for passphrase if not provided via --passphrase
        if (passphrase_str.empty()) {
            std::cout << "Enter Passphrase for your private key: ";
            std::cout.flush(); // Ensure prompt is displayed immediately
#if defined(_WIN32) || defined(__WIN32__) || defined(__MINGW32__)
            char ch;
            while ((ch = _getch()) != '\r' && ch != '\n') {
                if (ch == '\b') {
                    if (!passphrase_str.empty()) {
                        passphrase_str.pop_back();
                        std::cout << "\b \b";
                    }
                } else {
                    passphrase_str.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl;
#else
            struct termios oldt, newt;
            tcgetattr(STDIN_FILENO, &oldt);
            newt = oldt;
            newt.c_lflag &= ~(ECHO | ICANON);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);

            std::getline(std::cin, passphrase_str);

            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            std::cout << std::endl;
#endif
        }
        global_passphrase_for_pem_cb = passphrase_str; // Set global passphrase for callback for private key loading

        bool decrypt_success = false;
        if (mode == "pqc") {
            if (user_private_key_file.empty() || sender_public_key_file.empty()) {
                std::cerr << "Error: PQC decryption mode requires --user-privkey and --sender-pubkey." << std::endl;
                display_usage();
                if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
                return 1;
            }
            decrypt_success = crypto_handler->decryptFile(input_file, output_file,
                                                          user_private_key_file, sender_public_key_file);
        } else if (mode == "hybrid") {
            if (recipient_mlkem_privkey_file.empty() || recipient_ecdh_privkey_file.empty()) {
                std::cerr << "Error: Hybrid decryption mode requires --recipient-mlkem-privkey and --recipient-ecdh-privkey." << std::endl;
                display_usage();
                if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
                return 1;
            }
            // Directly call decryptFileHybrid polymorphically
            decrypt_success = crypto_handler->decryptFileHybrid(input_file, output_file,
                                                                recipient_mlkem_privkey_file,
                                                                recipient_ecdh_privkey_file);
        } else {
            std::cerr << "Error: Decryption not supported for the selected mode or missing required keys." << std::endl;
            display_usage();
            if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
            return 1;
        }
        
        if (decrypt_success) {
            std::cout << "File decrypted successfully to " << output_file << std::endl;
        } else {
            std::cerr << "Error: File decryption failed. Please check the program's output for OpenSSL errors." << std::endl;
            if (default_prov) { OSSL_PROVIDER_unload(default_prov); }
            return 1;
        }
    } else if (sign_mode) { // Handle signing
        // Requires signing private key (--signing-privkey), signature file
        // (--signature), and exactly one input file
        if (signing_private_key_file.empty() || signature_file.empty() ||
            non_option_args.size() != 1) {
            std::cerr << "Error: Signing mode requires --signing-privkey, --signature, and exactly one input file." << std::endl;
            display_usage();
            // Unload provider before exiting
            if (default_prov) {
                OSSL_PROVIDER_unload(default_prov);
            }
            return 1;
        }
        input_file = non_option_args[0];

        // Signing requires the user's private key passphrase
        // Prompt for passphrase if not provided via --passphrase
        if (passphrase_str.empty()) {
            std::cout << "Enter Passphrase for your signing private key: ";
            std::cout.flush();
#if defined(_WIN32) || defined(__WIN32__) || defined(__MINGW32__)
            char ch;
            while ((ch = _getch()) != '\r' && ch != '\n') {
                if (ch == '\b') {
                    if (!passphrase_str.empty()) {
                        passphrase_str.pop_back();
                        std::cout << "\b \b";
                    }
                } else {
                    passphrase_str.push_back(ch);
                    std::cout << "*";
                }
            }
            std::cout << std::endl;
#else
            struct termios oldt, newt;
            tcgetattr(STDIN_FILENO, &oldt);
            newt = oldt;
            newt.c_lflag &= ~(ECHO | ICANON);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);

            std::getline(std::cin, passphrase_str);

            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            std::cout << std::endl;
#endif
        }
        global_passphrase_for_pem_cb = passphrase_str; // Set global passphrase for callback for private key loading

        if (!crypto_handler->signFile(input_file, signature_file,
                                      signing_private_key_file, digest_algo)) {
            std::cerr << "Error: File signing failed." << std::endl;
            // Unload provider before exiting
            if (default_prov) {
                OSSL_PROVIDER_unload(default_prov);
            }
            return 1;
        }
        std::cout << "File signed successfully. Signature saved to " << signature_file << std::endl;
    } else if (verify_mode) { // Handle verification
        // Requires signing public key (--signing-pubkey), signature file
        // (--signature), and exactly one input file (original file)
        if (signing_public_key_file.empty() || signature_file.empty() ||
            non_option_args.size() != 1) {
            std::cerr << "Error: Verification mode requires --signing-pubkey, "
                      << "--signature, and exactly one input file (original file)." << std::endl;
            display_usage();
            // Unload provider before exiting
            if (default_prov) {
                OSSL_PROVIDER_unload(default_prov);
            }
            return 1;
        }
        input_file = non_option_args[0]; // The single non-option argument is the original file

        // Verification does not require the user's private key passphrase
        global_passphrase_for_pem_cb = ""; // Ensure passphrase is empty for verification

        if (!crypto_handler->verifySignature(input_file, signature_file,
                                             signing_public_key_file)) {
            std::cerr << "Verification failed." << std::endl;
            // verify_signature function already prints specific failure message
            // Unload provider before exiting
            if (default_prov) {
                OSSL_PROVIDER_unload(default_prov);
            }
            return 1;
        }
        std::cout << "Signature verified successfully." << std::endl;
    } else {
        std::cerr << "Error: No valid mode specified." << std::endl;
        display_usage();
        // Unload provider before exiting
        if (default_prov) {
            OSSL_PROVIDER_unload(default_prov);
        }
        return 1;
    }

    // Clean up OpenSSL (for OpenSSL 3.0+, these are often no-ops)
    // EVP_cleanup(); // Deprecated in OpenSSL 3.0
    // ERR_free_strings(); // Deprecated in OpenSSL 3.0
    // No direct replacements for these global cleanups in OpenSSL 3.0.
    // Resource management is now mostly handled via unique_ptr or automatic
    // freeing on context destruction.

    // Unload the OQS provider
    if (default_prov) {
        OSSL_PROVIDER_unload(default_prov);
    }

    return 0; // Success
}
