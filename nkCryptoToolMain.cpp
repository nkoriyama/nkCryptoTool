// nkCryptoToolMain.cpp (同期版)

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
// nkCryptoTool.cpp) and compile using a C++ compiler command (e.g., g++
// nkCryptoTool.cpp -o nkCryptoTool -lssl -lcrypto).
// Ensure your OpenSSL installation is correct and include/library paths are specified in
// the compile command.

#include <iostream>
#include <string>
#include <vector>
#include <memory> // For std::unique_ptr
#include <filesystem> // For std::filesystem::path
#include <mutex> // For std::mutex - still needed for global_passphrase_for_pem_cb access

// For getopt_long
#ifdef _WIN32
#include "getopt_long.h" // Assuming you have getopt_long.h for Windows if not using MinGW/Cygwin
#include <conio.h>       // For _getch on Windows
#else
#include <getopt.h> // Standard for Linux/macOS
#include <termios.h> // For tcsetattr, tcgetattr (Linux/macOS)
#include <unistd.  h>  // For STDIN_FILENO (Linux/macOS)
#endif

// Include necessary headers for cryptographic operations
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp" // For ECC specific operations
#include "nkCryptoToolPQC.hpp" // For PQC specific operations
#include <openssl/provider.h> // Required for OSSL_PROVIDER_load
#include <openssl/err.h> // Required for ERR_get_error, ERR_error_string_n

// --- IMPORTANT: Global variable and callback definition ---
// Global variable for PEM passphrase callback
std::string global_passphrase_for_pem_cb;
// Mutex to protect global_passphrase_for_pem_cb
std::mutex passphrase_mutex;


// Callback function for PEM passphrase
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    std::lock_guard<std::mutex> lock(passphrase_mutex); // Protect access to global_passphrase_for_pem_cb
    if (global_passphrase_for_pem_cb.empty()) {
        std::cerr << "Error: Passphrase not set for PEM operation (callback)." << std::endl;
        return 0; // Indicate failure or empty passphrase
    }
    size_t len = global_passphrase_for_pem_cb.copy(buf, size - 1);
    buf[len] = '\0';
    return static_cast<int>(len);
}

// --- display_usage() function definition ---
void display_usage() {
    // (Usage information remains the same as the original)
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
    std::cout << "Note: Operations are performed synchronously.\n"; // Updated note
}


// Helper function to securely get passphrase
std::string prompt_for_passphrase(const std::string& prompt_message) {
    std::string passphrase;
    std::cout << prompt_message;
    std::cout.flush(); // Ensure prompt is displayed immediately

#if defined(_WIN32) || defined(__WIN32__) || defined(__MINGW32__)
    char ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == '\b') { // Backspace
            if (!passphrase.empty()) {
                passphrase.pop_back();
                std::cout << "\b \b"; // Erase character on console
            }
        } else {
            passphrase.push_back(ch);
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

    // Read passphrase - std::getline might not be ideal with raw terminal mode.
    // A char-by-char read loop is more robust here.
    char c;
    while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n' && c != '\r') {
        if (c == 127 || c == 8) { // Handle backspace (ASCII DEL or BS)
             if (!passphrase.empty()) {
                passphrase.pop_back();
                // Optionally, provide visual feedback for backspace if desired:
                // write(STDOUT_FILENO, "\b \b", 3);
            }
        } else {
            passphrase.push_back(c);
            // Optionally, provide visual feedback for character typed:
            // write(STDOUT_FILENO, "*", 1);
        }
    }


    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Restore original terminal settings
    std::cout << std::endl; // Newline after input
#endif
    return passphrase;
}


int main(int argc, char *argv[]) {
    OSSL_PROVIDER* default_prov = OSSL_PROVIDER_load(NULL, "default");
    if (!default_prov) {
        std::cerr << "Error: Failed to load default OpenSSL provider. PQC algorithms may not be available." << std::endl;
        unsigned long err_code;
        while ((err_code = ERR_get_error()) != 0) {
            char err_buf[256];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            std::cerr << "OpenSSL Provider Error: " << err_buf << std::endl;
        }
        return 1; // Early exit if provider fails, as crypto ops won't work
    }

    // Asio 関連のセットアップをすべて削除
    // asio::io_context io_ctx;
    // auto work_guard = asio::make_work_guard(io_ctx);
    // unsigned int num_threads = std::thread::hardware_concurrency();
    // if (num_threads == 0) { num_threads = 2; }
    // std::vector<std::thread> threads;
    // for (unsigned int i = 0; i < num_threads; ++i) { threads.emplace_back([&io_ctx]() { io_ctx.run(); }); }
    // std::atomic<int> tasks_in_flight(0);
    // std::mutex tasks_mutex;
    // std::condition_variable cv_all_tasks_done;

    std::string mode_str;
    std::string passphrase_arg_str; // Passphrase provided as command line argument
    std::string key_dir = "keys";
    std::string input_file, output_file, signature_file;
    std::string recipient_public_key_file; 
    std::string user_private_key_file;     
    std::string sender_public_key_file;    
    std::string recipient_mlkem_pubkey_file; 
    std::string recipient_ecdh_pubkey_file;  
    std::string recipient_mlkem_privkey_file; 
    std::string recipient_ecdh_privkey_file;  
    std::string signing_private_key_file, signing_public_key_file;
    std::string digest_algo = "sha256"; 

    bool gen_enc_key_mode = false;
    bool gen_sign_key_mode = false;
    bool encrypt_mode = false;
    bool decrypt_mode = false;
    bool sign_mode = false;
    bool verify_mode = false;

    static struct option long_options[] = {
        {"mode", required_argument, nullptr, 'm'},
        {"gen-enc-key", no_argument, nullptr, 1}, // Use numbers > 255 for long opts without short
        {"gen-sign-key", no_argument, nullptr, 2},
        {"passphrase", required_argument, nullptr, 'p'},
        {"key-dir", required_argument, nullptr, 3},
        {"encrypt", no_argument, nullptr, 4},
        {"decrypt", no_argument, nullptr, 5},
        {"sign", no_argument, nullptr, 6},
        {"verify", no_argument, nullptr, 7},
        {"output", required_argument, nullptr, 'o'},
        {"recipient-pubkey", required_argument, nullptr, 8},
        {"user-privkey", required_argument, nullptr, 9},
        {"sender-pubkey", required_argument, nullptr, 10},
        {"recipient-mlkem-pubkey", required_argument, nullptr, 11},
        {"recipient-ecdh-pubkey", required_argument, nullptr, 12},
        {"recipient-mlkem-privkey", required_argument, nullptr, 13},
        {"recipient-ecdh-privkey", required_argument, nullptr, 14},
        {"signature", required_argument, nullptr, 15},
        {"signing-privkey", required_argument, nullptr, 16},
        {"signing-pubkey", required_argument, nullptr, 17},
        {"digest-algo", required_argument, nullptr, 18},
        {nullptr, 0, nullptr, 0} 
    };

    int opt;
    int long_index = 0;
    std::vector<std::string> non_option_args;

    while ((opt = getopt_long(argc, argv, "m:o:p:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'm': mode_str = optarg; break;
            case 'o': output_file = optarg; break;
            case 'p': passphrase_arg_str = optarg; break;
            case 1: gen_enc_key_mode = true; break;
            case 2: gen_sign_key_mode = true; break;
            case 3: key_dir = optarg; break;
            case 4: encrypt_mode = true; break;
            case 5: decrypt_mode = true; break;
            case 6: sign_mode = true; break;
            case 7: verify_mode = true; break;
            case 8: recipient_public_key_file = optarg; break;
            case 9: user_private_key_file = optarg; break;
            case 10: sender_public_key_file = optarg; break;
            case 11: recipient_mlkem_pubkey_file = optarg; break;
            case 12: recipient_ecdh_pubkey_file = optarg; break;
            case 13: recipient_mlkem_privkey_file = optarg; break;
            case 14: recipient_ecdh_privkey_file = optarg; break;
            case 15: signature_file = optarg; break;
            case 16: signing_private_key_file = optarg; break;
            case 17: signing_public_key_file = optarg; break;
            case 18: digest_algo = optarg; break;
            default:
                display_usage();
                if (default_prov) OSSL_PROVIDER_unload(default_prov);
                return 1;
        }
    }

    while (optind < argc) {
        non_option_args.push_back(argv[optind++]);
    }

    std::unique_ptr<nkCryptoToolBase> crypto_handler; // unique_ptr for local ownership
    if (mode_str == "ecc") {
        crypto_handler = std::make_unique<nkCryptoToolECC>();
    } else if (mode_str == "pqc" || mode_str == "hybrid") {
        crypto_handler = std::make_unique<nkCryptoToolPQC>();
    } else {
        std::cerr << "Error: Invalid or unsupported mode specified. Currently 'ecc', 'pqc', and 'hybrid' are supported." << std::endl;
        display_usage();
        if (default_prov) OSSL_PROVIDER_unload(default_prov);
        return 1;
    }

    if (!key_dir.empty()) {
        nkCryptoToolBase::setKeyBaseDirectory(key_dir);
    }
    
    // --- 同期的なタスク実行ロジック ---
    // 非同期関連の post_task ラムダを削除し、直接同期呼び出しを行う

    if (gen_enc_key_mode || gen_sign_key_mode) {
        std::string effective_passphrase = passphrase_arg_str;
        if (effective_passphrase.empty()) {
            effective_passphrase = prompt_for_passphrase("Enter Passphrase (for new key): ");
        }
        
        // Set global passphrase for the task
        {
           std::lock_guard<std::mutex> lock(passphrase_mutex);
           global_passphrase_for_pem_cb = effective_passphrase;
        }


        if (gen_enc_key_mode) {
            std::cout << "Generating encryption key pair..." << std::endl;
            bool success = false;
            if (mode_str == "hybrid") {
                // ハイブリッドモードの場合、ML-KEMとECDH両方の鍵を生成
                nkCryptoToolPQC pqc_generator; 
                success = pqc_generator.generateEncryptionKeyPair(
                    std::filesystem::path(key_dir) / "public_enc_hybrid_mlkem.key",
                    std::filesystem::path(key_dir) / "private_enc_hybrid_mlkem.key",
                    effective_passphrase 
                );
                if (success) {
                    std::cout << "ML-KEM encryption key pair for hybrid mode generated successfully." << std::endl;
                } else {
                    std::cerr << "Error: Failed to generate ML-KEM encryption key pair for hybrid mode." << std::endl;
                }

                nkCryptoToolECC ecc_generator; 
                bool ecc_success = ecc_generator.generateEncryptionKeyPair(
                    std::filesystem::path(key_dir) / "public_enc_hybrid_ecdh.key",
                    std::filesystem::path(key_dir) / "private_enc_hybrid_ecdh.key",
                    effective_passphrase
                );
                if (ecc_success) {
                    std::cout << "ECDH encryption key pair for hybrid mode generated successfully." << std::endl;
                } else {
                    std::cerr << "Error: Failed to generate ECDH encryption key pair for hybrid mode." << std::endl;
                    success = false; // ML-KEMが成功してもECDHが失敗したら全体を失敗とみなす
                }
                success = success && ecc_success; // 両方成功した場合のみ全体成功
            } else {
                success = crypto_handler->generateEncryptionKeyPair(
                    crypto_handler->getEncryptionPublicKeyPath(),
                    crypto_handler->getEncryptionPrivateKeyPath(),
                    effective_passphrase);
            }
            if (success) {
                std::cout << "Encryption key pair generation completed." << std::endl;
            } else {
                std::cerr << "Error: Failed to generate encryption key pair." << std::endl;
            }
        } else if (gen_sign_key_mode) {
            std::cout << "Generating signing key pair..." << std::endl;
            bool success = crypto_handler->generateSigningKeyPair(
                crypto_handler->getSigningPublicKeyPath(),
                crypto_handler->getSigningPrivateKeyPath(),
                effective_passphrase);
            if (success) {
                std::cout << "Signing key pair generated successfully." << std::endl;
            } else {
                std::cerr << "Error: Failed to generate signing key pair." << std::endl;
            }
        }
    } else if (encrypt_mode) {
        if (output_file.empty() || non_option_args.size() != 1) {
            std::cerr << "Error: Encryption mode requires -o (output file) and exactly one input file." << std::endl;
            display_usage();
        } else {
            input_file = non_option_args[0];
            { // Clear global passphrase for operations that don't need it for key loading (like encryption with public key)
                std::lock_guard<std::mutex> lock(passphrase_mutex);
                global_passphrase_for_pem_cb = "";
            }

            std::cout << "Encrypting file " << input_file << " to " << output_file << "..." << std::endl;
            bool success = false;
            if (mode_str == "pqc") {
                 if (recipient_public_key_file.empty()) {
                    std::cerr << "Error: PQC encryption mode requires --recipient-pubkey." << std::endl;
                    return 1; // Exit program on error
                }
                success = crypto_handler->encryptFile(input_file, output_file, recipient_public_key_file);
            } else if (mode_str == "hybrid") {
                 if (recipient_mlkem_pubkey_file.empty() || recipient_ecdh_pubkey_file.empty()) {
                    std::cerr << "Error: Hybrid encryption mode requires --recipient-mlkem-pubkey and --recipient-ecdh-pubkey." << std::endl;
                    return 1; 
                }
                success = crypto_handler->encryptFileHybrid(input_file, output_file,
                                                            recipient_mlkem_pubkey_file,
                                                            recipient_ecdh_pubkey_file);
            } else if (mode_str == "ecc") { // Assuming ECC encryptFile takes recipient_public_key_file
                 if (recipient_public_key_file.empty()) { // Adjust if ECC uses different param
                    std::cerr << "Error: ECC encryption mode requires --recipient-pubkey (or equivalent)." << std::endl;
                    return 1;
                }
                success = crypto_handler->encryptFile(input_file, output_file, recipient_public_key_file);
            }
            else {
                std::cerr << "Error: Encryption not supported for the selected mode or missing required keys." << std::endl;
            }

            if (success) {
                std::cout << "File encrypted successfully to " << output_file << std::endl;
            } else {
                std::cerr << "Error: File encryption failed." << std::endl;
                return 1; // Exit program on error
            }
        }
    } else if (decrypt_mode) {
         if (output_file.empty() || non_option_args.size() != 1) {
            std::cerr << "Error: Decryption mode requires -o (output file) and exactly one input file." << std::endl;
            display_usage();
        } else {
            input_file = non_option_args[0];
            std::string effective_passphrase = passphrase_arg_str;
            if (effective_passphrase.empty()) {
                 effective_passphrase = prompt_for_passphrase("Enter Passphrase for your private key: ");
            }
            
            std::cout << "Decrypting file " << input_file << " to " << output_file << "..." << std::endl;
            {
                std::lock_guard<std::mutex> lock(passphrase_mutex);
                global_passphrase_for_pem_cb = effective_passphrase;
            }
            bool success = false;
             if (mode_str == "pqc") {
                if (user_private_key_file.empty() || sender_public_key_file.empty()) { 
                    std::cerr << "Error: PQC decryption mode requires --user-privkey. --sender-pubkey might be for other schemes." << std::endl;
                    return 1;
                }
                success = crypto_handler->decryptFile(input_file, output_file,
                                                      user_private_key_file, sender_public_key_file);
            } else if (mode_str == "hybrid") {
                 if (recipient_mlkem_privkey_file.empty() || recipient_ecdh_privkey_file.empty()) {
                    std::cerr << "Error: Hybrid decryption mode requires --recipient-mlkem-privkey and --recipient-ecdh-privkey." << std::endl;
                    return 1;
                }
                success = crypto_handler->decryptFileHybrid(input_file, output_file,
                                                            recipient_mlkem_privkey_file,
                                                            recipient_ecdh_privkey_file);
            } else if (mode_str == "ecc") {
                if (user_private_key_file.empty() || sender_public_key_file.empty()) {
                     std::cerr << "Error: ECC decryption mode requires --user-privkey and --sender-pubkey." << std::endl;
                    return 1;
                }
                success = crypto_handler->decryptFile(input_file, output_file, user_private_key_file, sender_public_key_file);
            }
            else {
                std::cerr << "Error: Decryption not supported for the selected mode or missing required keys." << std::endl;
            }
            if (success) {
                std::cout << "File decrypted successfully to " << output_file << std::endl;
            } else {
                std::cerr << "Error: File decryption failed." << std::endl;
                return 1;
            }
        }
    } else if (sign_mode) {
        if (signing_private_key_file.empty() || signature_file.empty() || non_option_args.size() != 1) {
            std::cerr << "Error: Signing mode requires --signing-privkey, --signature, and exactly one input file." << std::endl;
            display_usage();
        } else {
            input_file = non_option_args[0];
            std::string effective_passphrase = passphrase_arg_str;
            if (effective_passphrase.empty()) {
                 effective_passphrase = prompt_for_passphrase("Enter Passphrase for your signing private key: ");
            }
            std::cout << "Signing file " << input_file << "..." << std::endl;
             {
                std::lock_guard<std::mutex> lock(passphrase_mutex);
                global_passphrase_for_pem_cb = effective_passphrase;
            }
            bool success = crypto_handler->signFile(input_file, signature_file,
                                  signing_private_key_file, digest_algo);
            if (success) {
                std::cout << "File signed successfully. Signature saved to " << signature_file << std::endl;
            } else {
                std::cerr << "Error: File signing failed." << std::endl;
                return 1;
            }
        }
    } else if (verify_mode) {
        if (signing_public_key_file.empty() || signature_file.empty() || non_option_args.size() != 1) {
            std::cerr << "Error: Verification mode requires --signing-pubkey, --signature, and exactly one input file." << std::endl;
            display_usage();
        } else {
            input_file = non_option_args[0];
            {
                std::lock_guard<std::mutex> lock(passphrase_mutex);
                global_passphrase_for_pem_cb = ""; // Verification uses public key, no passphrase needed for key itself
            }
            std::cout << "Verifying signature for file " << input_file << "..." << std::endl;
            bool success = crypto_handler->verifySignature(input_file, signature_file,
                                         signing_public_key_file);
            if (success) {
                std::cout << "Signature verified successfully." << std::endl;
            } else {
                std::cerr << "Error: Verification failed." << std::endl;
                return 1;
            }
        }
    } else {
        if (argc > 1) { // Only show error if some args were given but no valid mode matched
             std::cerr << "Error: No valid operation mode specified or missing arguments." << std::endl;
             display_usage();
             return 1;
        } else { // No arguments, just show usage
            display_usage();
        }
    }

    // クリーンアップ
    if (default_prov) {
        OSSL_PROVIDER_unload(default_prov);
        std::cout << "OpenSSL provider unloaded." << std::endl;
    }
    
    return 0;
}
