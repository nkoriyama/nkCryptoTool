// nkCryptoToolMain.cpp

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <mutex>
#include <map>
#include <functional>
#include <asio.hpp>

#include <getopt.h>

#include <openssl/provider.h>
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"

// Global passphrase variable passed to key generation functions.
std::string global_passphrase_for_pem_cb;
std::mutex passphrase_mutex;

// OpenSSL PEM passphrase callback function
// This function is called by OpenSSL when a passphrase is needed.
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag; // Unused parameter

    // The userdata is expected to be a pointer to a std::string.
    const std::string* passphrase_from_arg = static_cast<const std::string*>(userdata);
    std::string final_passphrase;

    // If a passphrase was provided via command line, use it.
    if (passphrase_from_arg && !passphrase_from_arg->empty()) {
        final_passphrase = *passphrase_from_arg;
    } else {
        // Otherwise, prompt the user to enter it interactively.
        std::cout << "Enter passphrase for private key: ";
        std::getline(std::cin, final_passphrase);
        if (std::cin.eof()) { // Handle EOF (e.g., Ctrl+D)
            return 0;
        }
    }

    // Ensure the passphrase is not empty. Encryption requires a passphrase.
    if (final_passphrase.empty()) {
        std::cerr << "\nError: Passphrase cannot be empty for encryption." << std::endl;
        return 0;
    }

    // Check if the passphrase is too long for the buffer.
    if (final_passphrase.length() >= (unsigned int)size) {
        std::cerr << "\nError: Passphrase is too long." << std::endl;
        return 0;
    }

    // Copy the passphrase to the buffer provided by OpenSSL.
    strncpy(buf, final_passphrase.c_str(), size - 1);
    buf[size - 1] = '\0'; // Ensure null-termination.

    return static_cast<int>(strlen(buf));
}


void display_usage() {
    std::cout << "Usage: nkCryptoTool [OPTIONS] [FILE]\n"
              << "Encrypt, decrypt, sign, or verify files using ECC, PQC, or Hybrid mode.\n\n"
              << "Modes of operation (choose one):\n"
              << "  --mode <type>       Use 'ecc', 'pqc', or 'hybrid'. Default: ecc\n\n"
              << "Key Generation:\n"
              << "  --gen-enc-key       Generate encryption key pair(s).\n"
              << "  --gen-sign-key      Generate signing key pair ('ecc' or 'pqc' mode).\n"
              << "  --passphrase <pwd>  Passphrase for private key encryption. If not provided, you will be prompted.\n\n"
              << "Encryption:\n"
              << "  --encrypt           Encrypt input file.\n"
              << "  -o, --output-file <path>   Output file path.\n"
              << "  --compress <algo>   Compress with 'lz4' before encryption. (Optional)\n"
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
              << "  -h, --help          Display this help message.\n";
}

int main(int argc, char* argv[]) {
    OSSL_PROVIDER_load(nullptr, "default");

    std::map<std::string, bool> flags;
    std::map<std::string, std::string> options;
    std::vector<std::string> non_option_args;

    options["mode"] = "ecc";
    options["digest-algo"] = "SHA256";
    options["compress"] = "none";

    enum {
        OPT_GEN_ENC_KEY = 256, OPT_GEN_SIGN_KEY, OPT_ENCRYPT, OPT_DECRYPT,
        OPT_SIGN, OPT_VERIFY, OPT_RECIPIENT_PUBKEY, OPT_USER_PRIVKEY,
        OPT_RECIPIENT_MLKEM_PUBKEY, OPT_RECIPIENT_ECDH_PUBKEY,
        OPT_RECIPIENT_MLKEM_PRIVKEY, OPT_RECIPIENT_ECDH_PRIVKEY,
        OPT_SIGNING_PRIVKEY, OPT_SIGNING_PUBKEY, OPT_SIGNATURE,
        OPT_DIGEST_ALGO, OPT_KEY_DIR, OPT_COMPRESS
    };

    struct option long_options[] = {
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
        {"compress", required_argument, nullptr, OPT_COMPRESS},
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

    int opt;
    while ((opt = getopt_long(argc, argv, "m:p:o:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'm': options["mode"] = optarg; break;
            case 'p': global_passphrase_for_pem_cb = optarg; break;
            case 'o': options["output-file"] = optarg; break;
            case 'h': display_usage(); return 0;
            case OPT_GEN_ENC_KEY: flags["gen-enc-key"] = true; break;
            case OPT_GEN_SIGN_KEY: flags["gen-sign-key"] = true; break;
            case OPT_ENCRYPT: flags["encrypt"] = true; break;
            case OPT_DECRYPT: flags["decrypt"] = true; break;
            case OPT_SIGN: flags["sign"] = true; break;
            case OPT_VERIFY: flags["verify"] = true; break;
            case OPT_COMPRESS: options["compress"] = optarg; break;
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
        crypto_handler = std::make_unique<nkCryptoToolPQC>();
        if (options["mode"] == "pqc") options["digest-algo"] = "SHA3-256";
    } else {
        std::cerr << "Error: Invalid mode '" << options["mode"] << "'." << std::endl;
        return 1;
    }

    if (options.count("key-dir")) {
        crypto_handler->setKeyBaseDirectory(options["key-dir"]);
    }
    
    asio::io_context io_context;
    int return_code = 0;
    bool op_started = false;

    if (flags["gen-enc-key"]) {
        op_started = true;
        bool success = false;
        if (options["mode"] == "hybrid") {
            // Hybrid mode needs to generate two key pairs: ML-KEM and ECDH
            std::cout << "Generating ML-KEM keys for hybrid encryption..." << std::endl;
            // The handler should be PQC for hybrid mode
            auto pqc_handler = static_cast<nkCryptoToolPQC*>(crypto_handler.get());
            success = pqc_handler->generateEncryptionKeyPair(
                pqc_handler->getKeyBaseDirectory() / "public_enc_mlkem.key",
                pqc_handler->getKeyBaseDirectory() / "private_enc_mlkem.key",
                global_passphrase_for_pem_cb
            );

            if(success) {
                std::cout << "Generating ECDH keys for hybrid encryption..." << std::endl;
                // We need a separate ECC handler instance for this part
                nkCryptoToolECC ecc_handler;
                ecc_handler.setKeyBaseDirectory(crypto_handler->getKeyBaseDirectory());
                success = ecc_handler.generateEncryptionKeyPair(
                    ecc_handler.getKeyBaseDirectory() / "public_enc_ecdh.key",
                    ecc_handler.getKeyBaseDirectory() / "private_enc_ecdh.key",
                    global_passphrase_for_pem_cb
                );
            }
        } else {
            // Standard ECC or PQC mode
            success = crypto_handler->generateEncryptionKeyPair(
                crypto_handler->getEncryptionPublicKeyPath(),
                crypto_handler->getEncryptionPrivateKeyPath(),
                global_passphrase_for_pem_cb
            );
        }

        if (success) {
            std::cout << "Encryption keys generated successfully in " << crypto_handler->getKeyBaseDirectory().string() << std::endl;
        } else {
            std::cerr << "Error: Encryption key generation failed." << std::endl;
            return_code = 1;
        }
    } else if (flags["gen-sign-key"]) {
        op_started = true;
        bool success = crypto_handler->generateSigningKeyPair(
            crypto_handler->getSigningPublicKeyPath(),
            crypto_handler->getSigningPrivateKeyPath(),
            global_passphrase_for_pem_cb
        );
        if (success) {
            std::cout << "Signing keys generated successfully to " << crypto_handler->getKeyBaseDirectory().string() << std::endl;
        } else {
            std::cerr << "Error: Signing key generation failed." << std::endl;
            return_code = 1;
        }
    } else if (flags["encrypt"]) {
        // (Existing encryption logic...)
        op_started = true;
        auto algo = nkCryptoToolBase::CompressionAlgorithm::NONE;
        if (options["compress"] == "lz4") algo = nkCryptoToolBase::CompressionAlgorithm::LZ4;

        if (options["mode"] == "hybrid") {
            crypto_handler->encryptFileHybrid(io_context, non_option_args[0], options["output-file"], options["recipient-mlkem-pubkey"], options["recipient-ecdh-pubkey"], algo,
                [&](std::error_code ec){ if(ec) return_code = 1; });
        } else {
            crypto_handler->encryptFile(io_context, non_option_args[0], options["output-file"], options["recipient-pubkey"], algo,
                [&](std::error_code ec){ if(ec) return_code = 1; });
        }
    } else if (flags["decrypt"]) {
        // (Existing decryption logic...)
        op_started = true;
        if (options["mode"] == "hybrid") {
             crypto_handler->decryptFileHybrid(io_context, non_option_args[0], options["output-file"], options["recipient-mlkem-privkey"], options["recipient-ecdh-privkey"],
                [&](std::error_code ec){ if(ec) return_code = 1; });
        } else {
             crypto_handler->decryptFile(io_context, non_option_args[0], options["output-file"], options["user-privkey"], "",
                [&](std::error_code ec){ if(ec) return_code = 1; });
        }
    } else if (flags["sign"]) {
        // (Existing signing logic...)
        op_started = true;
        crypto_handler->signFile(io_context, non_option_args[0], options["signature"], options["signing-privkey"], options["digest-algo"],
             [&](std::error_code ec){ if(ec) return_code = 1; });
    } else if (flags["verify"]) {
        // (Existing verification logic...)
        op_started = true;
        crypto_handler->verifySignature(io_context, non_option_args[0], options["signature"], options["signing-pubkey"],
             [&](std::error_code ec, bool result){ 
                 if(ec) { std::cerr << "\nError during verification: " << ec.message() << std::endl; return_code = 1; }
                 else if (result) { std::cout << "\nSignature verified successfully." << std::endl; }
                 else { std::cerr << "\nSignature verification failed." << std::endl; return_code = 1;}
             });
    } else {
        if (argc > 1) {
            std::cerr << "Error: No valid operation specified." << std::endl;
            return_code = 1;
        }
        display_usage();
    }
    
    if (op_started && return_code == 0) {
        try {
            io_context.run();
        } catch (const std::exception& e) {
            std::cerr << "An unexpected error occurred: " << e.what() << std::endl;
            return_code = 1;
        }
    }
    
    OSSL_PROVIDER_unload(nullptr);
    return return_code;
}
