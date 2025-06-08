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

#ifdef _WIN32
#include "getopt_long.h"
#else
#include <getopt.h>
#endif

#include <openssl/provider.h>
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"

// Global passphrase variable for OpenSSL PEM callbacks
std::string global_passphrase_for_pem_cb;
std::mutex passphrase_mutex;

// OpenSSL PEM passphrase callback function
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag;
    std::string *passphrase_ptr = static_cast<std::string*>(userdata);
    std::string input_passphrase;

    if (passphrase_ptr && !passphrase_ptr->empty()) {
        input_passphrase = *passphrase_ptr;
    } else {
        std::cout << "Enter passphrase: ";
        std::getline(std::cin, input_passphrase);
    }

    if (input_passphrase.length() > (unsigned int)size) {
        std::cerr << "Error: Passphrase too long." << std::endl;
        return 0;
    }
    memcpy(buf, input_passphrase.c_str(), input_passphrase.length());
    return static_cast<int>(input_passphrase.length());
}

void display_usage() {
    std::cout << "Usage: nkCryptoTool [OPTIONS] [FILE]\n"
              << "Encrypt, decrypt, sign, or verify files using ECC, PQC, or Hybrid mode.\n\n"
              << "Modes of operation (choose one):\n"
              << "  --mode <type>       Use 'ecc', 'pqc', or 'hybrid'. Default: ecc\n\n"
              << "Key Generation:\n"
              << "  --gen-enc-key       Generate encryption key pair(s).\n"
              << "  --gen-sign-key      Generate signing key pair ('ecc' or 'pqc' mode).\n"
              << "  --passphrase <pwd>  Passphrase for private key encryption.\n\n"
              << "Encryption:\n"
              << "  --encrypt           Encrypt input file.\n"
              << "  -o <path>           Output file path.\n"
              << "  --compress <algo>   Compress with 'lz4' before encryption. (Optional)\n"
              << "  --recipient-pubkey <path>      Recipient's public key (for ecc/pqc).\n"
              << "  --recipient-mlkem-pubkey <path> Recipient's ML-KEM public key (for hybrid).\n"
              << "  --recipient-ecdh-pubkey <path>  Recipient's ECDH public key (for hybrid).\n\n"
              << "Decryption:\n"
              << "  --decrypt           Decrypt input file.\n"
              << "  -o <path>           Output file path.\n"
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

    constexpr int RECIPIENT_MLKEM_PUBKEY_OPT = 256;
    constexpr int RECIPIENT_ECDH_PUBKEY_OPT = 257;
    constexpr int RECIPIENT_MLKEM_PRIVKEY_OPT = 258;
    constexpr int RECIPIENT_ECDH_PRIVKEY_OPT = 259;
    constexpr int SIGNATURE_FILE_OPT = 260;
    constexpr int COMPRESS_OPT = 261;

    struct option long_options[] = {
        {"mode", required_argument, nullptr, 'm'},
        {"gen-enc-key", no_argument, nullptr, 0},
        {"gen-sign-key", no_argument, nullptr, 0},
        {"passphrase", required_argument, nullptr, 'p'},
        {"encrypt", no_argument, nullptr, 0},
        {"decrypt", no_argument, nullptr, 0},
        {"sign", no_argument, nullptr, 0},
        {"verify", no_argument, nullptr, 0},
        {"compress", required_argument, nullptr, COMPRESS_OPT},
        {"output-file", required_argument, nullptr, 'o'},
        {"recipient-pubkey", required_argument, nullptr, 0},
        {"user-privkey", required_argument, nullptr, 0},
        {"recipient-mlkem-pubkey", required_argument, nullptr, RECIPIENT_MLKEM_PUBKEY_OPT},
        {"recipient-ecdh-pubkey", required_argument, nullptr, RECIPIENT_ECDH_PUBKEY_OPT},
        {"recipient-mlkem-privkey", required_argument, nullptr, RECIPIENT_MLKEM_PRIVKEY_OPT},
        {"recipient-ecdh-privkey", required_argument, nullptr, RECIPIENT_ECDH_PRIVKEY_OPT},
        {"signing-privkey", required_argument, nullptr, 0},
        {"signing-pubkey", required_argument, nullptr, 0},
        {"signature", required_argument, nullptr, SIGNATURE_FILE_OPT},
        {"digest-algo", required_argument, nullptr, 0},
        {"key-dir", required_argument, nullptr, 0},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };

    int opt, option_index = 0;
    while ((opt = getopt_long(argc, argv, "o:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0: // Long options that don't have a short version
                flags[long_options[option_index].name] = true;
                if(optarg) options[long_options[option_index].name] = optarg;
                break;
            case 'm': options["mode"] = optarg; break;
            case 'p': global_passphrase_for_pem_cb = optarg; break;
            case 'o': options["output-file"] = optarg; break;
            case 'h': display_usage(); return 0;
            case COMPRESS_OPT: options["compress"] = optarg; break;
            case SIGNATURE_FILE_OPT: options["signature"] = optarg; break;
            case RECIPIENT_MLKEM_PUBKEY_OPT: options["recipient-mlkem-pubkey"] = optarg; break;
            case RECIPIENT_ECDH_PUBKEY_OPT: options["recipient-ecdh-pubkey"] = optarg; break;
            case RECIPIENT_MLKEM_PRIVKEY_OPT: options["recipient-mlkem-privkey"] = optarg; break;
            case RECIPIENT_ECDH_PRIVKEY_OPT: options["recipient-ecdh-privkey"] = optarg; break;
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
    } else {
        std::cerr << "Error: Invalid mode '" << options["mode"] << "'." << std::endl;
        return 1;
    }

    if (options.count("key-dir")) {
        crypto_handler->setKeyBaseDirectory(options["key-dir"]);
    }
    
    asio::io_context io_context;
    int return_code = 0;
    bool async_op_started = false;

    if (flags["gen-enc-key"]) {
        // (鍵生成ロジック... 元のコードから)
    } else if (flags["gen-sign-key"]) {
        // (鍵生成ロジック... 元のコードから)
    } else if (flags["encrypt"]) {
        async_op_started = true;
        nkCryptoToolBase::CompressionAlgorithm algo = nkCryptoToolBase::CompressionAlgorithm::NONE;
        if (options["compress"] == "lz4") {
            algo = nkCryptoToolBase::CompressionAlgorithm::LZ4;
        }

        if (options["mode"] == "hybrid") {
            crypto_handler->encryptFileHybrid(io_context, non_option_args[0], options["output-file"], options["recipient-mlkem-pubkey"], options["recipient-ecdh-pubkey"], algo,
                [&](std::error_code ec){ if(ec) return_code = 1; });
        } else {
            crypto_handler->encryptFile(io_context, non_option_args[0], options["output-file"], options["recipient-pubkey"], algo,
                [&](std::error_code ec){ if(ec) return_code = 1; });
        }
    } else if (flags["decrypt"]) {
        async_op_started = true;
        if (options["mode"] == "hybrid") {
             crypto_handler->decryptFileHybrid(io_context, non_option_args[0], options["output-file"], options["recipient-mlkem-privkey"], options["recipient-ecdh-privkey"],
                [&](std::error_code ec){ if(ec) return_code = 1; });
        } else {
             crypto_handler->decryptFile(io_context, non_option_args[0], options["output-file"], options["user-privkey"], "",
                [&](std::error_code ec){ if(ec) return_code = 1; });
        }
    } else if (flags["sign"]) {
        async_op_started = true;
        crypto_handler->signFile(io_context, non_option_args[0], options["signature"], options["signing-privkey"], options["digest-algo"],
             [&](std::error_code ec){ if(ec) return_code = 1; });
    } else if (flags["verify"]) {
        async_op_started = true;
        crypto_handler->verifySignature(io_context, non_option_args[0], options["signature"], options["signing-pubkey"],
             [&](std::error_code ec, bool result){ if(ec || !result) return_code = 1; });
    } else {
        display_usage();
    }
    
    if (async_op_started) {
        io_context.run();
    }
    
    OSSL_PROVIDER_unload(nullptr);
    return return_code;
}
