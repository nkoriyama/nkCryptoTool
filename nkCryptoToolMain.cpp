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
        ("user-privkey", "The user's private key for decryption", cxxopts::value<std::string>())
        ("signing-privkey", "The signer's private key for signing", cxxopts::value<std::string>())
        ("signing-pubkey", "The signer's public key for verification", cxxopts::value<std::string>())
        ("signature", "Path to the signature file", cxxopts::value<std::string>())
        ("digest-algo", "Hashing algorithm", cxxopts::value<std::string>()->default_value("SHA3-512"))
        ("tpm", "Use TPM to protect private keys")
        ("no-passphrase", "Do not use a passphrase for private keys")
        ("passphrase", "Passphrase for private keys", cxxopts::value<std::string>())
        ("r,recursive", "Process directories recursively")
        ("input-dir", "Directory for recursive input", cxxopts::value<std::string>())
        ("output-dir", "Directory for recursive output", cxxopts::value<std::string>());

    try {
        auto result = options.parse(argc, argv);
        auto positional = result.unmatched();

        CryptoConfig config;
        config.mode = get_mode_from_string(result["mode"].as<std::string>());
        
        if (result.count("encrypt")) config.operation = Operation::Encrypt;
        else if (result.count("decrypt")) config.operation = Operation::Decrypt;
        else if (result.count("sign")) config.operation = Operation::Sign;
        else if (result.count("verify")) config.operation = Operation::Verify;
        else if (result.count("gen-enc-key")) config.operation = Operation::GenerateEncKey;
        else if (result.count("gen-sign-key")) config.operation = Operation::GenerateSignKey;

        if (result.count("output-file")) config.output_file = result["output-file"].as<std::string>();
        if (result.count("key-dir")) config.key_paths["key-dir"] = result["key-dir"].as<std::string>();
        if (result.count("recipient-pubkey")) config.key_paths["recipient-pubkey"] = result["recipient-pubkey"].as<std::string>();
        if (result.count("user-privkey")) config.key_paths["user-privkey"] = result["user-privkey"].as<std::string>();
        if (result.count("signing-privkey")) config.key_paths["signing-privkey"] = result["signing-privkey"].as<std::string>();
        if (result.count("signing-pubkey")) config.key_paths["signing-pubkey"] = result["signing-pubkey"].as<std::string>();
        if (result.count("signature")) config.key_paths["signature"] = result["signature"].as<std::string>();
        if (result.count("digest-algo")) config.digest_algo = result["digest-algo"].as<std::string>();
        
        bool tpm = result.count("tpm") > 0;
        bool no_pass = result.count("no-passphrase") > 0;
        if (tpm) config.key_paths["use-tpm"] = "true";

        if (result.count("passphrase")) {
            config.passphrase = result["passphrase"].as<std::string>();
            config.passphrase_was_provided = true;
        } else if (!no_pass && (config.operation != Operation::Verify)) {
             config.passphrase = get_masked_passphrase();
             config.passphrase_was_provided = true;
        }

        for (auto& p : positional) config.input_files.push_back(p);

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
