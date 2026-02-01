#include "CryptoProcessor.hpp"
#include "nkCryptoToolBase.hpp"
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"
#include "nkCryptoToolUtils.hpp"

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <thread>
#include <iostream>
#include <format>

CryptoProcessor::CryptoProcessor(CryptoConfig config)
    : config_(std::move(config)) {}

CryptoProcessor::~CryptoProcessor() = default;

std::future<void> CryptoProcessor::run() {
    std::promise<void> promise;
    auto future = promise.get_future();

    // Run the actual processing in a separate thread to not block the caller
    std::thread([this, p = std::move(promise)]() mutable {
        run_internal(std::move(p));
    }).detach();

    return future;
}

void CryptoProcessor::run_internal(std::promise<void> promise) {
    try {
        std::unique_ptr<nkCryptoToolBase> crypto_handler;
        if (config_.mode == CryptoMode::ECC) {
            crypto_handler = std::make_unique<nkCryptoToolECC>();
        } else { // PQC or Hybrid
            crypto_handler = std::make_unique<nkCryptoToolPQC>();
        }

        if (!config_.key_dir.empty()) {
            crypto_handler->setKeyBaseDirectory(config_.key_dir);
        }

        asio::io_context io_context;
        auto work_guard = asio::make_work_guard(io_context.get_executor());
        
        auto completion_handler = [&](std::error_code ec) {
            if (ec) {
                promise.set_exception(std::make_exception_ptr(std::system_error(ec, "Operation failed")));
            } else {
                promise.set_value();
            }
            work_guard.reset();
        };

        switch (config_.operation) {
            case Operation::Encrypt: {
                std::cout << std::format("Starting {} encryption...\n", to_string(config_.mode));
                if (config_.sync_mode) {
                    crypto_handler->encryptFileWithSync(config_.input_files[0], config_.output_file, config_.key_paths);
                    promise.set_value();
                } else {
                    crypto_handler->encryptFileWithPipeline(io_context, config_.input_files[0], config_.output_file, config_.key_paths, completion_handler);
                    io_context.run();
                }
                break;
            }
            case Operation::Decrypt: {
                std::cout << std::format("Starting {} decryption...\n", to_string(config_.mode));
                if (config_.sync_mode) {
                    crypto_handler->decryptFileWithSync(config_.input_files[0], config_.output_file, config_.key_paths);
                    promise.set_value();
                } else {
                    crypto_handler->decryptFileWithPipeline(io_context, config_.input_files[0], config_.output_file, config_.key_paths, completion_handler);
                    io_context.run();
                }
                break;
            }
            case Operation::Sign: {
                 std::cout << "Starting file signing...\n";
                 asio::co_spawn(io_context, crypto_handler->signFile(
                    io_context,
                    config_.input_files[0],
                    config_.signature_file,
                    config_.key_paths.at("signing-privkey"),
                    config_.digest_algo
                ), [&](std::exception_ptr p) {
                    if (p) {
                        promise.set_exception(p);
                    } else {
                        promise.set_value();
                    }
                    work_guard.reset();
                });
                io_context.run();
                break;
            }
             case Operation::Verify: {
                std::cout << "Starting signature verification...\n";
                asio::co_spawn(io_context, crypto_handler->verifySignature(
                    io_context,
                    config_.input_files[0],
                    config_.signature_file,
                    config_.key_paths.at("signing-pubkey")
                ), [&](std::exception_ptr p, std::expected<void, CryptoError> result) {
                    if (p) {
                        promise.set_exception(p);
                    } else if (!result) {
                        promise.set_exception(std::make_exception_ptr(std::runtime_error("Signature verification failed: " + toString(result.error()))));
                    } else {
                        std::cout << "Signature verified successfully." << std::endl;
                        promise.set_value();
                    }
                    work_guard.reset();
                });
                io_context.run();
                break;
            }
            case Operation::GenerateEncKey:
            case Operation::GenerateSignKey:
                 // Key generation is synchronous and simple, so we can do it directly.
                // Complex user interaction (passphrase) is handled here for now.
                {
                    auto handle_result = [&](const std::expected<void, CryptoError>& res, const std::string& key_type) {
                        if (res) {
                            std::cout << std::format("{} keys generated successfully in {}\n", key_type, crypto_handler->getKeyBaseDirectory().string());
                        } else {
                            throw std::runtime_error(std::format("Error: {} key generation failed. Reason: {}", key_type, toString(res.error())));
                        }
                    };

                    if (config_.mode == CryptoMode::Hybrid && config_.operation == Operation::GenerateEncKey) {
                        std::string mlkem_passphrase, ecdh_passphrase;
                        if (config_.passphrase_was_provided) {
                            mlkem_passphrase = config_.passphrase;
                            ecdh_passphrase = config_.passphrase;
                            std::cout << "Using provided passphrase for both ML-KEM and ECDH keys." << std::endl;
                        } else {
                            mlkem_passphrase = get_and_verify_passphrase("Enter passphrase for ML-KEM private key (press Enter to save unencrypted): ");
                            ecdh_passphrase = get_and_verify_passphrase("Enter passphrase for ECDH private key (press Enter to save unencrypted): ");
                        }
                        auto pqc_handler = static_cast<nkCryptoToolPQC*>(crypto_handler.get());
                        handle_result(pqc_handler->generateEncryptionKeyPair(pqc_handler->getKeyBaseDirectory() / "public_enc_hybrid_mlkem.key", pqc_handler->getKeyBaseDirectory() / "private_enc_hybrid_mlkem.key", mlkem_passphrase), "Hybrid ML-KEM");
                        
                        nkCryptoToolECC ecc_handler;
                        ecc_handler.setKeyBaseDirectory(crypto_handler->getKeyBaseDirectory());
                        handle_result(ecc_handler.generateEncryptionKeyPair(ecc_handler.getKeyBaseDirectory() / "public_enc_hybrid_ecdh.key", ecc_handler.getKeyBaseDirectory() / "private_enc_hybrid_ecdh.key", ecdh_passphrase), "Hybrid ECDH");
                    } else {
                        std::string passphrase_to_use = config_.passphrase_was_provided ? config_.passphrase : get_and_verify_passphrase("Enter passphrase to encrypt private key (press Enter to save unencrypted): ");
                        if (config_.operation == Operation::GenerateEncKey) {
                            handle_result(crypto_handler->generateEncryptionKeyPair(crypto_handler->getEncryptionPublicKeyPath(), crypto_handler->getEncryptionPrivateKeyPath(), passphrase_to_use), "Encryption");
                        } else {
                            handle_result(crypto_handler->generateSigningKeyPair(crypto_handler->getSigningPublicKeyPath(), crypto_handler->getSigningPrivateKeyPath(), passphrase_to_use), "Signing");
                        }
                    }
                    promise.set_value();
                }
                break;
            case Operation::RegeneratePubKey:
                {
                    std::string passphrase_to_use = config_.passphrase_was_provided ? config_.passphrase : get_and_verify_passphrase("Enter passphrase for private key (press Enter if unencrypted): ");
                    auto res = crypto_handler->regeneratePublicKey(config_.regenerate_privkey_path, config_.regenerate_pubkey_path, passphrase_to_use);
                    if (res) {
                        std::cout << std::format("Public key successfully regenerated and saved to: {}\n", config_.regenerate_pubkey_path);
                        promise.set_value();
                    } else {
                        throw std::runtime_error("Failed to regenerate public key. Reason: " + toString(res.error()));
                    }
                }
                break;
            case Operation::None:
                // No operation specified, should be handled by CLI logic before calling processor.
                promise.set_value();
                break;
        }

    } catch (const std::exception& e) {
        promise.set_exception(std::current_exception());
    }
}
