#include "CryptoProcessor.hpp"
#include "nkCryptoToolBase.hpp"
#include "ECCStrategy.hpp"
#include "PQCStrategy.hpp"
#include "HybridStrategy.hpp"
#include "nkCryptoToolUtils.hpp"
#include "TpmKeyProvider.hpp"

#include <iostream>
#include <chrono>
#include <iomanip>
#include <asio/post.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>

CryptoProcessor::CryptoProcessor(CryptoConfig config)
    : config_(std::move(config)), io_context_(1) {
    switch (config_.mode) {
        case CryptoMode::ECC:
            strategy_ = std::make_shared<nk::ECCStrategy>();
            break;
        case CryptoMode::PQC: {
            auto pqc = std::make_shared<PQCStrategy>();
            pqc->setKemAlgo(config_.pqc_kem_algo);
            pqc->setDsaAlgo(config_.pqc_dsa_algo);
            strategy_ = pqc;
            break;
        }
        case CryptoMode::Hybrid: {
            auto hybrid = std::make_shared<nk::HybridStrategy>();
            hybrid->setKemAlgo(config_.pqc_kem_algo);
            hybrid->setDsaAlgo(config_.pqc_dsa_algo);
            strategy_ = hybrid;
            break;
        }
    }
    current_handler_ = std::make_shared<nkCryptoToolBase>(strategy_);
}

CryptoProcessor::~CryptoProcessor() {
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
}

std::future<void> CryptoProcessor::run() {
    auto promise = std::make_shared<std::promise<void>>();
    auto future = promise->get_future();

    worker_thread_ = std::thread([this, promise]() mutable {
        try {
            run_internal();
            if (thread_exception_) {
                promise->set_exception(thread_exception_);
            } else {
                promise->set_value();
            }
        } catch (...) {
            promise->set_exception(std::current_exception());
        }
    });

    return future;
}

void CryptoProcessor::set_progress_callback(std::function<void(double)> callback) {
    progress_callback_ = callback;
}

void CryptoProcessor::setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider) {
    key_provider_ = provider;
    if (current_handler_) current_handler_->setKeyProvider(provider);
}

void CryptoProcessor::run_internal() {
    auto work_ptr = std::make_shared<asio::executor_work_guard<asio::io_context::executor_type>>(io_context_.get_executor());

    auto completion_handler = [this, work_ptr](std::error_code ec, std::string detail = "") {
        if (ec && !thread_exception_) {
            std::string msg = detail.empty() ? "Operation failed" : detail;
            thread_exception_ = std::make_exception_ptr(std::system_error(ec, msg));
        }
        work_ptr->reset();
    };

    try {
        switch (config_.operation) {
            case Operation::Encrypt:
                current_handler_->encryptFileWithPipeline(io_context_, config_.input_files[0], config_.output_file, config_.key_paths, [completion_handler](std::error_code ec, const std::string& detail) mutable { completion_handler(ec, detail); }, progress_callback_);
                break;
            case Operation::Decrypt:
                current_handler_->decryptFileWithPipeline(io_context_, config_.input_files[0], config_.output_file, config_.key_paths, config_.passphrase, [completion_handler](std::error_code ec, const std::string& detail) mutable { completion_handler(ec, detail); }, progress_callback_);
                break;
            case Operation::Sign:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    std::string key_path;
                    if (config_.key_paths.count("signing-privkey")) key_path = config_.key_paths.at("signing-privkey");
                    else if (config_.key_paths.count("private-key")) key_path = config_.key_paths.at("private-key");
                    else throw std::system_error(std::make_error_code(std::errc::invalid_argument), "Missing signing private key");

                    co_await current_handler_->signFile(io_context_, config_.input_files[0], config_.signature_file, key_path, config_.digest_algo, config_.passphrase, progress_callback_);
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::Verify:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    std::string key_path;
                    if (config_.key_paths.count("signing-pubkey")) key_path = config_.key_paths.at("signing-pubkey");
                    else if (config_.key_paths.count("public-key")) key_path = config_.key_paths.at("public-key");
                    else throw std::system_error(std::make_error_code(std::errc::invalid_argument), "Missing signing public key");

                    auto res = co_await current_handler_->verifySignature(io_context_, config_.input_files[0], config_.signature_file, key_path, config_.digest_algo, progress_callback_);
                    if (!res) throw std::system_error(make_error_code(std::errc::invalid_argument), toString(res.error()));
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::GenerateEncKey:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    auto res = current_handler_->generateEncryptionKeyPair(config_.key_paths, config_.passphrase);
                    if (!res) throw std::system_error(std::make_error_code(std::errc::invalid_argument), toString(res.error()));
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::GenerateSignKey:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    auto res = current_handler_->generateSigningKeyPair(config_.key_paths, config_.passphrase);
                    if (!res) throw std::system_error(std::make_error_code(std::errc::invalid_argument), toString(res.error()));
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::RegeneratePubKey:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    auto res = current_handler_->regeneratePublicKey(config_.regenerate_privkey_path, config_.regenerate_pubkey_path, config_.passphrase);
                    if (!res) throw std::system_error(make_error_code(std::errc::invalid_argument), toString(res.error()));
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::WrapKey:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    auto res = current_handler_->wrapPrivateKey(config_.input_files[0], config_.output_file, config_.passphrase);
                    if (!res) throw std::system_error(make_error_code(std::errc::invalid_argument), toString(res.error()));
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::UnwrapKey:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    auto res = current_handler_->unwrapPrivateKey(config_.input_files[0], config_.output_file, config_.passphrase);
                    if (!res) throw std::system_error(make_error_code(std::errc::invalid_argument), toString(res.error()));
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            case Operation::Info:
                asio::co_spawn(io_context_, [this]() -> asio::awaitable<void> {
                    auto res = co_await current_handler_->inspectFile(io_context_, config_.input_files[0], progress_callback_);
                    if (!res) throw std::system_error(make_error_code(std::errc::invalid_argument), toString(res.error()));
                    for (const auto& [k, v] : *res) std::cout << k << ": " << v << std::endl;
                    co_return;
                }, [completion_handler](std::exception_ptr p) mutable {
                    if (p) {
                        try { std::rethrow_exception(p); }
                        catch (const std::system_error& e) { completion_handler(e.code(), e.what()); }
                        catch (const std::exception& e) { completion_handler(std::make_error_code(std::errc::io_error), e.what()); }
                        catch (...) { completion_handler(std::make_error_code(std::errc::io_error)); }
                    }
                    else completion_handler({});
                });
                break;
            default:
                asio::post(io_context_, [completion_handler]() mutable { completion_handler({}); });
                break;
        }

        io_context_.run();
    } catch (...) {
        thread_exception_ = std::current_exception();
    }
}
