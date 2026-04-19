#include "CryptoProcessor.hpp"
#include "nkCryptoToolBase.hpp"
#include "ECCStrategy.hpp"
#include "PQCStrategy.hpp"
#include "HybridStrategy.hpp"
#include "nkCryptoToolUtils.hpp"
#include "TpmKeyProvider.hpp"

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <thread>
#include <iostream>
#include <format>

CryptoProcessor::CryptoProcessor(CryptoConfig config) : config_(std::move(config)), io_context_() {}

CryptoProcessor::~CryptoProcessor() {
    io_context_.stop();
}

std::future<void> CryptoProcessor::run() {
    return std::async(std::launch::async, [this]() {
        run_internal();
        if (thread_exception_) {
            std::rethrow_exception(thread_exception_);
        }
    });
}

void CryptoProcessor::set_progress_callback(ProgressCallback callback) {
    progress_callback_ = callback;
}

void CryptoProcessor::run_internal() {
    try {
        io_context_.restart();
        auto work_guard = asio::make_work_guard(io_context_.get_executor());
        auto work_ptr = std::make_shared<decltype(work_guard)>(std::move(work_guard));
        
        std::shared_ptr<ICryptoStrategy> strategy;
        if (config_.mode == CryptoMode::ECC) strategy = std::make_shared<ECCStrategy>();
        else if (config_.mode == CryptoMode::PQC) strategy = std::make_shared<PQCStrategy>();
        else strategy = std::make_shared<HybridStrategy>();

        current_handler_ = std::make_shared<nkCryptoToolBase>(std::move(strategy));
        if (config_.use_tpm) {
            current_handler_->setKeyProvider(std::make_shared<nk::TpmKeyProvider>());
        }

        auto completion_handler = [this, work_ptr](std::error_code ec, std::string detail = "") mutable {
            if (ec && !thread_exception_) {
                std::string msg = detail.empty() ? "Operation failed" : detail;
                thread_exception_ = std::make_exception_ptr(std::system_error(ec, msg));
            }
            work_ptr->reset();
        };

        switch (config_.operation) {
            case Operation::Encrypt:
                current_handler_->encryptFileWithPipeline(io_context_, config_.input_files[0], config_.output_file, config_.key_paths, [completion_handler](std::error_code ec) mutable { completion_handler(ec); }, progress_callback_);
                break;
            case Operation::Decrypt:
                current_handler_->decryptFileWithPipeline(io_context_, config_.input_files[0], config_.output_file, config_.key_paths, config_.passphrase, [completion_handler](std::error_code ec) mutable { completion_handler(ec); }, progress_callback_);
                break;
            case Operation::Sign:
                asio::co_spawn(io_context_, current_handler_->signFile(io_context_, config_.input_files[0], config_.signature_file, config_.key_paths.at("signing-privkey"), config_.digest_algo, config_.passphrase, progress_callback_), 
                [completion_handler](std::exception_ptr p) mutable {
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
                    auto res = co_await current_handler_->verifySignature(io_context_, config_.input_files[0], config_.signature_file, config_.key_paths.at("signing-pubkey"), config_.digest_algo, progress_callback_);
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
        }

        io_context_.run();
    } catch (...) {
        thread_exception_ = std::current_exception();
    }
}
