#ifndef CRYPTOPROCESSOR_HPP
#define CRYPTOPROCESSOR_HPP

#include "CryptoConfig.hpp"
#include "nkcrypto_ffi.hpp"
#include <system_error>
#include <functional>
#include <future>
#include <memory>
#include <thread>
#include <asio.hpp>

namespace nk { class IKeyProvider; }

class CryptoProcessor {
public:
    explicit CryptoProcessor(CryptoConfig config);
    ~CryptoProcessor();

    std::future<void> run();
    void set_progress_callback(ProgressCallback cb);
    void setKeyProvider(std::shared_ptr<nk::IKeyProvider> provider);

private:
    void run_internal(); // 引数を削除

    CryptoConfig config_;
    ProgressCallback progress_callback_ = nullptr;
    std::shared_ptr<nk::IKeyProvider> key_provider_;
    std::shared_ptr<class nkCryptoToolBase> current_handler_;
    std::thread worker_thread_;
    asio::io_context io_context_;
    std::exception_ptr thread_exception_; // 例外保持用
};

#endif // CRYPTOPROCESSOR_HPP
