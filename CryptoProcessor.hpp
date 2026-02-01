#ifndef CRYPTOPROCESSOR_HPP
#define CRYPTOPROCESSOR_HPP

#include "CryptoConfig.hpp"
#include "nkcrypto_ffi.hpp" // For ProgressCallback
#include <system_error>
#include <functional>
#include <future>

class CryptoProcessor {
public:
    explicit CryptoProcessor(CryptoConfig config);
    ~CryptoProcessor();

    // Asynchronously run the operation
    std::future<void> run();

    // Set the progress callback
    void set_progress_callback(ProgressCallback cb);

private:
    void run_internal(std::promise<void> promise);

    CryptoConfig config_;
    ProgressCallback progress_callback_ = nullptr;
};

#endif // CRYPTOPROCESSOR_HPP
