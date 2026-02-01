#ifndef CRYPTOPROCESSOR_HPP
#define CRYPTOPROCESSOR_HPP

#include "CryptoConfig.hpp"
#include <system_error>
#include <functional>
#include <future>

class CryptoProcessor {
public:
    explicit CryptoProcessor(CryptoConfig config);
    ~CryptoProcessor();

    // Asynchronously run the operation
    std::future<void> run();

private:
    void run_internal(std::promise<void> promise);

    CryptoConfig config_;
};

#endif // CRYPTOPROCESSOR_HPP
