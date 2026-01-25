#ifndef ASYNC_FILE_TYPES_HPP
#define ASYNC_FILE_TYPES_HPP

#include <asio.hpp>
#include <memory>
#include <system_error> // For std::error_code
#include <string>       // For std::string

#ifdef _WIN32
#include <asio/stream_file.hpp>
// On Windows, stream_file can be used directly as it handles closing.
using async_file_t = asio::stream_file;

#else // For Linux/macOS
#include <asio/posix/stream_descriptor.hpp>
#include <unistd.h> // For ::open, ::close
#include <fcntl.h>  // For O_RDONLY etc.

// RAII wrapper for asio::posix::stream_descriptor to ensure close() is called.
class SafeStreamDescriptor {
public:
    explicit SafeStreamDescriptor(asio::io_context& io_context)
        : descriptor_(io_context) {}

    // Forbid copying
    SafeStreamDescriptor(const SafeStreamDescriptor&) = delete;
    SafeStreamDescriptor& operator=(const SafeStreamDescriptor&) = delete;

    // Move constructor
    SafeStreamDescriptor(SafeStreamDescriptor&& other) noexcept
        : descriptor_(std::move(other.descriptor_)) {}

    // Move assignment
    SafeStreamDescriptor& operator=(SafeStreamDescriptor&& other) noexcept {
        if (this != &other) {
            close(); // Close existing descriptor before move
            descriptor_ = std::move(other.descriptor_);
        }
        return *this;
    }

    ~SafeStreamDescriptor() {
        close();
    }

    void assign(int fd, std::error_code& ec) {
        descriptor_.assign(fd, ec);
    }

    void open(const std::string& path, int flags, std::error_code& ec) {
        close();
        int fd = ::open(path.c_str(), flags, 0666);
        if (fd == -1) {
            ec.assign(errno, std::system_category());
        } else {
            descriptor_.assign(fd, ec);
        }
    }

    void close(std::error_code& ec) {
        if (descriptor_.is_open()) {
            descriptor_.close(ec);
        }
    }

    void close() {
        std::error_code ignored_ec;
        close(ignored_ec);
    }

    bool is_open() const {
        return descriptor_.is_open();
    }

    int native_handle() {
        return descriptor_.native_handle();
    }

    // Getter to access the underlying descriptor for Asio free functions
    asio::posix::stream_descriptor& get() { return descriptor_; }
    const asio::posix::stream_descriptor& get() const { return descriptor_; }

private:
    asio::posix::stream_descriptor descriptor_;
};

using async_file_t = SafeStreamDescriptor;

#endif // Not _WIN32
#endif // ASYNC_FILE_TYPES_HPP