/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef ASYNC_FILE_TYPES_HPP
#define ASYNC_FILE_TYPES_HPP

#include <asio.hpp>
#include <system_error>
#include <string>
#include <memory>
#include <cstdint>
#include <fcntl.h>

// Async file handle presenting one small interface across platforms:
//   open(path, O_* flags, ec) / seek(offset, ec) / get() [asio stream] /
//   native_handle() / close()
// On unix it wraps asio::posix::stream_descriptor (opened with ::open); on
// Windows it wraps asio::stream_file (overlapped I/O). Both are an
// AsyncReadStream/AsyncWriteStream, so asio::async_read/async_write work on each.

#ifdef _WIN32
#include <asio/stream_file.hpp>

class SafeStreamDescriptor {
public:
    explicit SafeStreamDescriptor(asio::io_context& io_context)
        : file_(std::make_shared<asio::stream_file>(io_context)) {}

    void open(const std::string& path, int flags, std::error_code& ec) {
        asio::file_base::flags f;
        if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR) {
            f = asio::file_base::write_only;
            if (flags & O_CREAT) f |= asio::file_base::create;
            if (flags & O_TRUNC) f |= asio::file_base::truncate;
        } else {
            f = asio::file_base::read_only;
        }
        file_->open(path, f, ec);
    }

    void seek(std::uintmax_t offset, std::error_code& ec) {
        file_->seek(static_cast<std::int64_t>(offset), asio::file_base::seek_set, ec);
    }

    void close() {
        std::error_code ec;
        if (file_->is_open()) file_->close(ec);
    }

    asio::stream_file& get() { return *file_; }
    auto native_handle() { return file_->native_handle(); }

private:
    std::shared_ptr<asio::stream_file> file_;
};

using async_file_t = SafeStreamDescriptor;

#else
#include <asio/posix/stream_descriptor.hpp>
#include <unistd.h>

class SafeStreamDescriptor {
public:
    explicit SafeStreamDescriptor(asio::io_context& io_context)
        : descriptor_(std::make_shared<asio::posix::stream_descriptor>(io_context)) {}

    void open(const std::string& path, int flags, std::error_code& ec) {
        int fd = ::open(path.c_str(), flags, 0644);
        if (fd == -1) {
            ec.assign(errno, std::system_category());
            return;
        }
        descriptor_->assign(fd, ec);
    }

    void seek(std::uintmax_t offset, std::error_code& ec) {
        if (::lseek(descriptor_->native_handle(), static_cast<off_t>(offset), SEEK_SET) == -1)
            ec.assign(errno, std::system_category());
    }

    void close() {
        std::error_code ec;
        if (descriptor_->is_open()) descriptor_->close(ec);
    }

    asio::posix::stream_descriptor& get() { return *descriptor_; }
    int native_handle() { return descriptor_->native_handle(); }

private:
    std::shared_ptr<asio::posix::stream_descriptor> descriptor_;
};

using async_file_t = SafeStreamDescriptor;
#endif

#endif
