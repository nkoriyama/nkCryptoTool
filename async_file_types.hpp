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

#ifdef _WIN32
#include <asio/windows/stream_handle.hpp>
using async_file_t = std::shared_ptr<asio::windows::stream_handle>;
#else
#include <asio/posix/stream_descriptor.hpp>
#include <fcntl.h>
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
