/*
 * Copyright (c) 2024-2025 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef PIPELINEMANAGER_HPP
#define PIPELINEMANAGER_HPP

#include <iostream>
#include <vector>
#include <queue>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <coroutine>
#include <string>
#include <filesystem>
#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <map>
#include <asio/steady_timer.hpp>
#include "async_file_types.hpp"
#include "nkcrypto_ffi.hpp"

class AsyncOrderedQueue {
public:
    AsyncOrderedQueue(asio::io_context& io_context)
        : io_context_(io_context), next_expected_order_(0), signal_timer_(io_context), is_closed_(false) {
        signal_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    }
    void push(uint64_t order, std::vector<char> data) {
        { std::unique_lock<std::mutex> lock(mutex_); buffer_.emplace(order, std::move(data)); }
        signal_timer_.cancel();
    }
    void close() {
        { std::unique_lock<std::mutex> lock(mutex_); is_closed_ = true; }
        signal_timer_.cancel();
    }
    asio::awaitable<std::vector<char>> async_pop() {
        while (true) {
            std::unique_lock<std::mutex> lock(mutex_);
            auto it = buffer_.find(next_expected_order_);
            if (it != buffer_.end()) {
                std::vector<char> data = std::move(it->second);
                buffer_.erase(it); next_expected_order_++;
                co_return data;
            }
            if (is_closed_) co_return std::vector<char>();
            lock.unlock();
            asio::error_code ec;
            signal_timer_.expires_at(std::chrono::steady_clock::time_point::max());
            co_await signal_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        }
    }
    size_t size() const { std::lock_guard<std::mutex> lock(mutex_); return buffer_.size(); }
    bool is_empty() const { std::lock_guard<std::mutex> lock(mutex_); return buffer_.empty(); }
private:
    asio::io_context& io_context_;
    mutable std::mutex mutex_;
    std::map<uint64_t, std::vector<char>> buffer_;
    uint64_t next_expected_order_;
    asio::steady_timer signal_timer_;
    bool is_closed_;
};

class PipelineManager : public std::enable_shared_from_this<PipelineManager> {
public:
    using StageFunc = std::function<std::vector<char>(const std::vector<char>&)>;
    using FinalizationFunc = std::function<asio::awaitable<void>(async_file_t&)>;

    explicit PipelineManager(asio::io_context& io_context)
        : io_context_(io_context), 
          results_queue_(io_context), input_file_(io_context), output_file_(io_context),
          is_running_(true), reading_complete_(false), next_task_id_(0), tasks_completed_count_(0),
          completion_handler_called_(false),
          backpressure_timer_(io_context) {
        backpressure_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    }

    ~PipelineManager() { is_running_ = false; backpressure_timer_.cancel(); }

    void add_stage(StageFunc stage) { stages_.push_back(std::move(stage)); }

    void run(const std::string& in_path, async_file_t out_file, uintmax_t read_offset, uintmax_t read_size,
             std::function<void(std::error_code)> completion_handler,
             FinalizationFunc finalization_handler = nullptr,
             ProgressCallback progress_callback = nullptr,
             uintmax_t total_input_size = 0);

    void run_sync(const std::string& in_path, const std::string& out_path, uintmax_t read_offset, uintmax_t read_size);

private:
    asio::awaitable<void> writer_coroutine(std::shared_ptr<PipelineManager> self);
    asio::awaitable<void> reader_coroutine(std::shared_ptr<PipelineManager> self);

    void call_completion_handler(const std::error_code& ec) {
        if (!completion_handler_called_.exchange(true)) {
            if (!ec && progress_callback_) progress_callback_(1.0);
            asio::post(io_context_, [this, ec, completion = completion_handler_]() {
                if (completion) completion(ec);
            });
        }
    }

    asio::io_context& io_context_;
    std::vector<StageFunc> stages_;
    AsyncOrderedQueue results_queue_;
    async_file_t input_file_;
    async_file_t output_file_;
    std::function<void(std::error_code)> completion_handler_;
    FinalizationFunc finalization_handler_;
    std::atomic<bool> is_running_, reading_complete_, completion_handler_called_;
    std::atomic<uint64_t> next_task_id_, tasks_completed_count_;
    std::mutex state_mutex_;
    asio::steady_timer backpressure_timer_; // 流量制限用タイマー
    uintmax_t total_to_read_{0}, total_read_{0}, total_written_{0}, total_input_size_{0}, next_progress_update_point_{0};
    ProgressCallback progress_callback_ = nullptr;
    static constexpr size_t CHUNK_SIZE = 1024 * 64;
    static constexpr size_t MAX_QUEUED_TASKS = 64; // 最大蓄積タスク数 (約4MB)
};
#endif
