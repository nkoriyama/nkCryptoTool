/*
 * Copyright (c) 2024-2025 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 *
 * nkCryptoTool is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nkCryptoTool is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nkCryptoTool. If not, see <https://www.gnu.org/licenses/>.
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
#include <coroutine> // Added for C++ coroutines
#include <string>
#include <filesystem>
#include <sstream>
#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <map>
#include <stack> // Added for buffer pool

#include <asio/steady_timer.hpp>
#include "async_file_types.hpp" // Use the new centralized header

// イベント駆動型キュー
class AsyncOrderedQueue {
public:
    AsyncOrderedQueue(asio::io_context& io_context)
        : io_context_(io_context),
          next_expected_order_(0),
          signal_timer_(io_context) // Corrected initializer list
    {
        signal_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    }

    void push(uint64_t order, std::vector<char> data) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            buffer_.emplace(order, std::move(data));
        }
        signal_timer_.cancel();
    }

    asio::awaitable<std::vector<char>> async_pop() {
        while (true)
        {
            std::unique_lock<std::mutex> lock(mutex_);
            auto it = buffer_.find(next_expected_order_);
            if (it != buffer_.end()) {
                std::vector<char> data = std::move(it->second);
                buffer_.erase(it);
                next_expected_order_++;
                co_return data;
            }
            lock.unlock();

            asio::error_code ec;
            signal_timer_.expires_at(std::chrono::steady_clock::time_point::max());
            co_await signal_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        }
    }

    bool is_empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return buffer_.empty();
    }

    uint64_t get_next_expected_order() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return next_expected_order_;
    }

private:
    asio::io_context& io_context_;
    mutable std::mutex mutex_;
    std::map<uint64_t, std::vector<char>> buffer_;
    uint64_t next_expected_order_;
    asio::steady_timer signal_timer_;
};

class PipelineManager : public std::enable_shared_from_this<PipelineManager> {
public:
    using StageFunc = std::function<std::vector<char>(const std::vector<char>&)>;
    using FinalizationFunc = std::function<asio::awaitable<void>(async_file_t&)>;

    explicit PipelineManager(asio::io_context& io_context, size_t num_threads = std::thread::hardware_concurrency())
        : io_context_(io_context),
          work_guard_(asio::make_work_guard(io_context.get_executor())),
          threads_(num_threads),
          input_file_(io_context),
          output_file_(io_context),
          is_running_(true),
          reading_complete_(false),
          next_task_id_(0),
          tasks_completed_count_(0),
          completion_handler_called_(false),
          results_queue_(io_context_)
    {
        log_message("PipelineManager created with " + std::to_string(num_threads) + " threads.");
        for (size_t i = 0; i < num_threads; ++i) {
            threads_[i] = std::thread(&PipelineManager::worker_thread, this, i);
        }
    }

    ~PipelineManager() {
        {
            std::unique_lock<std::mutex> lock(shared_state_mutex_);
            is_running_ = false;
        }
        cv_task_.notify_all();
        for (auto& t : threads_) {
            if (t.joinable()) {
                t.join();
            }
        }
        log_message("PipelineManager destroyed.");
    }

    void add_stage(StageFunc stage) {
        stages_.push_back(std::move(stage));
    }

    void run(const std::string& in_path, async_file_t&& out_file, uintmax_t read_offset, uintmax_t read_size, std::function<void(std::error_code)> on_complete, FinalizationFunc on_finalize = nullptr) {
        log_message("Pipeline starting. Input: " + in_path);
        completion_handler_ = on_complete;
        finalization_handler_ = std::move(on_finalize);
        output_file_ = std::move(out_file);

        std::error_code ec;
#ifdef _WIN32
        input_file_.open(in_path.c_str(), async_file_t::read_only, ec);
#else
        input_file_.open(in_path, O_RDONLY, ec); // Changed c_str() to path for SafeStreamDescriptor
#endif
        if (ec) {
            call_completion_handler(ec);
            return;
        }

#ifdef _WIN32
        input_file_.get().seek(read_offset, asio::file_base::seek_set, ec); // Use .get() for seek
#else
        // Using native_handle() for lseek as SafeStreamDescriptor wraps stream_descriptor
        if (::lseek(input_file_.native_handle(), read_offset, SEEK_SET) == -1) {
            ec.assign(errno, std::system_category());
        }
#endif
        if(ec) {
             call_completion_handler(ec); return;
        }

        total_to_read_ = read_size;
        total_read_ = 0;

        start_writer();
        asio::co_spawn(io_context_, reader_coroutine(), [this, self = shared_from_this()](std::exception_ptr p) {
            if (p) {
                try { std::rethrow_exception(p); }
                catch (const std::exception& e) { self->call_completion_handler(std::make_error_code(std::errc::io_error)); }
            }
        });
    }

private:
    struct Task {
        std::vector<char> data;
        uint64_t original_order;
    };

    // --- メモリプール機能 ---
    std::stack<std::vector<char>> buffer_pool_;
    std::mutex pool_mutex_;

    std::vector<char> acquire_buffer(size_t size) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        if (buffer_pool_.empty()) {
            return std::vector<char>(size);
        }
        std::vector<char> buf = std::move(buffer_pool_.top());
        buffer_pool_.pop();

        if (buf.size() != size) {
            buf.resize(size);
        }
        return buf;
    }

    void release_buffer(std::vector<char> buf) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        buffer_pool_.push(std::move(buf));
    }
    // ------------------------

    void log_message(const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex_);
#if defined (DETAIL_LOG)
        std::stringstream ss;
        ss << "[TID:" << std::this_thread::get_id() << "] " << msg << "\n";
        std::cout << ss.str();
        std::cout.flush();
#endif
    }

    void call_completion_handler(const std::error_code& ec) {
        bool already_called = completion_handler_called_.exchange(true);
        if (!already_called) {
            asio::post(io_context_, [this, ec]() {
                if (completion_handler_) completion_handler_(ec);
                work_guard_.reset();
            });
        }
    }

    void worker_thread(size_t thread_id) {
        while (is_running_) {
            Task task;
            {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                cv_task_.wait(lock, [this] { return !task_queue_.empty() || !is_running_; });
                if (!is_running_) break;
                if (task_queue_.empty()) continue;

                task = std::move(task_queue_.front());
                task_queue_.pop();
            }

            try {
                for (const auto& stage : stages_) {
                    task.data = stage(task.data);
                }
                results_queue_.push(task.original_order, std::move(task.data));
            } catch (const std::exception& e) {
                call_completion_handler(std::make_error_code(std::errc::io_error));
            }
        }
    }

    void start_writer() {
        asio::co_spawn(io_context_, writer_coroutine(), [this, self = shared_from_this()](std::exception_ptr p) {
            if (p) {
                try { std::rethrow_exception(p); }
                catch (const std::exception& e) { self->call_completion_handler(std::make_error_code(std::errc::io_error)); }
            }
        });
    }

    asio::awaitable<void> writer_coroutine() {
        uint64_t next_order_to_write = 0;
        while (true) {
            bool all_tasks_processed = false;
            {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                all_tasks_processed = reading_complete_ && (tasks_completed_count_ == next_task_id_);
            }
            if (all_tasks_processed && results_queue_.is_empty()) break;

            std::vector<char> data_to_write = co_await results_queue_.async_pop();

            if (!data_to_write.empty()) {
                try {
                    size_t bytes_written = co_await asio::async_write(output_file_.get(), asio::buffer(data_to_write), asio::use_awaitable);
                } catch (const std::system_error& e) {
                    call_completion_handler(e.code());
                    co_return;
                }

                release_buffer(std::move(data_to_write));

                tasks_completed_count_++;
                next_order_to_write++;
            } else {
                break;
            }
        }

        if (finalization_handler_) {
            co_await finalization_handler_(output_file_);
        }
        call_completion_handler({});
        co_return;
    }

    asio::awaitable<void> reader_coroutine() {
        while (true) {
            if (total_to_read_ > 0 && total_read_ >= total_to_read_) {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                reading_complete_ = true;
                cv_task_.notify_all();
                break;
            }

            size_t to_read_now = std::min(static_cast<size_t>(CHUNK_SIZE), static_cast<size_t>(total_to_read_ - total_read_));
            if (total_to_read_ > 0 && to_read_now == 0) {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                reading_complete_ = true;
                cv_task_.notify_all();
                break;
            }
            if (total_to_read_ == 0) to_read_now = CHUNK_SIZE;

            std::vector<char> chunk = acquire_buffer(to_read_now);

            std::error_code ec;
            // Corrected: Use .get() for async_read_some on SafeStreamDescriptor
            size_t bytes_transferred = co_await input_file_.get().async_read_some(asio::buffer(chunk), asio::redirect_error(asio::use_awaitable, ec));

            if (ec && ec != asio::error::eof) {
                call_completion_handler(ec);
                co_return;
            }

            if (bytes_transferred > 0) {
                total_read_ += bytes_transferred;
                if (chunk.size() != bytes_transferred) {
                    chunk.resize(bytes_transferred);
                }

                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                task_queue_.push({std::move(chunk), next_task_id_++});
                cv_task_.notify_one();
            }

            if (ec == asio::error::eof) {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                reading_complete_ = true;
                cv_task_.notify_all();
                break;
            }
        }
        co_return;
    }

    asio::io_context& io_context_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::vector<std::thread> threads_;
    std::vector<StageFunc> stages_;

    std::mutex log_mutex_;
    std::mutex shared_state_mutex_;

    std::queue<Task> task_queue_;
    std::condition_variable cv_task_;

    AsyncOrderedQueue results_queue_;

    async_file_t input_file_;
    async_file_t output_file_;

    std::function<void(std::error_code)> completion_handler_;
    FinalizationFunc finalization_handler_;

    std::atomic<bool> is_running_;
    std::atomic<bool> reading_complete_;
    std::atomic<uint64_t> next_task_id_;
    std::atomic<uint64_t> tasks_completed_count_;
    std::atomic<bool> completion_handler_called_;

    uintmax_t total_to_read_{0};
    uintmax_t total_read_{0};

    // [修正] 実績のある 64KB に戻す (SysTime削減とキャッシュ効率向上)
    static constexpr size_t CHUNK_SIZE = 1024 * 64;
};
#endif // PIPELINEMANAGER_HPP
