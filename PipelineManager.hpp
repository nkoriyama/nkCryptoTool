// PipelineManager.hpp
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
#include <string>
#include <filesystem>
#include <sstream>
#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>

#include <asio/steady_timer.hpp>

#ifdef _WIN32
#include <asio/stream_file.hpp>
using async_file_t = asio::stream_file;
#else // For Linux/macOS
#include <asio/posix/stream_descriptor.hpp>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h> // For fstat()
using async_file_t = asio::posix::stream_descriptor;
#endif

class PipelineManager : public std::enable_shared_from_this<PipelineManager> {
public:
    using StageFunc = std::function<std::vector<char>(const std::vector<char>&)>;
    using FinalizationFunc = std::function<asio::awaitable<void>(async_file_t)>;

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
          completion_handler_called_(false)
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
        log_message("Output file handle received.");

        std::error_code ec;
#ifdef _WIN32
        input_file_.open(in_path.c_str(), async_file_t::read_only, ec);
#else
        int fd_in = ::open(in_path.c_str(), O_RDONLY);
        if (fd_in == -1) ec.assign(errno, std::system_category()); else input_file_.assign(fd_in, ec);
#endif
        if (ec) {
            log_message("Failed to open input file: " + ec.message());
            call_completion_handler(ec);
            return;
        }
        log_message("Input file opened.");

#ifdef _WIN32
        input_file_.seek(read_offset, asio::file_base::seek_set, ec);
#else
        if (::lseek(input_file_.native_handle(), read_offset, SEEK_SET) == -1) {
            ec.assign(errno, std::system_category());
        }
#endif
        if(ec) {
             log_message("Failed to seek input file: " + ec.message());
             call_completion_handler(ec); return;
        }

        total_to_read_ = read_size;
        total_read_ = 0;
        
        start_writer();
        read_next_chunk();
    }

private:
    struct Task {
        std::vector<char> data;
        size_t stage_index;
        uint64_t original_order;
    };

    void log_message(const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex_);
#if defined (DETAIL_LOG)
        std::stringstream ss;
        ss << "[TID:" << std::this_thread::get_id() << "] " << msg << "\n";
        std::cout << ss.str();
        std::cout.flush(); // Ensure logs are visible immediately
#endif
    }

    void call_completion_handler(const std::error_code& ec) {
        bool already_called = completion_handler_called_.exchange(true);
        if (!already_called) {
            log_message("Calling completion handler with code: " + ec.message());
            asio::post(io_context_, [this, ec]() {
                if (completion_handler_) {
                    completion_handler_(ec);
                }
                work_guard_.reset();
            });
        }
    }

    void read_next_chunk() {
        if (total_to_read_ > 0 && total_read_ >= total_to_read_) {
            log_message("Finished reading all data. Total read: " + std::to_string(total_read_));
            std::unique_lock<std::mutex> lock(shared_state_mutex_);
            reading_complete_ = true;
            cv_task_.notify_all();
            return;
        }

        size_t to_read_now = std::min(static_cast<size_t>(CHUNK_SIZE), static_cast<size_t>(total_to_read_ - total_read_));
        if (total_to_read_ > 0 && to_read_now == 0) {
             log_message("Finished reading specified size.");
            std::unique_lock<std::mutex> lock(shared_state_mutex_);
            reading_complete_ = true;
            cv_task_.notify_all();
            return;
        }
        if (total_to_read_ == 0) {
            to_read_now = CHUNK_SIZE;
        }

        auto chunk = std::make_shared<std::vector<char>>(to_read_now);
        
        log_message("Reading next chunk. To read: " + std::to_string(to_read_now));
        input_file_.async_read_some(asio::buffer(*chunk),
            [this, self = shared_from_this(), chunk](const std::error_code& ec, size_t bytes_transferred) {
                if (ec && ec != asio::error::eof) {
                    log_message("Read error: " + ec.message());
                    self->call_completion_handler(ec);
                    return;
                }
                
                if (bytes_transferred > 0) {
                    log_message("Read " + std::to_string(bytes_transferred) + " bytes.");
                    self->total_read_ += bytes_transferred;
                    chunk->resize(bytes_transferred);
                    
                    std::unique_lock<std::mutex> lock(self->shared_state_mutex_);
                    self->task_queue_.push({std::move(*chunk), 0, self->next_task_id_++});
                    self->cv_task_.notify_one();
                }

                if (!ec) {
                    self->read_next_chunk();
                } else { // EOF
                    log_message("Final read (EOF). Total read: " + std::to_string(self->total_read_));
                    std::unique_lock<std::mutex> lock(self->shared_state_mutex_);
                    self->reading_complete_ = true;
                    self->cv_task_.notify_all();
                }
            });
    }

    void worker_thread(size_t thread_id) {
        log_message("Worker thread " + std::to_string(thread_id) + " started.");
        while (is_running_) {
            Task task;
            {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                cv_task_.wait(lock, [this] { return !task_queue_.empty() || !is_running_; });
                if (!is_running_) break;
                if (task_queue_.empty()) continue;

                task = std::move(task_queue_.front());
                task_queue_.pop();
                log_message("Worker " + std::to_string(thread_id) + " picked up task " + std::to_string(task.original_order));
            }
            
            try {
                std::vector<char> processed_data = stages_[task.stage_index](task.data);
                task.data = std::move(processed_data);
                task.stage_index++;

                if (task.stage_index < stages_.size()) {
                    std::unique_lock<std::mutex> lock(shared_state_mutex_);
                    task_queue_.push(std::move(task));
                    cv_task_.notify_one();
                } else {
                    std::unique_lock<std::mutex> lock(shared_state_mutex_);
                    results_map_[task.original_order] = std::move(task.data);
                }
            } catch (const std::exception& e) {
                log_message("Exception in worker thread " + std::to_string(thread_id) + ": " + e.what());
                call_completion_handler(std::make_error_code(std::errc::io_error));
            }
        }
        log_message("Worker thread " + std::to_string(thread_id) + " finished.");
    }
    
    void start_writer() {
        asio::co_spawn(io_context_, writer_coroutine(), [this, self = shared_from_this()](std::exception_ptr p) {
            if (p) {
                try {
                    std::rethrow_exception(p);
                } catch (const std::exception& e) {
                    log_message("Writer coroutine exception: " + std::string(e.what()));
                    self->call_completion_handler(std::make_error_code(std::errc::io_error));
                }
            }
        });
    }

    asio::awaitable<void> writer_coroutine() {
        log_message("Writer starting.");
        uint64_t next_order_to_write = 0;
        asio::steady_timer timer(io_context_);

        while (true) {
            bool is_finished = false;
            {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                is_finished = reading_complete_ && (tasks_completed_count_ == next_task_id_);
            }
            if (is_finished) {
                 log_message("Writer detected completion. Total tasks written: " + std::to_string(tasks_completed_count_));
                 break;
            }

            std::vector<char> data_to_write;
            {
                std::unique_lock<std::mutex> lock(shared_state_mutex_);
                auto it = results_map_.find(next_order_to_write);
                if (it != results_map_.end()) {
                    data_to_write = std::move(it->second);
                    results_map_.erase(it);
                }
            }

            if (!data_to_write.empty()) {
                log_message("Writer writing chunk " + std::to_string(next_order_to_write));
                try {
                    size_t bytes_written = co_await asio::async_write(output_file_, asio::buffer(data_to_write), asio::use_awaitable);
                    log_message("Writer finished writing chunk " + std::to_string(next_order_to_write) + " (" + std::to_string(bytes_written) + " bytes)");
                } catch (const std::system_error& e) {
                    log_message("Writer ERROR: " + std::string(e.what()));
                    call_completion_handler(e.code());
                    co_return;
                }
                tasks_completed_count_++;
                next_order_to_write++;
            } else {
                timer.expires_after(std::chrono::milliseconds(10));
                co_await timer.async_wait(asio::use_awaitable);
            }
        }

        log_message("Writer proceeding to finalization.");
        if (finalization_handler_) {
            co_await finalization_handler_(std::move(output_file_));
        }

        log_message("Writer finished successfully.");
        call_completion_handler({});
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

    std::map<uint64_t, std::vector<char>> results_map_;
    
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
    
    static constexpr size_t CHUNK_SIZE = 1024 * 64; // 64 KB
};

#endif // PIPELINEMANAGER_HPP