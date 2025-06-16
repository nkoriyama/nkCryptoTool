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
#include <asio.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/internet.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/as_tuple.hpp>

#ifdef _WIN32
#include <asio/stream_file.hpp>
using async_file_t = asio::stream_file;
#else // For Linux/macOS
#include <asio/posix/stream_descriptor.hpp>
#include <fcntl.h>
#include <unistd.h>
using async_file_t = asio::posix::stream_descriptor;
#endif

// --- デバッグ用ロギング機能の前方宣言 ---
// void log_message(const std::string& msg); // 必要に応じて有効化

class PipelineManager : public std::enable_shared_from_this<PipelineManager> {
public:
    using StageFunc = std::function<std::vector<char>(const std::vector<char>&)>;
    using FinalizationFunc = std::function<asio::awaitable<void>()>;

    explicit PipelineManager(asio::io_context& io_context, size_t num_threads = std::thread::hardware_concurrency())
        : io_context_(io_context), threads_(num_threads), input_file_(io_context), output_file_(io_context), is_running_(true), work_in_progress_(0), reading_complete_(false), next_task_id_(0) {
        
        // log_message("PipelineManager created with " + std::to_string(num_threads) + " threads.");
        for (size_t i = 0; i < num_threads; ++i) {
            threads_[i] = std::thread(&PipelineManager::worker_thread, this, i);
        }
    }

    ~PipelineManager() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            is_running_ = false;
        }
        cv_task_.notify_all();
        for (auto& t : threads_) {
            if (t.joinable()) {
                t.join();
            }
        }
        // log_message("PipelineManager destroyed.");
    }

    void add_stage(StageFunc stage) {
        stages_.push_back(std::move(stage));
    }

    void run(const std::string& in_path, const std::string& out_path, uintmax_t read_offset, uintmax_t read_size, std::function<void(std::error_code)> on_complete, FinalizationFunc on_finalize = nullptr) {
        // log_message("Pipeline starting. Input: " + in_path + ", Output: " + out_path);
        completion_handler_ = on_complete;
        finalization_handler_ = std::move(on_finalize);

        std::error_code ec;
#ifdef _WIN32
        input_file_.open(in_path.c_str(), async_file_t::read_only, ec);
#else
        int fd_in = ::open(in_path.c_str(), O_RDONLY);
        if (fd_in == -1) ec.assign(errno, std::system_category()); else input_file_.assign(fd_in, ec);
#endif
        if (ec) {
            // log_message("Failed to open input file: " + ec.message());
            on_complete(ec);
            return;
        }
        // log_message("Input file opened.");

#ifdef _WIN32
        // 出力ファイルは追記ではなく、新規作成または上書きが一般的。ここでは用途に応じて変更が必要。
        // 今回はヘッダーを別で書き込むため追記モード(append)が都合が良い。
        output_file_.open(out_path.c_str(), async_file_t::append | async_file_t::write_only, ec);
#else
        int fd_out = ::open(out_path.c_str(), O_WRONLY | O_APPEND);
        if (fd_out == -1) ec.assign(errno, std::system_category()); else output_file_.assign(fd_out, ec);
#endif
        if (ec) {
            // log_message("Failed to open output file: " + ec.message());
            on_complete(ec);
            return;
        }
        // log_message("Output file opened.");

        input_file_.seek(read_offset, asio::file_base::seek_set, ec);
        if(ec) {
             // log_message("Failed to seek input file: " + ec.message());
             on_complete(ec); return;
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

    void read_next_chunk() {
        if (total_read_ >= total_to_read_) {
            // log_message("Finished reading all data. Total read: " + std::to_string(total_read_));
            std::unique_lock<std::mutex> lock(queue_mutex_);
            reading_complete_ = true;
            cv_task_.notify_all(); // Wake up workers to finish processing
            return;
        }

        size_t to_read_now = std::min(static_cast<size_t>(CHUNK_SIZE), static_cast<size_t>(total_to_read_ - total_read_));
        auto chunk = std::make_shared<std::vector<char>>(to_read_now);
        
        // log_message("Reading next chunk. To read: " + std::to_string(to_read_now));

        input_file_.async_read_some(asio::buffer(*chunk),
            [self = shared_from_this(), chunk](const std::error_code& ec, size_t bytes_transferred) {
                if (ec && ec != asio::error::eof) {
                    // log_message("Read error: " + ec.message());
                    self->completion_handler_(ec);
                    return;
                }
                
                if (bytes_transferred > 0) {
                    // log_message("Read " + std::to_string(bytes_transferred) + " bytes.");
                    self->total_read_ += bytes_transferred;
                    chunk->resize(bytes_transferred);
                    
                    std::unique_lock<std::mutex> lock(self->queue_mutex_);
                    self->work_in_progress_++;
                    self->task_queue_.push({std::move(*chunk), 0, self->next_task_id_++});
                    self->cv_task_.notify_one();
                }

                if (!ec && self->total_read_ < self->total_to_read_) {
                    self->read_next_chunk();
                } else {
                    // log_message("Final read. Error code: " + ec.message() + ", Total read: " + std::to_string(self->total_read_));
                    std::unique_lock<std::mutex> lock(self->queue_mutex_);
                    self->reading_complete_ = true;
                    self->cv_task_.notify_all();
                }
            });
    }


    void worker_thread(size_t thread_id) {
        // log_message("Worker thread " + std::to_string(thread_id) + " started.");
        while (true) {
            Task task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                cv_task_.wait(lock, [this] { return !task_queue_.empty() || !is_running_ || (reading_complete_ && task_queue_.empty()); });
                if ((!is_running_ || reading_complete_) && task_queue_.empty()) break;
                if (task_queue_.empty()) continue;

                task = std::move(task_queue_.front());
                task_queue_.pop();
            }
            
            try {
                // log_message("Thread " + std::to_string(thread_id) + " processing task " + std::to_string(task.original_order));
                std::vector<char> processed_data = stages_[task.stage_index](task.data);
                
                task.data = std::move(processed_data);
                task.stage_index++;

                if (task.stage_index < stages_.size()) {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    task_queue_.push(std::move(task));
                    cv_task_.notify_one();
                } else {
                    std::unique_lock<std::mutex> lock(results_mutex_);
                    results_map_[task.original_order] = std::move(task.data);
                    cv_results_.notify_one();
                }
            } catch (const std::exception& e) {
                // log_message("Exception in worker thread " + std::to_string(thread_id) + ": " + e.what());
                io_context_.post([this, e](){
                    if (completion_handler_) {
                        completion_handler_(std::make_error_code(std::errc::io_error));
                    }
                });
            }
        }
        // log_message("Worker thread " + std::to_string(thread_id) + " finished.");
    }
    
    void start_writer() {
        asio::co_spawn(io_context_, writer_coroutine(), [this](std::exception_ptr p) {
            if (p) {
                try {
                    std::rethrow_exception(p);
                } catch (const std::exception& e) {
                    // log_message("Writer coroutine exception: " + std::string(e.what()));
                    if (completion_handler_) {
                        completion_handler_(std::make_error_code(std::errc::io_error));
                    }
                }
            }
        });
    }

    asio::awaitable<void> writer_coroutine() {
        // log_message("Writer coroutine started.");
        uint64_t next_order_to_write = 0;
        while (true) {
            std::vector<char> data_to_write;
            bool should_break = false;
            {
                std::unique_lock<std::mutex> lock(results_mutex_);
                cv_results_.wait(lock, [this, next_order_to_write] {
                    bool all_tasks_done = reading_complete_ && (work_in_progress_ == 0);
                    return results_map_.count(next_order_to_write) || all_tasks_done;
                });

                auto it = results_map_.find(next_order_to_write);
                if (it != results_map_.end()) {
                    data_to_write = std::move(it->second);
                    results_map_.erase(it);
                } else if (reading_complete_ && work_in_progress_ == 0 && results_map_.empty()) {
                    should_break = true;
                } else {
                    continue;
                }
            }
            
            if (should_break) break;

            if (!data_to_write.empty()) {
                // log_message("Writing chunk " + std::to_string(next_order_to_write) + ", size: " + std::to_string(data_to_write.size()));
                auto [ec, bytes_written] = co_await asio::async_write(output_file_, asio::buffer(data_to_write), asio::as_tuple(asio::use_awaitable));
                if (ec) {
                     // log_message("Write error: " + ec.message());
                    if(completion_handler_) io_context_.post([this, ec]{ completion_handler_(ec); });
                    co_return;
                }
            }
            
            next_order_to_write++;
            work_in_progress_--;
        }

        // 全てのチャンクを書き込んだ後、最終処理を実行
        if (finalization_handler_) {
            // log_message("Executing finalization handler.");
            co_await finalization_handler_();
        }

        // log_message("Writer coroutine finished successfully.");
        if(completion_handler_) {
            io_context_.post([this]{ completion_handler_({}); });
        }
        co_return;
    }

    asio::io_context& io_context_;
    std::vector<std::thread> threads_;
    std::vector<StageFunc> stages_;
    
    std::queue<Task> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_task_;

    std::map<uint64_t, std::vector<char>> results_map_;
    std::mutex results_mutex_;
    std::condition_variable cv_results_;

    async_file_t input_file_;
    async_file_t output_file_;
    
    std::function<void(std::error_code)> completion_handler_;
    FinalizationFunc finalization_handler_;

    std::atomic<bool> is_running_;
    std::atomic<bool> reading_complete_;
    std::atomic<uint64_t> next_task_id_;
    
    std::atomic<uint64_t> work_in_progress_;
    uintmax_t total_to_read_{0};
    uintmax_t total_read_{0};
    
    static constexpr size_t CHUNK_SIZE = 1024 * 64; // 64 KB
};

#endif // PIPELINEMANAGER_HPP