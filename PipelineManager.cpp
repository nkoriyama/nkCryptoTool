#include "PipelineManager.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>

void PipelineManager::run(const std::string& in_path, async_file_t out_file, uintmax_t read_offset, uintmax_t read_size,
                          std::function<void(std::error_code)> completion_handler,
                          FinalizationFunc finalization_handler,
                          std::function<void(double)> progress_callback,
                          uintmax_t total_input_size) {

    output_file_ = std::move(out_file);
    completion_handler_ = completion_handler;
    finalization_handler_ = finalization_handler;
    progress_callback_ = progress_callback;
    total_input_size_ = total_input_size;
    
    if (total_input_size_ > 0 && progress_callback_) {
        next_progress_update_point_ = std::max((uintmax_t)(total_input_size_ / 100), (uintmax_t)(1024 * 128));
    }

    std::error_code ec;
    input_file_.open(in_path, O_RDONLY, ec);
    if (ec) { call_completion_handler(ec); return; }

    if (::lseek(input_file_.native_handle(), (off_t)read_offset, SEEK_SET) == -1) {
        ec.assign(errno, std::system_category());
        call_completion_handler(ec); return;
    }

    total_to_read_ = read_size;
    total_read_ = 0; total_written_ = 0;

    auto self = shared_from_this();
    asio::co_spawn(io_context_, writer_coroutine(self), [this, self](std::exception_ptr p) {
        if (p) call_completion_handler(std::make_error_code(std::errc::io_error));
    });
    asio::co_spawn(io_context_, reader_coroutine(self), [this, self](std::exception_ptr p) {
        if (p) call_completion_handler(std::make_error_code(std::errc::io_error));
    });
}

asio::awaitable<void> PipelineManager::writer_coroutine(std::shared_ptr<PipelineManager> self) {
    try {
        while (true) {
            std::vector<char> data = co_await results_queue_.async_pop();
            if (data.empty()) {
                std::unique_lock<std::mutex> lock(state_mutex_);
                if (reading_complete_ && (tasks_completed_count_ == next_task_id_)) break;
                continue;
            }

            for (const auto& stage : stages_) data = stage(data);

            if (!data.empty()) {
                co_await asio::async_write(output_file_.get(), asio::buffer(data), asio::use_awaitable);
                total_written_ += data.size();
                if (progress_callback_ && total_written_ >= next_progress_update_point_) {
                    progress_callback_(static_cast<double>(total_written_) / total_input_size_);
                    next_progress_update_point_ = total_written_ + (total_input_size_ / 100);
                }
            }
            tasks_completed_count_++;
            // バックプレッシャー解除
            backpressure_timer_.cancel();
        }
        if (finalization_handler_) co_await finalization_handler_(output_file_);
        call_completion_handler({});
    } catch (...) {
        call_completion_handler(std::make_error_code(std::errc::io_error));
    }
}

asio::awaitable<void> PipelineManager::reader_coroutine(std::shared_ptr<PipelineManager> self) {
    try {
        while (is_running_) {
            // バックプレッシャー: キューがいっぱいなら待機
            while (results_queue_.size() >= MAX_QUEUED_TASKS) {
                asio::error_code ec;
                backpressure_timer_.expires_at(std::chrono::steady_clock::time_point::max());
                co_await backpressure_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
            }

            if (total_to_read_ > 0 && total_read_ >= total_to_read_) break;
            uint64_t remaining = (total_to_read_ > 0) ? (total_to_read_ - total_read_) : 0xFFFFFFFFFFFFFFFFULL;
            size_t to_read = static_cast<size_t>(std::min(static_cast<uint64_t>(CHUNK_SIZE), remaining));
            std::vector<char> chunk(to_read);
            std::error_code ec;
            size_t n = co_await asio::async_read(input_file_.get(), asio::buffer(chunk), asio::transfer_at_least(1), asio::redirect_error(asio::use_awaitable, ec));
            
            if (n > 0) {
                total_read_ += n; if (chunk.size() != n) chunk.resize(n);
                results_queue_.push(next_task_id_++, std::move(chunk));
            }
            if (ec == asio::error::eof || (total_to_read_ > 0 && total_read_ >= total_to_read_)) break;
            if (ec) { call_completion_handler(ec); co_return; }
        }
    } catch (...) { call_completion_handler(std::make_error_code(std::errc::io_error)); }
    { std::unique_lock<std::mutex> lock(state_mutex_); reading_complete_ = true; }
    results_queue_.close();
}

void PipelineManager::run_sync(const std::string& in_path, const std::string& out_path, uintmax_t read_offset, uintmax_t read_size) {
    std::ifstream input_file(in_path, std::ios::binary);
    std::ofstream output_file(out_path, std::ios::binary | std::ios::trunc);
    input_file.seekg((off_t)read_offset, std::ios::beg);
    uintmax_t total_read_sync = 0;
    std::vector<char> buffer(CHUNK_SIZE);
    while (total_read_sync < read_size) {
        uintmax_t to_read_now = std::min(static_cast<uintmax_t>(CHUNK_SIZE), read_size - total_read_sync);
        input_file.read(buffer.data(), (std::streamsize)to_read_now);
        std::streamsize bytes_read = input_file.gcount();
        if (bytes_read == 0) break; 
        std::vector<char> data(buffer.data(), buffer.data() + bytes_read);
        for (const auto& stage : stages_) data = stage(data);
        if (!data.empty()) output_file.write(data.data(), (std::streamsize)data.size());
        total_read_sync += bytes_read;
    }
}
