#include "PipelineManager.hpp"
#include <fstream>
#include <iostream>

void PipelineManager::run_sync(
    const std::string& in_path, 
    const std::string& out_path, 
    uintmax_t read_offset, 
    uintmax_t read_size) {

    std::ifstream input_file(in_path, std::ios::binary);
    if (!input_file) {
        throw std::runtime_error("Failed to open input file: " + in_path);
    }

    std::ofstream output_file(out_path, std::ios::binary | std::ios::trunc);
    if (!output_file) {
        throw std::runtime_error("Failed to open output file: " + out_path);
    }

    input_file.seekg(read_offset, std::ios::beg);

    uintmax_t total_read = 0;
    std::vector<char> buffer(CHUNK_SIZE);

    while (total_read < read_size) {
        uintmax_t to_read_now = std::min(static_cast<uintmax_t>(CHUNK_SIZE), read_size - total_read);
        input_file.read(buffer.data(), to_read_now);
        std::streamsize bytes_read = input_file.gcount();
        
        if (bytes_read == 0) {
            break; 
        }

        std::vector<char> data(buffer.data(), buffer.data() + bytes_read);

        for (const auto& stage : stages_) {
            data = stage(data);
        }

        if (!data.empty()) {
            output_file.write(data.data(), data.size());
        }

        total_read += bytes_read;
    }
}
