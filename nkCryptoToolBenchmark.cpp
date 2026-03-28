#include <benchmark/benchmark.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <format>
#include <ranges>
#include <asio.hpp>
#include <openssl/provider.h>
#include <openssl/conf.h>
#include "nkCryptoToolBase.hpp"
#include "ECCStrategy.hpp"
#include "PQCStrategy.hpp"

void createDummyFile(const std::string& filename, size_t size) {
    std::filesystem::path p(filename);
    if (std::filesystem::exists(p) && std::filesystem::file_size(p) == size) return;
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    std::vector<char> buffer(1024 * 64, 'A');
    for (size_t i = 0; i < size; i += buffer.size()) {
        ofs.write(buffer.data(), std::min(buffer.size(), size - i));
    }
}

std::vector<size_t> dummy_file_sizes = { 1024, 1024 * 1024, 1024 * 1024 * 10 };
std::filesystem::path dummy_input_files_dir = "./benchmark_data";
std::map<size_t, std::string> dummy_input_file_paths;

static void BM_Encryption(benchmark::State& state) {
    const size_t file_size = state.range(0);
    const std::string mode = state.range(1) == 0 ? "ecc" : "pqc";

    std::filesystem::path key_dir = "./benchmark_keys";
    std::string input_filename = dummy_input_file_paths[file_size];
    std::string encrypted_filename = (dummy_input_files_dir / ("encrypted_" + std::to_string(file_size) + ".enc")).string();

    std::unique_ptr<ICryptoStrategy> strategy;
    if (mode == "ecc") strategy = std::make_unique<ECCStrategy>();
    else strategy = std::make_unique<PQCStrategy>();
    
    nkCryptoToolBase tool(std::move(strategy));
    asio::io_context io_context;

    for (auto _ : state) {
        state.PauseTiming();
        std::filesystem::remove(encrypted_filename);
        state.ResumeTiming();
        io_context.restart();

        std::map<std::string, std::string> key_paths;
        if (mode == "ecc") key_paths["recipient-pubkey"] = (key_dir / "public_enc_ecc.key").string();
        else key_paths["recipient-pubkey"] = (key_dir / "public_enc_pqc.key").string();

        std::error_code ec;
        tool.encryptFileWithPipeline(io_context, input_filename, encrypted_filename, key_paths, [&](std::error_code err){ ec = err; });
        io_context.run();
        
        if (ec) state.SkipWithError("Encryption failed");
        
        state.PauseTiming();
        std::filesystem::remove(encrypted_filename);
        state.ResumeTiming();
    }
}

BENCHMARK(BM_Encryption)->Args({1024, 0})->Args({1024, 1});
BENCHMARK(BM_Encryption)->Args({1024 * 1024, 0})->Args({1024 * 1024, 1});

void SetupKeys() {
    std::filesystem::path key_dir = "./benchmark_keys";
    std::filesystem::create_directories(key_dir);
    std::string pass = "";

    nkCryptoToolBase ecc_tool(std::make_unique<ECCStrategy>());
    std::map<std::string, std::string> ecc_paths = {{"public-key", (key_dir / "public_enc_ecc.key").string()}, {"private-key", (key_dir / "private_enc_ecc.key").string()}};
    ecc_tool.generateEncryptionKeyPair(ecc_paths, pass);

    nkCryptoToolBase pqc_tool(std::make_unique<PQCStrategy>());
    std::map<std::string, std::string> pqc_paths = {{"public-key", (key_dir / "public_enc_pqc.key").string()}, {"private-key", (key_dir / "private_enc_pqc.key").string()}};
    pqc_tool.generateEncryptionKeyPair(pqc_paths, pass);
}

void SetupDummyFiles() {
    std::filesystem::create_directories(dummy_input_files_dir);
    for(auto size : dummy_file_sizes) {
        std::string filename = (dummy_input_files_dir / ("input_" + std::to_string(size) + ".bin")).string();
        createDummyFile(filename, size);
        dummy_input_file_paths[size] = filename;
    }
}

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    OSSL_PROVIDER_load(nullptr, "default");
    SetupKeys();
    SetupDummyFiles();
    benchmark::RunSpecifiedBenchmarks();
    std::filesystem::remove_all(dummy_input_files_dir);
    std::filesystem::remove_all("./benchmark_keys");
    return 0;
}
