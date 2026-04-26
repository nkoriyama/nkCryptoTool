/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include <benchmark/benchmark.h>
#include "SecureMemory.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <format>
#include <ranges>
#include <asio.hpp>
#include <openssl/provider.h>
#include <openssl/conf.h>
#include <iostream>
#include "nkCryptoToolBase.hpp"
#include "ECCStrategy.hpp"
#include "PQCStrategy.hpp"
#include "HybridStrategy.hpp"

namespace fs = std::filesystem;

// Utility to create dummy files efficiently
void createDummyFile(const std::string& filename, size_t size) {
    if (fs::exists(filename) && fs::file_size(filename) == size) return;
    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    // Use a larger buffer for massive files
    std::vector<char> buffer(1024 * 1024, 'A'); 
    for (size_t i = 0; i < size; i += buffer.size()) {
        ofs.write(buffer.data(), std::min(buffer.size(), size - i));
    }
}

fs::path dummy_data_dir = "./benchmark_data";
fs::path key_dir = "./benchmark_keys";

std::shared_ptr<ICryptoStrategy> CreateStrategy(int mode_val) {
    if (mode_val == 0) return std::make_shared<ECCStrategy>();
    if (mode_val == 1) return std::make_shared<nk::PQCStrategy>();
    return std::make_shared<HybridStrategy>();
}

static void BM_Crypt(benchmark::State& state, int mode_val, bool encrypt) {
    const size_t file_size = static_cast<size_t>(state.range(0));
    
    std::string input_f = (dummy_data_dir / ("input_" + std::to_string(file_size) + ".bin")).string();
    std::string output_f = (dummy_data_dir / "output.tmp").string();

    std::map<std::string, std::string> key_paths;
    if (mode_val == 0) {
        key_paths["recipient-pubkey"] = (key_dir / "public_enc_ecc.key").string();
        key_paths["user-privkey"] = (key_dir / "private_enc_ecc.key").string();
    } else if (mode_val == 1) {
        key_paths["recipient-pubkey"] = (key_dir / "public_enc_pqc.key").string();
        key_paths["user-privkey"] = (key_dir / "private_enc_pqc.key").string();
    } else {
        key_paths["recipient-mlkem-pubkey"] = (key_dir / "public_enc_hybrid_mlkem.key").string();
        key_paths["recipient-ecdh-pubkey"] = (key_dir / "public_enc_hybrid_ecdh.key").string();
        key_paths["recipient-mlkem-privkey"] = (key_dir / "private_enc_hybrid_mlkem.key").string();
        key_paths["recipient-ecdh-privkey"] = (key_dir / "private_enc_hybrid_ecdh.key").string();
    }

    if (!encrypt) {
        nkCryptoToolBase tool(CreateStrategy(mode_val));
        asio::io_context io;
        tool.encryptFileWithPipeline(io, input_f, output_f, key_paths, [](auto){});
        io.run();
        input_f = output_f;
        output_f = (dummy_data_dir / "decrypted.tmp").string();
    }

    SecureString pass = "";
    for (auto _ : state) {
        nkCryptoToolBase tool(CreateStrategy(mode_val));
        asio::io_context io_context;
        std::error_code ec;
        if (encrypt) tool.encryptFileWithPipeline(io_context, input_f, output_f, key_paths, [&](auto err){ ec = err; });
        else tool.decryptFileWithPipeline(io_context, input_f, output_f, key_paths, pass, [&](auto err){ ec = err; });
        io_context.run();
        if (ec) { state.SkipWithError("Operation failed"); break; }
    }
    state.SetBytesProcessed(state.iterations() * file_size);
    if (fs::exists(output_f)) fs::remove(output_f);
}

// Register for various sizes including huge files
#define REGISTER_BM(mode_val, mode_name) \
    BENCHMARK_CAPTURE(BM_Crypt, mode_name##_Enc, mode_val, true)->Unit(benchmark::kMillisecond) \
        ->Arg(1024*1024)->Arg(100*1024*1024)->Arg(1024LL*1024*1024)->Arg(5LL*1024*1024*1024); \
    BENCHMARK_CAPTURE(BM_Crypt, mode_name##_Dec, mode_val, false)->Unit(benchmark::kMillisecond) \
        ->Arg(1024*1024)->Arg(100*1024*1024)->Arg(1024LL*1024*1024)->Arg(5LL*1024*1024*1024);

REGISTER_BM(0, ECC)
REGISTER_BM(1, PQC)
REGISTER_BM(2, Hybrid)

void SetupKeys() {
    fs::create_directories(key_dir);
    SecureString pass = "";
    auto gen = [&](std::shared_ptr<ICryptoStrategy> strategy, const std::string& mode) {
        nkCryptoToolBase tool(std::move(strategy));
        std::map<std::string, std::string> paths;
        if (mode == "hybrid") {
            paths["public-mlkem-key"] = (key_dir / "public_enc_hybrid_mlkem.key").string();
            paths["private-mlkem-key"] = (key_dir / "private_enc_hybrid_mlkem.key").string();
            paths["public-ecdh-key"] = (key_dir / "public_enc_hybrid_ecdh.key").string();
            paths["private-ecdh-key"] = (key_dir / "private_enc_hybrid_ecdh.key").string();
        } else {
            paths["public-key"] = (key_dir / ("public_enc_" + mode + ".key")).string();
            paths["private-key"] = (key_dir / ("private_enc_" + mode + ".key")).string();
        }
        tool.generateEncryptionKeyPair(paths, pass);
    };
    gen(std::make_shared<ECCStrategy>(), "ecc");
    gen(std::make_shared<nk::PQCStrategy>(), "pqc");
    gen(std::make_shared<HybridStrategy>(), "hybrid");
}

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    OSSL_PROVIDER_load(nullptr, "default");
    SetupKeys();
    fs::create_directories(dummy_data_dir);
    
    // Create benchmark files
    std::vector<size_t> sizes = { 1024*1024, 100*1024*1024, 1024LL*1024*1024, 5LL*1024*1024*1024 };
    for (auto s : sizes) {
        std::cout << "Creating dummy file of size " << (s / (1024*1024)) << " MB..." << std::endl;
        createDummyFile((dummy_data_dir / ("input_" + std::to_string(s) + ".bin")).string(), s);
    }
    
    benchmark::RunSpecifiedBenchmarks();
    
    fs::remove_all(dummy_data_dir);
    fs::remove_all(key_dir);
    return 0;
}
