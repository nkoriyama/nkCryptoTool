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
#include "nkCryptoToolECC.hpp"
#include "nkCryptoToolPQC.hpp"

// ダミーファイルを作成するヘルパー関数
void createDummyFile(const std::string& filename, size_t size) {
    std::filesystem::path p(filename);
    if (std::filesystem::exists(p) && std::filesystem::file_size(p) == size) {
        // File already exists and has the correct size, skip creation
        return;
    }

    std::ofstream ofs(filename, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        throw std::runtime_error(std::format("Failed to create dummy file: {}", filename));
    }
    std::vector<char> buffer(1024, 'A');
    for (size_t i = 0; i < size; i += buffer.size()) {
        ofs.write(buffer.data(), std::min(buffer.size(), size - i));
    }
}

// Global variables for dummy files
std::vector<size_t> dummy_file_sizes = {
    1024,
    1024 * 1024,
    1024 * 1024 * 10,
    6719094784
    // Removed 6719094784 to prevent long setup time
};
std::filesystem::path dummy_input_files_dir = "./benchmark_data";
std::map<size_t, std::string> dummy_input_file_paths;

// 簡単なベンチマークの例
static void BM_StringCreation(benchmark::State& state) {
  for (auto _ : state) {
    std::string s("hello");
  }
}
// ベンチマークを登録
BENCHMARK(BM_StringCreation);

static void BM_StringCopy(benchmark::State& state) {
  std::string s1 = "hello";
  for (auto _ : state) {
    std::string s2 = s1;
  }
}
BENCHMARK(BM_StringCopy);

// 暗号化ベンチマーク
static void BM_Encryption(benchmark::State& state) {
    const size_t file_size = state.range(0);
    const std::string mode = state.range(1) == 0 ? "ecc" : (state.range(1) == 1 ? "pqc" : "hybrid");

    std::filesystem::path key_dir = "./benchmark_keys";
    std::string input_filename = dummy_input_file_paths[file_size];
    std::string encrypted_filename = (dummy_input_files_dir / ("encrypted_" + std::to_string(file_size) + ".enc")).string();

    std::unique_ptr<nkCryptoToolBase> crypto_handler;
    if (mode == "ecc") {
        crypto_handler = std::make_unique<nkCryptoToolECC>();
    } else if (mode == "pqc" || mode == "hybrid") {
        crypto_handler = std::make_unique<nkCryptoToolPQC>();
    }
    crypto_handler->setKeyBaseDirectory(key_dir);

    asio::io_context io_context;

    for (auto _ : state) {
        state.PauseTiming();
        // Ensure the output file does not exist from a previous failed iteration
        std::filesystem::remove(encrypted_filename);
        state.ResumeTiming();
        
        io_context.restart();

        std::map<std::string, std::string> key_paths;
        if (mode == "hybrid") {
            key_paths["recipient-mlkem-pubkey"] = (key_dir / "public_enc_hybrid_mlkem.key").string();
            key_paths["recipient-ecdh-pubkey"] = (key_dir / "public_enc_hybrid_ecdh.key").string();
        } else if (mode == "ecc") {
            key_paths["recipient-pubkey"] = (key_dir / "public_enc_ecc.key").string();
        } else if (mode == "pqc") {
            key_paths["recipient-pubkey"] = (key_dir / "public_enc_pqc.key").string();
        }

        std::error_code ec;
        crypto_handler->encryptFileWithPipeline(io_context, input_filename, encrypted_filename, key_paths, [&](std::error_code err){ ec = err; });
        io_context.run();
        
        if (ec) {
            state.SkipWithError(("Encryption failed: " + ec.message()).c_str());
            // Do not break here, let the benchmark framework handle stopping.
        }
        
        state.PauseTiming();
        std::filesystem::remove(encrypted_filename); // Remove encrypted file after each iteration
        state.ResumeTiming();
    }
    // input_filename is a dummy file, no need to remove here
    // encrypted_filename is removed inside the loop
}

// 復号ベンチマーク
static void BM_Decryption(benchmark::State& state) {
    const size_t file_size = state.range(0);
    const std::string mode = state.range(1) == 0 ? "ecc" : (state.range(1) == 1 ? "pqc" : "hybrid");

    std::filesystem::path key_dir = "./benchmark_keys";
    std::string input_filename = dummy_input_file_paths[file_size];
    std::string encrypted_filename = (dummy_input_files_dir / ("encrypted_" + std::to_string(file_size) + ".enc")).string();
    std::string decrypted_filename = (dummy_input_files_dir / ("decrypted_" + std::to_string(file_size) + ".bin")).string();

    // Setup: Create an encrypted file to be used by all iterations
    { 
        std::unique_ptr<nkCryptoToolBase> crypto_handler_enc;
        if (mode == "ecc") {
            crypto_handler_enc = std::make_unique<nkCryptoToolECC>();
        } else if (mode == "pqc" || mode == "hybrid") {
            crypto_handler_enc = std::make_unique<nkCryptoToolPQC>();
        }
        crypto_handler_enc->setKeyBaseDirectory(key_dir);

        std::map<std::string, std::string> enc_key_paths;
        if (mode == "hybrid") {
            enc_key_paths["recipient-mlkem-pubkey"] = (key_dir / "public_enc_hybrid_mlkem.key").string();
            enc_key_paths["recipient-ecdh-pubkey"] = (key_dir / "public_enc_hybrid_ecdh.key").string();
        } else if (mode == "ecc") {
            enc_key_paths["recipient-pubkey"] = (key_dir / "public_enc_ecc.key").string();
        } else if (mode == "pqc") {
            enc_key_paths["recipient-pubkey"] = (key_dir / "public_enc_pqc.key").string();
        }

        asio::io_context enc_io_context;
        std::error_code enc_ec;
        crypto_handler_enc->encryptFileWithPipeline(enc_io_context, input_filename, encrypted_filename, enc_key_paths, [&](std::error_code err){ enc_ec = err; });
        enc_io_context.run();
        
        if (enc_ec) {
            std::filesystem::remove(encrypted_filename);
            state.SkipWithError(("Setup Encryption failed: " + enc_ec.message()).c_str());
            return;
        }
    } 

    std::unique_ptr<nkCryptoToolBase> crypto_handler_dec;
    if (mode == "ecc") {
        crypto_handler_dec = std::make_unique<nkCryptoToolECC>();
    } else if (mode == "pqc" || mode == "hybrid") {
        crypto_handler_dec = std::make_unique<nkCryptoToolPQC>();
    }
    crypto_handler_dec->setKeyBaseDirectory(key_dir);

    asio::io_context io_context;

    for (auto _ : state) {
        state.PauseTiming();
        // Ensure the output file does not exist from a previous failed iteration
        std::filesystem::remove(decrypted_filename);
        state.ResumeTiming();

        io_context.restart();

        std::map<std::string, std::string> dec_key_paths;
        if (mode == "hybrid") {
            dec_key_paths["recipient-mlkem-privkey"] = (key_dir / "private_enc_hybrid_mlkem.key").string();
            dec_key_paths["recipient-ecdh-privkey"] = (key_dir / "private_enc_hybrid_ecdh.key").string();
        } else if (mode == "ecc") {
            dec_key_paths["user-privkey"] = (key_dir / "private_enc_ecc.key").string();
        } else if (mode == "pqc") {
            dec_key_paths["user-privkey"] = (key_dir / "private_enc_pqc.key").string();
        }

        std::error_code ec;
        crypto_handler_dec->decryptFileWithPipeline(io_context, encrypted_filename, decrypted_filename, dec_key_paths, [&](std::error_code err){ ec = err; });
        io_context.run();
        
        if (ec) {
            state.SkipWithError(("Decryption failed: " + ec.message()).c_str());
            // Do not break here, let the benchmark framework handle stopping.
        }
        
        state.PauseTiming();
        std::filesystem::remove(decrypted_filename); // Remove decrypted file after each iteration
        state.ResumeTiming();
    }
    std::filesystem::remove(encrypted_filename); // Remove encrypted file after all iterations
}


// 同期暗号化ベンチマーク
static void BM_EncryptionSync(benchmark::State& state) {
    const size_t file_size = state.range(0);
    const std::string mode = state.range(1) == 0 ? "ecc" : (state.range(1) == 1 ? "pqc" : "hybrid");

    std::filesystem::path key_dir = "./benchmark_keys";
    std::string input_filename = dummy_input_file_paths[file_size];
    std::string encrypted_filename = (dummy_input_files_dir / ("encrypted_" + std::to_string(file_size) + ".enc")).string();

    std::unique_ptr<nkCryptoToolBase> crypto_handler;
    if (mode == "ecc") {
        crypto_handler = std::make_unique<nkCryptoToolECC>();
    } else if (mode == "pqc" || mode == "hybrid") {
        crypto_handler = std::make_unique<nkCryptoToolPQC>();
    }
    crypto_handler->setKeyBaseDirectory(key_dir);

    for (auto _ : state) {
        state.PauseTiming();
        std::filesystem::remove(encrypted_filename);
        state.ResumeTiming();
        
        std::map<std::string, std::string> key_paths;
        if (mode == "hybrid") {
            key_paths["recipient-mlkem-pubkey"] = (key_dir / "public_enc_hybrid_mlkem.key").string();
            key_paths["recipient-ecdh-pubkey"] = (key_dir / "public_enc_hybrid_ecdh.key").string();
        } else if (mode == "ecc") {
            key_paths["recipient-pubkey"] = (key_dir / "public_enc_ecc.key").string();
        } else if (mode == "pqc") {
            key_paths["recipient-pubkey"] = (key_dir / "public_enc_pqc.key").string();
        }

        try {
            crypto_handler->encryptFileWithSync(input_filename, encrypted_filename, key_paths);
        } catch (const std::exception& e) {
            state.SkipWithError(("Sync encryption failed: " + std::string(e.what())).c_str());
        }
        
        state.PauseTiming();
        std::filesystem::remove(encrypted_filename);
        state.ResumeTiming();
    }
}

// 同期復号ベンチマーク
static void BM_DecryptionSync(benchmark::State& state) {
    const size_t file_size = state.range(0);
    const std::string mode = state.range(1) == 0 ? "ecc" : (state.range(1) == 1 ? "pqc" : "hybrid");

    std::filesystem::path key_dir = "./benchmark_keys";
    std::string input_filename = dummy_input_file_paths[file_size];
    std::string encrypted_filename = (dummy_input_files_dir / ("encrypted_" + std::to_string(file_size) + ".enc")).string();
    std::string decrypted_filename = (dummy_input_files_dir / ("decrypted_" + std::to_string(file_size) + ".bin")).string();

    // Setup
    {
        std::unique_ptr<nkCryptoToolBase> crypto_handler_enc;
        if (mode == "ecc") {
            crypto_handler_enc = std::make_unique<nkCryptoToolECC>();
        } else if (mode == "pqc" || mode == "hybrid") {
            crypto_handler_enc = std::make_unique<nkCryptoToolPQC>();
        }
        crypto_handler_enc->setKeyBaseDirectory(key_dir);
        std::map<std::string, std::string> enc_key_paths;
        if (mode == "hybrid") {
            enc_key_paths["recipient-mlkem-pubkey"] = (key_dir / "public_enc_hybrid_mlkem.key").string();
            enc_key_paths["recipient-ecdh-pubkey"] = (key_dir / "public_enc_hybrid_ecdh.key").string();
        } else if (mode == "ecc") {
            enc_key_paths["recipient-pubkey"] = (key_dir / "public_enc_ecc.key").string();
        } else if (mode == "pqc") {
            enc_key_paths["recipient-pubkey"] = (key_dir / "public_enc_pqc.key").string();
        }
        crypto_handler_enc->encryptFileWithSync(input_filename, encrypted_filename, enc_key_paths);
    }

    std::unique_ptr<nkCryptoToolBase> crypto_handler_dec;
    if (mode == "ecc") {
        crypto_handler_dec = std::make_unique<nkCryptoToolECC>();
    } else if (mode == "pqc" || mode == "hybrid") {
        crypto_handler_dec = std::make_unique<nkCryptoToolPQC>();
    }
    crypto_handler_dec->setKeyBaseDirectory(key_dir);

    for (auto _ : state) {
        state.PauseTiming();
        std::filesystem::remove(decrypted_filename);
        state.ResumeTiming();

        std::map<std::string, std::string> dec_key_paths;
        if (mode == "hybrid") {
            dec_key_paths["recipient-mlkem-privkey"] = (key_dir / "private_enc_hybrid_mlkem.key").string();
            dec_key_paths["recipient-ecdh-privkey"] = (key_dir / "private_enc_hybrid_ecdh.key").string();
        } else if (mode == "ecc") {
            dec_key_paths["user-privkey"] = (key_dir / "private_enc_ecc.key").string();
        } else if (mode == "pqc") {
            dec_key_paths["user-privkey"] = (key_dir / "private_enc_pqc.key").string();
        }

        try {
            crypto_handler_dec->decryptFileWithSync(encrypted_filename, decrypted_filename, dec_key_paths);
        } catch (const std::exception& e) {
            state.SkipWithError(("Sync decryption failed: " + std::string(e.what())).c_str());
        }
        
        state.PauseTiming();
        std::filesystem::remove(decrypted_filename);
        state.ResumeTiming();
    }
    std::filesystem::remove(encrypted_filename);
}


// ベンチマークの登録
BENCHMARK(BM_Encryption)->Args({1024, 0})->Args({1024, 1})->Args({1024, 2})->Repetitions(1); // 1KB, ECC, PQC, Hybrid
BENCHMARK(BM_Decryption)->Args({1024, 0})->Args({1024, 1})->Args({1024, 2})->Repetitions(1); // 1KB, ECC, PQC, Hybrid

BENCHMARK(BM_EncryptionSync)->Args({1024, 0})->Args({1024, 1})->Args({1024, 2})->Repetitions(1);
BENCHMARK(BM_DecryptionSync)->Args({1024, 0})->Args({1024, 1})->Args({1024, 2})->Repetitions(1);

BENCHMARK(BM_Encryption)->Args({1024 * 1024, 0})->Args({1024 * 1024, 1})->Args({1024 * 1024, 2})->Repetitions(1); // 1MB, ECC, PQC, Hybrid
BENCHMARK(BM_Decryption)->Args({1024 * 1024, 0})->Args({1024 * 1024, 1})->Args({1024 * 1024, 2})->Repetitions(1); // 1MB, ECC, PQC, Hybrid

BENCHMARK(BM_EncryptionSync)->Args({1024 * 1024, 0})->Args({1024 * 1024, 1})->Args({1024 * 1024, 2})->Repetitions(1);
BENCHMARK(BM_DecryptionSync)->Args({1024 * 1024, 0})->Args({1024 * 1024, 1})->Args({1024 * 1024, 2})->Repetitions(1);

BENCHMARK(BM_Encryption)->Args({1024 * 1024 * 10, 0})->Args({1024 * 1024 * 10, 1})->Args({1024 * 1024 * 10, 2})->Repetitions(1); // 10MB, ECC, PQC, Hybrid
BENCHMARK(BM_Decryption)->Args({1024 * 1024 * 10, 0})->Args({1024 * 1024 * 10, 1})->Args({1024 * 1024 * 10, 2})->Repetitions(1); // 10MB, ECC, PQC, Hybrid

BENCHMARK(BM_EncryptionSync)->Args({1024 * 1024 * 10, 0})->Args({1024 * 1024 * 10, 1})->Args({1024 * 1024 * 10, 2})->Repetitions(1);
BENCHMARK(BM_DecryptionSync)->Args({1024 * 1024 * 10, 0})->Args({1024 * 1024 * 10, 1})->Args({1024 * 1024 * 10, 2})->Repetitions(1);

BENCHMARK(BM_Encryption)->Args({6719094784, 0})->Args({6719094784, 1})->Args({6719094784, 2})->Repetitions(1); // ~6.7GB, ECC, PQC, Hybrid
BENCHMARK(BM_Decryption)->Args({6719094784, 0})->Args({6719094784, 1})->Args({6719094784, 2})->Repetitions(1); // ~6.7GB, ECC, PQC, Hybrid

BENCHMARK(BM_EncryptionSync)->Args({6719094784, 0})->Args({6719094784, 1})->Args({6719094784, 2})->Repetitions(1);
BENCHMARK(BM_DecryptionSync)->Args({6719094784, 0})->Args({6719094784, 1})->Args({6719094784, 2})->Repetitions(1);

// Function to setup dummy files
void SetupDummyFiles() {
    std::filesystem::create_directories(dummy_input_files_dir);
    std::ranges::for_each(dummy_file_sizes, [&](size_t size) {
        std::string filename = (dummy_input_files_dir / ("input_" + std::to_string(size) + ".bin")).string();
        createDummyFile(filename, size);
        dummy_input_file_paths[size] = filename;
        std::cout << "Created dummy file: " << filename << " (" << size << " bytes)" << std::endl << std::flush;
    });
}

// Function to teardown dummy files
void TeardownDummyFiles() {
    std::filesystem::remove_all(dummy_input_files_dir);
    std::cout << "Removed dummy files." << std::endl << std::flush;
}

// ベンチマーク実行前にキーペアを生成するセットアップ関数
void SetupKeys() {
    std::filesystem::path key_dir = "./benchmark_keys";
    std::filesystem::create_directories(key_dir);

    nkCryptoToolECC ecc_handler;
    ecc_handler.setKeyBaseDirectory(key_dir);
    if (ecc_handler.generateEncryptionKeyPair(ecc_handler.getEncryptionPublicKeyPath(), ecc_handler.getEncryptionPrivateKeyPath(), "")) {
        std::cout << "ECC keys generated successfully." << std::endl << std::flush;
    } else {
        std::cerr << "Error: Failed to generate ECC keys." << std::endl << std::flush;
        nkCryptoToolBase::printOpenSSLErrors();
    }

    nkCryptoToolPQC pqc_handler;
    pqc_handler.setKeyBaseDirectory(key_dir);
    try {
        if (pqc_handler.generateEncryptionKeyPair(pqc_handler.getEncryptionPublicKeyPath(), pqc_handler.getEncryptionPrivateKeyPath(), "")) {
            std::cout << "PQC keys generated successfully." << std::endl << std::flush;
        } else {
            std::cerr << "Error: Failed to generate PQC keys." << std::endl << std::flush;
            nkCryptoToolBase::printOpenSSLErrors();
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Caught exception during PQC key generation: " << e.what() << std::endl << std::flush;
        nkCryptoToolBase::printOpenSSLErrors();
        throw;
    }

    // Hybridモード用のキーペアも生成 (PQCとECCの組み合わせ)
    // PQCはML-KEM、ECCはECDHとして扱う
    try {
        if (pqc_handler.generateEncryptionKeyPair(key_dir / "public_enc_hybrid_mlkem.key", key_dir / "private_enc_hybrid_mlkem.key", "")) {
            std::cout << "Hybrid ML-KEM keys generated successfully." << std::endl << std::flush;
        } else {
            std::cerr << "Error: Failed to generate Hybrid ML-KEM keys." << std::endl << std::flush;
            nkCryptoToolBase::printOpenSSLErrors();
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Caught exception during Hybrid ML-KEM key generation: " << e.what() << std::endl << std::flush;
        nkCryptoToolBase::printOpenSSLErrors();
        throw;
    }
    if (ecc_handler.generateEncryptionKeyPair(key_dir / "public_enc_hybrid_ecdh.key", key_dir / "private_enc_hybrid_ecdh.key", "")) {
        std::cout << "Hybrid ECDH keys generated successfully." << std::endl << std::flush;
    } else {
        std::cerr << "Error: Failed to generate Hybrid ECDH keys." << std::endl << std::flush;
        nkCryptoToolBase::printOpenSSLErrors();
    }
}

// ベンチマーク実行後にキーペアをクリーンアップするティアダウン関数
void TeardownKeys() {
    std::filesystem::remove_all("./benchmark_keys");
    OSSL_PROVIDER_unload(nullptr);
}

// ベンチマークのメイン関数
int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);
    OSSL_PROVIDER_load(nullptr, "default"); // 既存
    // OSSL_PROVIDER_load(nullptr, "oqsprovider"); // 追加
    SetupKeys();
    SetupDummyFiles();
    if (benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    benchmark::RunSpecifiedBenchmarks();
    TeardownDummyFiles();
    TeardownKeys();
    return 0;
}
