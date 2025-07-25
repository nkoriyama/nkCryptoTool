
#include <benchmark/benchmark.h>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <filesystem>
#include <asio.hpp>
#include <cxxopts.hpp>
#include <openssl/provider.h>

#include "../nkCryptoToolBase.hpp"
#include "../nkCryptoToolECC.hpp"
#include "../nkCryptoToolPQC.hpp"

int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    return 0;
}

// =============================================================================
//  ベンチマーク用のフィクスチャ
// =============================================================================

class CryptoBenchmark : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) override {
        // OpenSSLプロバイダーのロード
        OSSL_PROVIDER_load(nullptr, "default");

        // テスト用のファイルと鍵のパスを設定
        m_largeFileName = "large_test_file.bin";
        m_encryptedFileName = "large_test_file.bin.enc";
        m_decryptedFileName = "large_test_file.bin.dec";

        m_mlkem_pub_key = "mlkem.pub";
        m_mlkem_priv_key = "mlkem.priv";
        m_ecdh_pub_key = "ecdh.pub";
        m_ecdh_priv_key = "ecdh.priv";

        // 6408 MiB (approx. 6.4 GB) のランダムなデータを持つテストファイルを作成
        createLargeFile(m_largeFileName, 6408);

        // 鍵ペアの生成
        generateKeys();
    }

    void TearDown(const ::benchmark::State& state) override {
        // 作成したファイルをすべて削除
        std::filesystem::remove(m_largeFileName);
        std::filesystem::remove(m_encryptedFileName);
        std::filesystem::remove(m_decryptedFileName);
        std::filesystem::remove(m_mlkem_pub_key);
        std::filesystem::remove(m_mlkem_priv_key);
        std::filesystem::remove(m_ecdh_pub_key);
        std::filesystem::remove(m_ecdh_priv_key);

        // OpenSSLプロバイダーのアンロード
        OSSL_PROVIDER_unload(nullptr);
    }

protected:
    std::string m_largeFileName;
    std::string m_encryptedFileName;
    std::string m_decryptedFileName;
    std::string m_mlkem_pub_key;
    std::string m_mlkem_priv_key;
    std::string m_ecdh_pub_key;
    std::string m_ecdh_priv_key;

private:
    void createLargeFile(const std::string& filename, size_t size_in_mb) {
        std::ofstream ofs(filename, std::ios::binary | std::ios::out);
        if (!ofs) return;
        
        std::vector<char> buffer(1024 * 1024, 0); // 1MB buffer
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, 255);

        for (auto& c : buffer) {
            c = static_cast<char>(dist(rng));
        }

        for (size_t i = 0; i < size_in_mb; ++i) {
            ofs.write(buffer.data(), buffer.size());
        }
    }

    void generateKeys() {
        nkCryptoToolPQC pqc_handler;
        nkCryptoToolECC ecc_handler;

        // ML-KEM鍵ペアの生成
        pqc_handler.generateEncryptionKeyPair(m_mlkem_pub_key, m_mlkem_priv_key, "");

        // ECDH鍵ペアの生成
        ecc_handler.generateEncryptionKeyPair(m_ecdh_pub_key, m_ecdh_priv_key, "");
    }
};

// =============================================================================
//  ベンチマークの定義
// =============================================================================

BENCHMARK_F(CryptoBenchmark, BM_EncryptLargeFile)(benchmark::State& state) {
    for (auto _ : state) {
        state.PauseTiming(); // セットアップ時間は測定から除外
        asio::io_context io_context;
        nkCryptoToolPQC crypto_handler;
        std::map<std::string, std::string> key_paths;
        key_paths["recipient-mlkem-pubkey"] = m_mlkem_pub_key;
        key_paths["recipient-ecdh-pubkey"] = m_ecdh_pub_key;
        state.ResumeTiming(); // 測定再開

        crypto_handler.encryptFileWithPipeline(io_context, m_largeFileName, m_encryptedFileName, key_paths, [](std::error_code ec){});
        io_context.run();
    }
}

BENCHMARK_F(CryptoBenchmark, BM_DecryptLargeFile)(benchmark::State& state) {
    // 事前にファイルを暗号化しておく
    {
        asio::io_context setup_context;
        nkCryptoToolPQC setup_handler;
        std::map<std::string, std::string> setup_key_paths;
        setup_key_paths["recipient-mlkem-pubkey"] = m_mlkem_pub_key;
        setup_key_paths["recipient-ecdh-pubkey"] = m_ecdh_pub_key;
        setup_handler.encryptFileWithPipeline(setup_context, m_largeFileName, m_encryptedFileName, setup_key_paths, [](std::error_code ec){});
        setup_context.run();
    }

    for (auto _ : state) {
        state.PauseTiming();
        asio::io_context io_context;
        nkCryptoToolPQC crypto_handler;
        std::map<std::string, std::string> key_paths;
        key_paths["recipient-mlkem-privkey"] = m_mlkem_priv_key;
        key_paths["recipient-ecdh-privkey"] = m_ecdh_priv_key;
        state.ResumeTiming();

        crypto_handler.decryptFileWithPipeline(io_context, m_encryptedFileName, m_decryptedFileName, key_paths, [](std::error_code ec){});
        io_context.run();
    }
}

BENCHMARK_MAIN();
