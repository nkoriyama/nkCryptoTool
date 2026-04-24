/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * Unit tests for nkCryptoTool using Google Test.
 */

#include <gtest/gtest.h>

#include "SecureMemory.hpp"
#include "nkCryptoToolUtils.hpp"
#include "CryptoConfig.hpp"
#include "CryptoError.hpp"
#include "KeyProvider.hpp"
#include "ICryptoStrategy.hpp"
#include "nkcrypto_ffi.hpp"
#include "PipelineManager.hpp"
#include "nkCryptoToolBase.hpp"

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <thread>
#include <future>
#include <fstream>
#include <filesystem>
#include <sstream>

// ============================================================================
// SecureMemory Tests
// ============================================================================

TEST(SecureStringTest, DefaultConstruction) {
    SecureString s;
    EXPECT_EQ(s.size(), 0u);
    EXPECT_TRUE(s.empty());
}

TEST(SecureStringTest, AssignAndAccess) {
    SecureString s = "hello world";
    EXPECT_EQ(s.size(), 11u);
    EXPECT_EQ(s[0], 'h');
    EXPECT_EQ(s.back(), 'd');
}

TEST(SecureStringTest, Concatenation) {
    SecureString a = "hello";
    SecureString b = " world";
    SecureString c = a + b;
    EXPECT_EQ(c, "hello world");
}

TEST(SecureStringTest, Comparison) {
    SecureString a = "abc";
    SecureString b = "abc";
    SecureString c = "def";
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

TEST(SecureStringTest, ClearOnDestruction) {
    {
        SecureString s = "sensitive data";
        s.clear();
    }
    EXPECT_TRUE(true);
}

TEST(SecureVectorTest, DefaultConstruction) {
    SecureVector v;
    EXPECT_EQ(v.size(), 0u);
    EXPECT_TRUE(v.empty());
}

TEST(SecureVectorTest, PushBack) {
    SecureVector v;
    v.push_back(0xDE);
    v.push_back(0xAD);
    v.push_back(0xBE);
    v.push_back(0xEF);
    EXPECT_EQ(v.size(), 4u);
    EXPECT_EQ(v[0], 0xDE);
    EXPECT_EQ(v[3], 0xEF);
}

TEST(SecureVectorTest, Resize) {
    SecureVector v(10, 0x42);
    EXPECT_EQ(v.size(), 10u);
    for (auto val : v) {
        EXPECT_EQ(val, 0x42);
    }
}

TEST(SecureVectorTest, Assign) {
    SecureVector v;
    v.assign({1, 2, 3, 4, 5});
    EXPECT_EQ(v.size(), 5u);
    EXPECT_EQ(v[2], 3u);
}

TEST(SecureAllocatorTest, AllocateAndDeallocate) {
    SecureVector v;
    for (int i = 0; i < 100; ++i) {
        v.push_back(static_cast<unsigned char>(i));
    }
    EXPECT_EQ(v.size(), 100u);
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(v[i], static_cast<unsigned char>(i));
    }
}

TEST(SecureAllocatorTest, LargeAllocation) {
    SecureVector v(1024 * 1024, 0xFF);
    EXPECT_EQ(v.size(), 1024u * 1024u);
    EXPECT_EQ(v.front(), 0xFF);
    EXPECT_EQ(v.back(), 0xFF);
}

// ============================================================================
// Utils Tests
// ============================================================================

TEST(UtilsTest, WriteU16Le) {
    std::vector<char> out;
    write_u16_le(out, 0x0102);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0x02);
    EXPECT_EQ(static_cast<unsigned char>(out[1]), 0x01);
}

TEST(UtilsTest, ReadU16Le) {
    std::vector<char> data{0x02, 0x01};
    size_t pos = 0;
    uint16_t val;
    EXPECT_TRUE(read_u16_le(data, pos, val));
    EXPECT_EQ(val, 0x0102u);
    EXPECT_EQ(pos, 2u);
}

TEST(UtilsTest, WriteU32Le) {
    std::vector<char> out;
    write_u32_le(out, 0x01020304);
    EXPECT_EQ(out.size(), 4u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0x04);
}

TEST(UtilsTest, ReadU32Le) {
    std::vector<char> data{0x04, 0x03, 0x02, 0x01};
    size_t pos = 0;
    uint32_t val;
    EXPECT_TRUE(read_u32_le(data, pos, val));
    EXPECT_EQ(val, 0x01020304u);
}

TEST(UtilsTest, OsslPassphraseCb) {
    SecureString pass = "testpass";
    char buf[64];
    size_t len = 0;
    int res = ossl_passphrase_cb(buf, sizeof(buf), &len, nullptr, (void*)&pass);
    EXPECT_EQ(res, 1);
    EXPECT_EQ(len, 8u);
    EXPECT_STREQ(buf, "testpass");
}

TEST(UtilsTest, PemPasswdCb) {
    SecureString pass = "pempas";
    char buf[64];
    int res = pem_passwd_cb(buf, sizeof(buf), 0, (void*)&pass);
    EXPECT_EQ(res, 6);
}

TEST(UtilsTest, ProcessDirectory) {
    asio::io_context ctx;
    std::filesystem::path test_in = "test_dir_in";
    std::filesystem::path test_out = "test_dir_out";
    std::filesystem::create_directories(test_in / "subdir");
    std::ofstream(test_in / "file1.txt") << "data1";
    
    int call_count = 0;
    processDirectory(ctx, test_in, test_out, [&](auto, auto) { call_count++; });
    EXPECT_EQ(call_count, 1);
    std::filesystem::remove_all(test_in);
    std::filesystem::remove_all(test_out);
}

TEST(UtilsTest, GetAndVerifyPassphraseSuccess) {
    std::stringstream input("secret\nsecret\n");
    auto* old_cin = std::cin.rdbuf(input.rdbuf());
    SecureString res = get_and_verify_passphrase("Prompt: ");
    std::cin.rdbuf(old_cin);
    EXPECT_EQ(res, "secret");
}

// ============================================================================
// CryptoConfig Tests
// ============================================================================

TEST(CryptoConfigTest, DefaultValues) {
    CryptoConfig config;
    EXPECT_EQ(config.operation, Operation::None);
}

TEST(CryptoModeTest, ToString) {
    EXPECT_EQ(to_string(CryptoMode::ECC), "ecc");
}

// ============================================================================
// Mock Objects for Strategy and Base Class
// ============================================================================

class MockStrategy : public ICryptoStrategy {
public:
    StrategyType getStrategyType() const override { return StrategyType::ECC; }
    void setKeyProvider(std::shared_ptr<nk::IKeyProvider>) override {}
    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>&, SecureString&) override { return {}; }
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>&, SecureString&) override { return {}; }
    std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>&) override { return {}; }
    std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>&, SecureString&) override { return {}; }
    std::vector<char> encryptTransform(const std::vector<char>& data) override { return data; }
    std::vector<char> decryptTransform(const std::vector<char>& data) override { return data; }
    std::expected<void, CryptoError> finalizeEncryption(std::vector<char>&) override { return {}; }
    std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>&) override { return {}; }
    std::expected<void, CryptoError> prepareSigning(const std::filesystem::path&, SecureString&, const std::string&) override { return {}; }
    std::expected<void, CryptoError> prepareVerification(const std::filesystem::path&, const std::string&) override { return {}; }
    void updateHash(const std::vector<char>&) override {}
    std::expected<std::vector<char>, CryptoError> signHash() override { return std::vector<char>{}; }
    std::expected<bool, CryptoError> verifyHash(const std::vector<char>&) override { return true; }
    std::vector<char> serializeSignatureHeader() const override { return {}; }
    std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>&) override { return 0; }
    std::map<std::string, std::string> getMetadata(const std::string&) const override { return {}; }
    size_t getHeaderSize() const override { return 0; }
    std::vector<char> serializeHeader() const override { return {}; }
    std::expected<size_t, CryptoError> deserializeHeader(const std::vector<char>&) override { return 0; }
    size_t getTagSize() const override { return 0; }
};

class TestCryptoTool : public nkCryptoToolBase {
public:
    TestCryptoTool() : nkCryptoToolBase(std::make_shared<MockStrategy>()) {}
    using nkCryptoToolBase::detectStrategyType;
    using nkCryptoToolBase::isPrivateKeyEncrypted;
};

// ============================================================================
// Base Class Tests
// ============================================================================

TEST(BaseTest, DetectStrategyTypeInvalid) {
    std::ofstream("invalid_magic.bin") << "NOT_MAGIC";
    TestCryptoTool tool;
    auto res = tool.detectStrategyType("invalid_magic.bin");
    EXPECT_FALSE(res.has_value());
    std::filesystem::remove("invalid_magic.bin");
}

// ============================================================================
// PipelineManager Tests
// ============================================================================

TEST(PipelineManagerTest, SimpleRun) {
    asio::io_context ctx;
    auto pm = std::make_shared<PipelineManager>(ctx);
    std::filesystem::path in = "test_pm_in.bin";
    std::filesystem::path out_path = "test_pm_out.bin";
    { std::ofstream ofs(in); ofs << "test data"; }
    
    std::error_code ec;
    async_file_t out_file(ctx);
    out_file.open(out_path, O_WRONLY | O_CREAT | O_TRUNC, ec);
    ASSERT_FALSE(ec);
    
    bool completed = false;
    pm->run(in.string(), std::move(out_file), 0, 9, [&](std::error_code ec2) {
        completed = true;
    });
    ctx.run();
    EXPECT_TRUE(completed);
    std::filesystem::remove(in);
    std::filesystem::remove(out_path);
}

TEST(PipelineManagerTest, InvalidInputFile) {
    asio::io_context ctx;
    auto pm = std::make_shared<PipelineManager>(ctx);
    
    bool completed = false;
    std::error_code error;
    pm->run("non_existent_input_file", async_file_t(ctx), 0, 100, [&](std::error_code ec) {
        error = ec;
        completed = true;
    });
    ctx.run();
    EXPECT_TRUE(completed);
    EXPECT_TRUE(error);
}

// ============================================================================
// FFI Tests
// ============================================================================

TEST(FFITest, RunInvalidJson) {
    int result = run_crypto_op_json("{ invalid json }");
    EXPECT_EQ(result, 1);
}

TEST(FFITest, RunKeyGeneration) {
    std::string key_dir = "test_ffi_keys";
    std::filesystem::create_directories(key_dir);
    std::string json = R"({ "operation": "generate_enc_key", "mode": "ecc", "key_paths": { "public-key": "test_ffi_keys/ffi_ecc.pub", "private-key": "test_ffi_keys/ffi_ecc.key" } })";
    int result = run_crypto_op_json(json.c_str());
    EXPECT_EQ(result, 0);
    std::filesystem::remove_all(key_dir);
}

// ============================================================================
// CryptoProcessor Tests
// ============================================================================

#include "CryptoProcessor.hpp"

TEST(CryptoProcessorTest, InvalidOperationError) {
    CryptoConfig config;
    config.operation = Operation::Encrypt;
    config.mode = CryptoMode::ECC;
    config.input_files = {"non_existent_file"};
    CryptoProcessor processor(config);
    auto future = processor.run();
    EXPECT_THROW(future.get(), std::system_error);
}
