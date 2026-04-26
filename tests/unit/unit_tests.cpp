/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ICryptoStrategy.hpp"
#include "ECCStrategy.hpp"
#include "PQCStrategy.hpp"
#include "HybridStrategy.hpp"
#include "nkCryptoToolUtils.hpp"
#include "backend/IBackend.hpp"
#include "CryptoConfig.hpp"

using namespace nk;

// --- SecureAllocator Tests ---

TEST(SecureVectorTest, DefaultConstruction) {
    SecureVector<uint8_t> v;
    EXPECT_EQ(v.size(), 0);
}

TEST(SecureVectorTest, PushBack) {
    SecureVector<uint8_t> v;
    v.push_back(0x01);
    EXPECT_EQ(v.size(), 1);
    EXPECT_EQ(v[0], 0x01);
}

TEST(SecureStringTest, Assignment) {
    SecureString s = "secret";
    EXPECT_EQ(s, "secret");
}

TEST(SecureVectorTest, Assign) {
    SecureVector<uint8_t> v;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    v.assign(data.begin(), data.end());
    EXPECT_EQ(v.size(), 3);
}

// --- Utils Tests ---

TEST(UtilsTest, LE16) {
    std::vector<char> buf;
    write_u16_le(buf, 0x1234);
    EXPECT_EQ(buf.size(), 2);
    
    size_t pos = 0;
    uint16_t val;
    EXPECT_TRUE(read_u16_le(buf, pos, val));
    EXPECT_EQ(val, 0x1234);
}

TEST(UtilsTest, LE32) {
    std::vector<char> buf;
    write_u32_le(buf, 0x12345678);
    EXPECT_EQ(buf.size(), 4);
    
    size_t pos = 0;
    uint32_t val;
    EXPECT_TRUE(read_u32_le(buf, pos, val));
    EXPECT_EQ(val, 0x12345678);
}

// --- Strategy Factory Tests ---

class MockStrategy : public ICryptoStrategy {
public:
    StrategyType getStrategyType() const override { return StrategyType::ECC; }
    void setKeyProvider(std::shared_ptr<nk::IKeyProvider>) override {}
    std::expected<void, CryptoError> generateEncryptionKeyPair(const std::map<std::string, std::string>&, SecureString&) override { return {}; }
    std::expected<void, CryptoError> generateSigningKeyPair(const std::map<std::string, std::string>&, SecureString&) override { return {}; }
    std::expected<void, CryptoError> regeneratePublicKey(const std::filesystem::path&, const std::filesystem::path&, SecureString&) override { return {}; }
    std::expected<void, CryptoError> prepareEncryption(const std::map<std::string, std::string>&) override { return {}; }
    std::expected<void, CryptoError> prepareDecryption(const std::map<std::string, std::string>&, SecureString&) override { return {}; }
    std::vector<char> encryptTransform(const std::vector<char>& data) override { return data; }
    std::vector<char> decryptTransform(const std::vector<char>& data) override { return data; }
    std::expected<void, CryptoError> finalizeEncryption(std::vector<char>&) override { return {}; }
    std::expected<void, CryptoError> finalizeDecryption(const std::vector<char>&) override { return {}; }
    std::expected<void, CryptoError> prepareSigning(const std::filesystem::path&, SecureString&, const std::string&) override { return {}; }
    std::expected<void, CryptoError> prepareVerification(const std::filesystem::path&, const std::string&) override { return {}; }
    void updateHash(const std::vector<char>&) override {}
    std::expected<std::vector<char>, CryptoError> signHash() override { return std::vector<char>(); }
    std::expected<bool, CryptoError> verifyHash(const std::vector<char>&) override { return true; }
    std::vector<char> serializeSignatureHeader() const override { return {}; }
    std::expected<size_t, CryptoError> deserializeSignatureHeader(const std::vector<char>&) override { return 0; }
    std::map<std::string, std::string> getMetadata(const std::string&) const override { return {}; }
    size_t getHeaderSize() const override { return 0; }
    std::vector<char> serializeHeader() const override { return {}; }
    std::expected<size_t, CryptoError> deserializeHeader(const std::vector<char>&) override { return 0; }
    size_t getTagSize() const override { return 16; }
};

TEST(StrategyTest, ECCStrategyCreation) {
    auto strategy = std::make_unique<ECCStrategy>();
    EXPECT_NE(strategy, nullptr);
}

TEST(StrategyTest, PQCStrategyCreation) {
    auto strategy = std::make_unique<PQCStrategy>();
    EXPECT_NE(strategy, nullptr);
}

TEST(StrategyTest, HybridStrategyCreation) {
    auto strategy = std::make_unique<HybridStrategy>();
    EXPECT_NE(strategy, nullptr);
}
