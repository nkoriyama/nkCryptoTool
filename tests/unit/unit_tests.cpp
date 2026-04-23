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

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <thread>
#include <future>

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
    // SecureAllocator::deallocate calls OPENSSL_cleanse, so memory is wiped.
    // We can't directly verify this, but we ensure no crash occurs.
    {
        SecureString s = "sensitive data";
        s.clear();
    }
    EXPECT_TRUE(true); // No crash = pass
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
    // Verify allocator works correctly with a vector
    SecureVector v;
    for (int i = 0; i < 100; ++i) {
        v.push_back(static_cast<unsigned char>(i));
    }
    EXPECT_EQ(v.size(), 100u);
    // Verify data integrity
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(v[i], static_cast<unsigned char>(i));
    }
}

TEST(SecureAllocatorTest, LargeAllocation) {
    // Test allocation of a larger buffer (1MB)
    SecureVector v(1024 * 1024, 0xFF);
    EXPECT_EQ(v.size(), 1024u * 1024u);
    EXPECT_EQ(v.front(), 0xFF);
    EXPECT_EQ(v.back(), 0xFF);
}

// ============================================================================
// nkCryptoToolUtils - Endianness Tests
// ============================================================================

TEST(UtilsTest, WriteU16Le) {
    std::vector<char> out;
    write_u16_le(out, 0x0102);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0x02);
    EXPECT_EQ(static_cast<unsigned char>(out[1]), 0x01);
}

TEST(UtilsTest, WriteU16LeZero) {
    std::vector<char> out;
    write_u16_le(out, 0x0000);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0x00);
    EXPECT_EQ(static_cast<unsigned char>(out[1]), 0x00);
}

TEST(UtilsTest, WriteU16LeMax) {
    std::vector<char> out;
    write_u16_le(out, 0xFFFF);
    EXPECT_EQ(out.size(), 2u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0xFF);
    EXPECT_EQ(static_cast<unsigned char>(out[1]), 0xFF);
}

TEST(UtilsTest, ReadU16Le) {
    std::vector<char> data{0x02, 0x01};
    size_t pos = 0;
    uint16_t val;
    EXPECT_TRUE(read_u16_le(data, pos, val));
    EXPECT_EQ(val, 0x0102u);
    EXPECT_EQ(pos, 2u);
}

TEST(UtilsTest, ReadU16LeOutOfBounds) {
    std::vector<char> data{0x01};
    size_t pos = 0;
    uint16_t val;
    EXPECT_FALSE(read_u16_le(data, pos, val));
}

TEST(UtilsTest, ReadU16LePosBeyondSize) {
    std::vector<char> data{0x01, 0x02};
    size_t pos = 3;
    uint16_t val;
    EXPECT_FALSE(read_u16_le(data, pos, val));
}

TEST(UtilsTest, WriteU32Le) {
    std::vector<char> out;
    write_u32_le(out, 0x01020304);
    EXPECT_EQ(out.size(), 4u);
    EXPECT_EQ(static_cast<unsigned char>(out[0]), 0x04);
    EXPECT_EQ(static_cast<unsigned char>(out[1]), 0x03);
    EXPECT_EQ(static_cast<unsigned char>(out[2]), 0x02);
    EXPECT_EQ(static_cast<unsigned char>(out[3]), 0x01);
}

TEST(UtilsTest, WriteU32LeZero) {
    std::vector<char> out;
    write_u32_le(out, 0x00000000);
    EXPECT_EQ(out.size(), 4u);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(static_cast<unsigned char>(out[i]), 0x00);
    }
}

TEST(UtilsTest, WriteU32LeMax) {
    std::vector<char> out;
    write_u32_le(out, 0xFFFFFFFF);
    EXPECT_EQ(out.size(), 4u);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(static_cast<unsigned char>(out[i]), 0xFF);
    }
}

TEST(UtilsTest, ReadU32Le) {
    std::vector<char> data{0x04, 0x03, 0x02, 0x01};
    size_t pos = 0;
    uint32_t val;
    EXPECT_TRUE(read_u32_le(data, pos, val));
    EXPECT_EQ(val, 0x01020304u);
    EXPECT_EQ(pos, 4u);
}

TEST(UtilsTest, ReadU32LeOutOfBounds) {
    std::vector<char> data{0x01, 0x02, 0x03};
    size_t pos = 0;
    uint32_t val;
    EXPECT_FALSE(read_u32_le(data, pos, val));
}

TEST(UtilsTest, RoundTripU16) {
    for (uint16_t v : {0, 1, 255, 256, 65535, 0x1234, 0xABCD}) {
        std::vector<char> out;
        write_u16_le(out, v);
        size_t pos = 0;
        uint16_t result;
        EXPECT_TRUE(read_u16_le(out, pos, result)) << "v=" << v;
        EXPECT_EQ(result, v) << "v=" << v;
    }
}

TEST(UtilsTest, RoundTripU32) {
    for (uint32_t v : {uint32_t{0}, uint32_t{1}, uint32_t{255}, uint32_t{256}, uint32_t{65535}, uint32_t{65536}, uint32_t{0xFFFFFFFF}, uint32_t{0x12345678}}) {
        std::vector<char> out;
        write_u32_le(out, v);
        size_t pos = 0;
        uint32_t result;
        EXPECT_TRUE(read_u32_le(out, pos, result)) << "v=" << v;
        EXPECT_EQ(result, v) << "v=" << v;
    }
}

// ============================================================================
// CryptoConfig Tests
// ============================================================================

TEST(CryptoConfigTest, DefaultValues) {
    CryptoConfig config;
    EXPECT_EQ(config.operation, Operation::None);
    EXPECT_EQ(config.mode, CryptoMode::ECC);
    EXPECT_FALSE(config.passphrase_was_provided);
    EXPECT_FALSE(config.use_tpm);
    EXPECT_EQ(config.digest_algo, "SHA3-512");
    EXPECT_EQ(config.pqc_kem_algo, "ML-KEM-1024");
    EXPECT_EQ(config.pqc_dsa_algo, "ML-DSA-87");
    EXPECT_FALSE(config.sync_mode);
    EXPECT_FALSE(config.use_parallel);
    EXPECT_FALSE(config.is_recursive);
    EXPECT_TRUE(config.input_files.empty());
    EXPECT_TRUE(config.output_file.empty());
}

TEST(CryptoModeTest, GetStringValidModes) {
    EXPECT_EQ(get_mode_from_string("ecc"), CryptoMode::ECC);
    EXPECT_EQ(get_mode_from_string("pqc"), CryptoMode::PQC);
    EXPECT_EQ(get_mode_from_string("hybrid"), CryptoMode::Hybrid);
}

TEST(CryptoModeTest, GetStringInvalidMode) {
    EXPECT_THROW(get_mode_from_string("invalid"), std::invalid_argument);
    EXPECT_THROW(get_mode_from_string(""), std::invalid_argument);
    EXPECT_THROW(get_mode_from_string("ECC"), std::invalid_argument);
    EXPECT_THROW(get_mode_from_string("PQC"), std::invalid_argument);
}

TEST(CryptoModeTest, ToString) {
    EXPECT_EQ(to_string(CryptoMode::ECC), "ecc");
    EXPECT_EQ(to_string(CryptoMode::PQC), "pqc");
    EXPECT_EQ(to_string(CryptoMode::Hybrid), "hybrid");
}

TEST(CryptoModeTest, RoundTrip) {
    for (const auto& s : {"ecc", "pqc", "hybrid"}) {
        auto mode = get_mode_from_string(s);
        EXPECT_EQ(to_string(mode), s);
    }
}

// ============================================================================
// CryptoError Tests
// ============================================================================

TEST(CryptoErrorTest, ToStringSuccess) {
    EXPECT_EQ(toString(CryptoError::Success), "Success");
}

TEST(CryptoErrorTest, ToStringFileErrors) {
    EXPECT_EQ(toString(CryptoError::FileCreationError), "Error creating file");
    EXPECT_EQ(toString(CryptoError::FileReadError), "Error reading file");
    EXPECT_EQ(toString(CryptoError::FileWriteError), "Error writing to file");
}

TEST(CryptoErrorTest, ToStringKeyErrors) {
    EXPECT_EQ(toString(CryptoError::KeyGenerationInitError),
              "Failed to initialize key generation context");
    EXPECT_EQ(toString(CryptoError::KeyGenerationError),
              "Failed to generate key pair");
    EXPECT_EQ(toString(CryptoError::PrivateKeyWriteError),
              "Failed to write private key to file");
    EXPECT_EQ(toString(CryptoError::PublicKeyWriteError),
              "Failed to write public key to file");
    EXPECT_EQ(toString(CryptoError::PrivateKeyLoadError),
              "Failed to load private key");
    EXPECT_EQ(toString(CryptoError::PublicKeyLoadError),
              "Failed to load public key");
}

TEST(CryptoErrorTest, ToStringOtherErrors) {
    EXPECT_EQ(toString(CryptoError::ParameterError),
              "Failed to set parameters");
    EXPECT_EQ(toString(CryptoError::SignatureVerificationError),
              "Signature verification failed");
    EXPECT_EQ(toString(CryptoError::OpenSSLError),
              "An OpenSSL error occurred");
    EXPECT_EQ(toString(CryptoError::TPMError), "A TPM error occurred");
    EXPECT_EQ(toString(CryptoError::TPMProviderLoadError),
              "Failed to load TPM provider");
    EXPECT_EQ(toString(CryptoError::ProviderNotAvailable),
              "No key protection provider is available");
    EXPECT_EQ(toString(CryptoError::KeyProtectionError),
              "A key protection error occurred");
}

// ============================================================================
// StrategyType Tests
// ============================================================================

TEST(StrategyTypeTest, EnumValues) {
    EXPECT_EQ(static_cast<uint8_t>(StrategyType::ECC), 1u);
    EXPECT_EQ(static_cast<uint8_t>(StrategyType::PQC), 2u);
    EXPECT_EQ(static_cast<uint8_t>(StrategyType::Hybrid), 3u);
}

// ============================================================================
// KeyProvider Tests
// ============================================================================

TEST(KeyProviderTest, DefaultConstruction) {
    nk::KeyProvider kp;
    EXPECT_FALSE(kp.isAvailable());
}

TEST(KeyProviderTest, WrapWithoutProvider) {
    nk::KeyProvider kp;
    auto result = kp.wrap(nullptr);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CryptoError::ProviderNotAvailable);
}

TEST(KeyProviderTest, UnwrapWithoutProvider) {
    nk::KeyProvider kp;
    SecureString wrapped;
    auto result = kp.unwrap(wrapped);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), CryptoError::ProviderNotAvailable);
}

// ============================================================================
// OpenSSL Integration Tests (smoke tests)
// ============================================================================

#include "OpenSSLDeleters.hpp"

TEST(OpenSSLTest, VersionCheck) {
    // Verify OpenSSL 3.x is available
    unsigned long v = OpenSSL_version_num();
    // OpenSSL 3.0 = 0x30000000L
    EXPECT_GE(v, 0x30000000UL);
}

TEST(OpenSSLTest, ECCKeyGeneration) {
    // Generate an ECC key pair using the same API as ECCStrategy
    std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>
        pctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    ASSERT_NE(pctx.get(), nullptr);

    EXPECT_GT(EVP_PKEY_keygen_init(pctx.get()), 0);

    const char* curve_name = "prime256v1";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", const_cast<char*>(curve_name), 0),
        OSSL_PARAM_construct_end()
    };
    EVP_PKEY_CTX_set_params(pctx.get(), params);

    EVP_PKEY* pkey = nullptr;
    EXPECT_GT(EVP_PKEY_keygen(pctx.get(), &pkey), 0);
    ASSERT_NE(pkey, nullptr);

    int bits = EVP_PKEY_get_bits(pkey);
    EXPECT_GT(bits, 0);

    EVP_PKEY_free(pkey);
}

TEST(OpenSSLTest, EncryptDecryptSmoke) {
    // Quick smoke test: verify EVP_aes_256_gcm cipher is available
    auto cipher = EVP_aes_256_gcm();
    EXPECT_NE(cipher, nullptr);

    // Verify EVP_CIPHER_CTX can be created
    std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>
        ctx(EVP_CIPHER_CTX_new());
    ASSERT_NE(ctx.get(), nullptr);
}

TEST(OpenSSLTest, DigestSHA3_512) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    EVP_Digest("test", 4, digest, &digest_len, EVP_sha3_512(), nullptr);
    EXPECT_EQ(digest_len, 64u); // SHA3-512 = 512 bits = 64 bytes
}

TEST(OpenSSLTest, BIOReadWrite) {
    // Test BIO (Basic I/O) abstraction
    std::string test_data = "Hello, OpenSSL BIO!";
    auto bio = BIO_new_mem_buf(test_data.data(), static_cast<int>(test_data.size()));
    ASSERT_NE(bio, nullptr);

    std::vector<char> buf(test_data.size() + 1, 0);
    int read_len = BIO_read(bio, buf.data(), static_cast<int>(test_data.size()));
    EXPECT_EQ(read_len, static_cast<int>(test_data.size()));
    EXPECT_EQ(std::string(buf.data(), read_len), test_data);

    BIO_free(bio);
}
