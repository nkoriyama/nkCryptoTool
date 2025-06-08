// nkCryptoToolBase.cpp

#include "nkCryptoToolBase.hpp"
#include <fstream>
#include <iostream>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

// External callback for PEM passphrase, defined in nkCryptoToolMain.cpp
extern int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);
extern std::string global_passphrase_for_pem_cb;

// --- OpenSSL Custom Deleters Implementation ---
void EVP_PKEY_Deleter::operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
void EVP_PKEY_CTX_Deleter::operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
void EVP_CIPHER_CTX_Deleter::operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
void EVP_MD_CTX_Deleter::operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
void BIO_Deleter::operator()(BIO *b) const { BIO_free_all(b); }
void EVP_KDF_Deleter::operator()(EVP_KDF *p) const { EVP_KDF_free(p); }
void EVP_KDF_CTX_Deleter::operator()(EVP_KDF_CTX *p) const { EVP_KDF_CTX_free(p); }

// --- Constructor / Destructor ---
nkCryptoToolBase::nkCryptoToolBase() : key_base_directory("keys") {
    try {
      if (!std::filesystem::exists(key_base_directory)) {
        std::filesystem::create_directories(key_base_directory);
      }
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Error creating directory '" << key_base_directory << "': " << e.what() << std::endl;
    }
}

nkCryptoToolBase::~nkCryptoToolBase() {}

void nkCryptoToolBase::setKeyBaseDirectory(const std::filesystem::path& dir) {
    key_base_directory = dir;
    try {
      if (!std::filesystem::exists(key_base_directory)) {
        std::filesystem::create_directories(key_base_directory);
      }
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Error creating directory '" << key_base_directory << "': " << e.what() << std::endl;
    }
}

std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const {
    return key_base_directory;
}

// --- AsyncStateBase Constructor ---
nkCryptoToolBase::AsyncStateBase::AsyncStateBase(asio::io_context& io_context)
    : input_file(io_context),
      output_file(io_context),
      cipher_ctx(EVP_CIPHER_CTX_new()), // FIX: Correctly initialize unique_ptr with default deleter
      input_buffer(CHUNK_SIZE),
      output_buffer(CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH),
      tag(GCM_TAG_LEN),
      bytes_read(0),
      total_bytes_processed(0) {}

// --- Common Helper Functions Implementation ---

void nkCryptoToolBase::printOpenSSLErrors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error())) {
        char err_buf[256];
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "OpenSSL Error: " << err_buf << std::endl;
    }
}

void nkCryptoToolBase::printProgress(double percentage) {
    int barWidth = 50;
    std::cout << "[";
    int pos = static_cast<int>(barWidth * percentage);
    for (int i = 0; i < barWidth; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << static_cast<int>(percentage * 100.0) << " %\r";
    std::cout.flush();
}

std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> nkCryptoToolBase::loadPublicKey(const std::filesystem::path& public_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> pub_bio(BIO_new_file(public_key_path.string().c_str(), "rb"));
    if (!pub_bio) {
        std::cerr << "Error loading public key: Could not open file " << public_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr);
    if (!public_key) {
        std::cerr << "Error loading public key: PEM_read_bio_PUBKEY failed for " << public_key_path << std::endl;
        printOpenSSLErrors();
    }
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(public_key);
}

std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter> nkCryptoToolBase::loadPrivateKey(const std::filesystem::path& private_key_path) {
    std::unique_ptr<BIO, BIO_Deleter> priv_bio(BIO_new_file(private_key_path.string().c_str(), "rb"));
    if (!priv_bio) {
        std::cerr << "Error loading private key: Could not open file " << private_key_path << std::endl;
        printOpenSSLErrors();
        return nullptr;
    }
    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(priv_bio.get(), nullptr, pem_passwd_cb, &global_passphrase_for_pem_cb);
    if (!private_key) {
        std::cerr << "Error loading private key: PEM_read_bio_PrivateKey failed for " << private_key_path << std::endl;
        printOpenSSLErrors();
    }
    return std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>(private_key);
}

std::vector<unsigned char> nkCryptoToolBase::hkdfDerive(const std::vector<unsigned char>& ikm, size_t output_len,
                                                      const std::string& salt_str, const std::string& info_str,
                                                      const std::string& digest_algo) {
    std::unique_ptr<EVP_KDF, EVP_KDF_Deleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) {
        std::cerr << "Error: EVP_KDF_fetch failed for HKDF." << std::endl;
        printOpenSSLErrors();
        return {};
    }
    std::unique_ptr<EVP_KDF_CTX, EVP_KDF_CTX_Deleter> kctx(EVP_KDF_CTX_new(kdf.get()));
    if (!kctx) {
        std::cerr << "Error: EVP_KDF_CTX_new failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }

    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest_algo.c_str(), 0);
    params[p++] = OSSL_PARAM_construct_octet_string("key", (void*)ikm.data(), ikm.size());
    if (!salt_str.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string("salt", (void*)salt_str.c_str(), salt_str.length());
    }
    if (!info_str.empty()) {
        params[p++] = OSSL_PARAM_construct_octet_string("info", (void*)info_str.c_str(), info_str.length());
    }
    params[p++] = OSSL_PARAM_construct_end();

    std::vector<unsigned char> derived_key(output_len);
    if (EVP_KDF_derive(kctx.get(), derived_key.data(), output_len, params) <= 0) {
        std::cerr << "Error: HKDF derivation failed." << std::endl;
        printOpenSSLErrors();
        return {};
    }
    return derived_key;
}

// --- Synchronous File I/O ---
std::vector<unsigned char> nkCryptoToolBase::readFile(const std::filesystem::path& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file for reading: " + filepath.string());
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Could not read file content: " + filepath.string());
    }
    return buffer;
}

bool nkCryptoToolBase::writeFile(const std::filesystem::path& filepath, const std::vector<unsigned char>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file for writing: " << filepath << std::endl;
        return false;
    }
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        std::cerr << "Error: Could not write file content: " << filepath << std::endl;
        return false;
    }
    return true;
}
