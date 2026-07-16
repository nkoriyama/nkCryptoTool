/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkKeyring.hpp"
#include "nkCryptoToolUtils.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

extern "C" {
void nkct_kr_string_free(char*);
int  nkct_kr_gen_my_key(const char* db, const char* algo, const char* role_hint,
                        const char* handle, const char* passphrase, char** out_fp_hex);
int  nkct_kr_import_my_key(const char* db, const unsigned char* pem, size_t pem_len,
                           const char* role_hint, const char* handle, const char* passphrase);
int  nkct_kr_get_unlocked(const char* db, const char* handle, const char* role,
                          const char* algo, const char* passphrase, char** out_pem);
char* nkct_kr_list(const char* db);
}

namespace nk::keyring_db {

namespace {
// Prompt (verify) for a new-key passphrase; empty NK_PASSPHRASE means prompt.
std::string newPassphrase() {
    SecureString p = get_and_verify_passphrase("Generate keyring key pair: ");
    return std::string(p.c_str(), p.length());
}
std::string prompt(const char* what) {
    std::fprintf(stderr, "%s", what);
    SecureString p = get_masked_passphrase();
    return std::string(p.c_str(), p.length());
}
}

int genMyKey(const std::string& db, const std::string& algo,
             const std::string& role_hint, const std::string& handle) {
    std::string pass = newPassphrase();
    if (pass.empty()) { std::fprintf(stderr, "Error: gen-my-key requires a passphrase\n"); return 1; }
    char* fp = nullptr;
    int rc = nkct_kr_gen_my_key(db.c_str(), algo.c_str(), role_hint.c_str(),
                                handle.empty() ? "me" : handle.c_str(), pass.c_str(), &fp);
    if (rc != 0) { std::fprintf(stderr, "Error: gen-my-key failed (algo/role, or key already in slot)\n"); if (fp) nkct_kr_string_free(fp); return 1; }
    std::printf("Generated %s:%s:%s (fingerprint %s) in keyring %s — no key file written\n",
                (handle.empty()?"me":handle.c_str()),
                (role_hint.empty()? (algo.rfind("ML-KEM",0)==0?"enc":(algo.rfind("ML-DSA",0)==0?"sign":"?")) : role_hint.c_str()),
                algo.c_str(), fp ? fp : "?", db.c_str());
    if (fp) nkct_kr_string_free(fp);
    return 0;
}

int importMyKey(const std::string& db, const std::string& pem_path,
                const std::string& role_hint, const std::string& handle) {
    std::ifstream ifs(pem_path, std::ios::binary);
    if (!ifs) { std::fprintf(stderr, "Error: read %s\n", pem_path.c_str()); return 1; }
    std::vector<unsigned char> pem((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    std::string pass = prompt(("Passphrase for " + pem_path + ": ").c_str());
    int rc = nkct_kr_import_my_key(db.c_str(), pem.data(), pem.size(), role_hint.c_str(),
                                   handle.empty() ? "me" : handle.c_str(), pass.c_str());
    if (rc != 0) { std::fprintf(stderr, "Error: import-my-key failed (not encrypted PKCS#8? wrong passphrase? P-256 needs --key-role?)\n"); return 1; }
    std::printf("Imported into keyring %s\n", db.c_str());
    return 0;
}

int listMyKeys(const std::string& db) {
    char* l = nkct_kr_list(db.c_str());
    if (!l) { std::fprintf(stderr, "Error: open keyring %s\n", db.c_str()); return 1; }
    std::string s(l); nkct_kr_string_free(l);
    if (s.empty()) { std::printf("(keyring %s has no my-identities)\n", db.c_str()); return 0; }
    std::printf("handle:role:algo:fingerprint(8)\n%s", s.c_str());
    return 0;
}

std::optional<std::string> getUnlockedPem(const std::string& db, const std::string& handle,
                                          const std::string& role, const std::string& algo,
                                          const std::string& passphrase) {
    std::string pass = passphrase;
    if (pass.empty()) pass = prompt(("Keyring passphrase for " + handle + ": ").c_str());
    char* pem = nullptr;
    int rc = nkct_kr_get_unlocked(db.c_str(), handle.c_str(), role.c_str(), algo.c_str(), pass.c_str(), &pem);
    if (rc != 0) { if (pem) nkct_kr_string_free(pem); return std::nullopt; }
    std::string out(pem ? pem : ""); if (pem) nkct_kr_string_free(pem);
    return out;
}

} // namespace nk::keyring_db
