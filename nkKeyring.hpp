/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

// Shared-keyring.db management for the C++ tool, via the Rust keyring shim
// (keyring-shim/). The C++ tool reads and writes the SAME keyring.db the Rust
// nkCryptoTool uses (redb my-identities store), so keys generated/imported by
// either binary are usable by both. Only compiled when NKCT_ENABLE_KEYRING.

#ifndef NK_KEYRING_HPP
#define NK_KEYRING_HPP

#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace nk::keyring_db {

// --keyring-cmd gen-my-key: generate a key straight into keyring.db.
int genMyKey(const std::string& db_path, const std::string& algo,
             const std::string& role_hint, const std::string& handle);

// --keyring-cmd import-my-key: import an encrypted-PKCS#8 PEM key file.
int importMyKey(const std::string& db_path, const std::string& pem_path,
                const std::string& role_hint, const std::string& handle);

// --keyring-cmd list-my-keys.
int listMyKeys(const std::string& db_path);

// Auto-match: fetch + unlock the slot handle:role:algo from keyring.db and
// return the still-encrypted PKCS#8 PEM text (as a key file would hold). Empty
// optional on not-found; the passphrase is prompted if `passphrase` is empty.
// Used to resolve a signing/enc key from the DB when no key path is given.
std::optional<std::string> getUnlockedPem(const std::string& db_path,
                                          const std::string& handle,
                                          const std::string& role,
                                          const std::string& algo,
                                          const std::string& passphrase);

// Fetch a slot's PUBLIC key (SPKI DER) — no passphrase, no private material.
// Used by gen-keybundle to bind/anchor the public halves from the keyring.
// Empty optional on not-found or open error.
std::optional<std::vector<uint8_t>> getPublicSpki(const std::string& db_path,
                                                  const std::string& handle,
                                                  const std::string& role,
                                                  const std::string& algo);

} // namespace nk::keyring_db

#endif // NK_KEYRING_HPP
