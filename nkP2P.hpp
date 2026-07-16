/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

// P2P chat over the iroh transport, interoperable with nkCryptoTool-rust.
// The transport (NAT hole-punch, relay, QUIC, NodeId) is provided by the Rust
// `nkct-p2p-shim` static library (built from p2p-shim/ by CMake); this module
// implements the app-layer V3.1 PQC handshake + chat framing in C++, mirroring
// nkCryptoTool-rust src/p2p/processor.rs and src/network/mod.rs byte-for-byte.
//
// Only compiled when NKCT_ENABLE_P2P is defined (requires the OpenSSL backend
// and a Rust toolchain to build the shim).

#ifndef NK_P2P_HPP
#define NK_P2P_HPP

#include <string>
#include <optional>
#include <vector>
#include <cstdint>

namespace nk::p2p {

// Run a chat client: connect to `ticket`, run the handshake (mutual ML-DSA auth
// if the ticket carries a signer fingerprint AND `signing_priv`/`signing_pub`
// are provided, else anonymous), then chat (stdin -> peer, peer -> stdout).
// Returns 0 on success. `signing_priv`/`signing_pub` are PEM key paths for our
// own identity; empty ⇒ anonymous initiator.
int connectChat(const std::string& ticket,
                const std::string& signing_priv,
                const std::string& signing_pub);

// Run a chat server: bind, print the NKCT1 ticket, accept one peer, run the
// responder handshake (self-auth if `signing_priv` given, else anonymous),
// then chat. `allow_unauth` lets an anonymous initiator in.
int serveChat(const std::string& signing_priv,
              const std::string& signing_pub,
              bool allow_unauth);

// scp get: connect to `ticket`, download `remote_path` from the peer to
// `local_path` (single file). Interoperates with the Rust scp server.
int connectScpGet(const std::string& ticket,
                  const std::string& remote_path,
                  const std::string& local_path,
                  const std::string& signing_priv,
                  const std::string& signing_pub);

// shell client: connect to `ticket`, run the handshake (mutual auth mandatory),
// then a shell session. `cmd` empty ⇒ interactive PTY; non-empty ⇒ run that one
// command (ssh-style) and exit with its status. Interoperates with the Rust
// `--serve-shell` server (ALPN nkct/shell/2). Returns the remote exit code.
int connectShell(const std::string& ticket,
                 const std::string& signing_priv,
                 const std::string& signing_pub,
                 const std::string& cmd);

// pairing client (ssh-copy-id): connect to `ticket`, run the handshake, then
// send our own signed KeyBundle `bundle` with the one-time `token` for the
// server to register. Interoperates with the Rust `--serve-pairing` server
// (ALPN nkct/pairing/1). Returns 0 on successful registration.
int connectPairing(const std::string& ticket,
                   const std::string& token,
                   const std::vector<uint8_t>& bundle,
                   const std::string& signing_priv,
                   const std::string& signing_pub);

// shell server: bind, print a ticket, accept ONE client (mutual auth; the
// allowed client is pinned by `allowed_client_pub`, an ML-DSA pubkey PEM), then
// run a PTY-backed shell session. Interoperates with the Rust `--shell` client.
// Refuses to run as root. Returns 0 when the session ends.
int serveShell(const std::string& signing_priv,
               const std::string& allowed_client_pub);

// pairing server (ssh-copy-id): print a one-time token + ticket + fingerprint,
// accept ONE self-authenticated client, receive its KeyBundle, verify the token,
// and register it into `keyring_db` with `grants`. Interoperates with the Rust
// `--copy-bundle` client. Needs the keyring feature (redb writes). Root-refused.
int servePairing(const std::string& signing_priv,
                 const std::string& keyring_db,
                 uint8_t grants);

} // namespace nk::p2p

#endif // NK_P2P_HPP
