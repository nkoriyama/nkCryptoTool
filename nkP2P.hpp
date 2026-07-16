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

} // namespace nk::p2p

#endif // NK_P2P_HPP
