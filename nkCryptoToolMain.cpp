/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "CryptoProcessor.hpp"
#include "TpmKeyProvider.hpp"
#include "nkCryptoToolUtils.hpp"
#include "nkKeyBundle.hpp"
#ifdef NKCT_ENABLE_P2P
#include "nkP2P.hpp"
#endif
#include "backend/IBackend.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <filesystem>
#include <map>
#include <memory>
#include <cxxopts.hpp>

std::shared_ptr<nk::backend::ICryptoBackend> get_nk_backend();

namespace {

// Load a PEM public-key file -> SPKI DER.
std::expected<std::vector<uint8_t>, CryptoError> loadPubSpki(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return std::unexpected(CryptoError::FileReadError);
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY");
}

// --gen-keybundle: bind this identity's encryption public key(s) under its
// ML-DSA-65 signature (SPEC §6). Mirrors the Rust run_gen_keybundle. Standalone
// (uses the keybundle library, not the strategy pipeline).
int runGenKeybundle(const cxxopts::ParseResult& result, CryptoMode mode, const std::string& key_dir) {
    if (!result.count("keybundle-handle")) { std::cerr << "Error: --gen-keybundle requires --keybundle-handle <name>" << std::endl; return 1; }
    if (!result.count("keybundle-output")) { std::cerr << "Error: --gen-keybundle requires --keybundle-output <file>" << std::endl; return 1; }
    std::string handle = result["keybundle-handle"].as<std::string>();
    std::string output = result["keybundle-output"].as<std::string>();

    // Owner identity is ALWAYS ML-DSA-65, independent of --mode.
    std::string sign_priv = result.count("signing-privkey") ? result["signing-privkey"].as<std::string>()
                                                            : key_dir + "/private_sign_pqc.key";
    std::string sign_pub = result.count("signing-pubkey") ? result["signing-pubkey"].as<std::string>()
                                                          : key_dir + "/public_sign_pqc.key";
    std::string kem_algo = result.count("kem-algo") ? result["kem-algo"].as<std::string>() : "ML-KEM-768";

    std::ifstream pifs(sign_priv, std::ios::binary);
    if (!pifs) { std::cerr << "Error: cannot read " << sign_priv << std::endl; return 1; }
    std::string priv_content((std::istreambuf_iterator<char>(pifs)), std::istreambuf_iterator<char>());
    SecureString pass = nkCryptoToolUtils::getPassphraseIfNeeded(priv_content, SecureString());
    auto owner_priv_der = nkCryptoToolUtils::unwrapFromPem(priv_content, "PRIVATE KEY");
    if (!owner_priv_der) { std::cerr << "Error: parse " << sign_priv << std::endl; return 1; }

    auto backend = ::get_nk_backend();
    auto owner_spki = loadPubSpki(sign_pub);
    if (!owner_spki) { std::cerr << "Error: read " << sign_pub << std::endl; return 1; }
    auto owner_raw = backend->rawPublicKeyFromSpki(*owner_spki);
    if (!owner_raw) { std::cerr << "Error: extract owner raw pubkey (need OpenSSL backend + ML-DSA)" << std::endl; return 1; }

    uint64_t created_at = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::optional<uint64_t> expires_at;
    if (result.count("keybundle-expiry-secs"))
        expires_at = created_at + result["keybundle-expiry-secs"].as<uint64_t>();

    std::vector<nk::keybundle::KeyToBind> keys;
    auto add_enc_ml_kem = [&](const std::string& path) -> int {
        auto spki = loadPubSpki(path); if (!spki) { std::cerr << "Error: read " << path << std::endl; return 1; }
        auto raw = backend->rawPublicKeyFromSpki(*spki); if (!raw) { std::cerr << "Error: extract ML-KEM ek" << std::endl; return 1; }
        keys.push_back({nk::keybundle::KEY_USAGE_ENC, *raw, created_at, expires_at}); return 0;
    };
    auto add_hybrid_p256 = [&](const std::string& path) -> int {
        auto spki = loadPubSpki(path); if (!spki) { std::cerr << "Error: read " << path << std::endl; return 1; }
        keys.push_back({nk::keybundle::KEY_USAGE_HYBRID, *spki, created_at, expires_at}); return 0;
    };

    if (mode == CryptoMode::PQC) { if (add_enc_ml_kem(key_dir + "/public_enc_pqc.key")) return 1; }
    else if (mode == CryptoMode::ECC) { if (add_hybrid_p256(key_dir + "/public_enc_ecc.key")) return 1; }
    else { // Hybrid: C++ names the two halves public_enc_pqc.key (ML-KEM) and
           // public_enc_ecc.key (P-256). The bundle content (raw ek, P-256 SPKI)
           // is what interoperates, not the filenames.
           if (add_enc_ml_kem(key_dir + "/public_enc_pqc.key")) return 1;
           if (add_hybrid_p256(key_dir + "/public_enc_ecc.key")) return 1; }

    auto bundle = nk::keybundle::buildSigned(*owner_priv_der, *owner_raw, handle, created_at, keys, pass);
    if (!bundle) { std::cerr << "Error: build keybundle: " << toString(bundle.error()) << std::endl; return 1; }
    std::ofstream ofs(output, std::ios::binary | std::ios::trunc);
    if (!ofs) { std::cerr << "Error: write " << output << std::endl; return 1; }
    ofs.write(reinterpret_cast<const char*>(bundle->data()), (std::streamsize)bundle->size());

    auto fp = nk::keybundle::ownerFingerprintHex(*owner_raw);
    std::cout << "Wrote signed KeyBundle (" << keys.size() << " key(s), handle \"" << handle
              << "\") to " << output << ".\n"
              << "Share this fingerprint out-of-band so senders can pin your identity:\n  "
              << (fp ? *fp : std::string("?")) << std::endl;
    return 0;
}

// Parse a 64-hex fingerprint into 32 bytes.
std::expected<std::array<uint8_t,32>, CryptoError> parseFpHex(const std::string& hex) {
    if (hex.size() != 64) return std::unexpected(CryptoError::ParameterError);
    std::array<uint8_t,32> out{};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        int hi = nib(hex[2*i]), lo = nib(hex[2*i+1]);
        if (hi < 0 || lo < 0) return std::unexpected(CryptoError::ParameterError);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return out;
}

// --recipient-keybundle: verify the pinned bundle, enforce expiry on the key(s)
// this mode uses, materialise those enc public keys as temp SPKI PEM files, and
// point the recipient-pubkey key_paths at them. Returns temp paths to unlink.
// Mirrors the Rust consume path (raw pubkey encryption is unauthenticated, so a
// pinned signed bundle is required).
std::expected<std::vector<std::string>, CryptoError> consumeRecipientBundle(
    const cxxopts::ParseResult& result, CryptoMode mode, const std::string& kem_algo,
    std::map<std::string,std::string>& key_paths) {
    std::string path = result["recipient-keybundle"].as<std::string>();
    if (!result.count("recipient-fingerprint")) {
        std::cerr << "Error: --recipient-keybundle requires --recipient-fingerprint <64-hex>" << std::endl;
        return std::unexpected(CryptoError::ParameterError);
    }
    auto pin = parseFpHex(result["recipient-fingerprint"].as<std::string>());
    if (!pin) { std::cerr << "Error: bad --recipient-fingerprint" << std::endl; return std::unexpected(pin.error()); }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) { std::cerr << "Error: read " << path << std::endl; return std::unexpected(CryptoError::FileReadError); }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    auto vb = nk::keybundle::parseAndVerify(bytes, *pin);
    if (!vb) { std::cerr << "Error: recipient keybundle rejected: " << toString(vb.error()) << std::endl; return std::unexpected(vb.error()); }

    uint64_t now = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto backend = ::get_nk_backend();

    // Pick the key(s) this mode needs and enforce expiry on exactly those.
    auto pick = [&](uint8_t usage) -> std::expected<std::vector<uint8_t>, CryptoError> {
        for (const auto& k : vb->keys) if (k.key_usage == usage) {
            if (k.expires_at && now > *k.expires_at) {
                std::cerr << "Error: recipient keybundle key expired" << std::endl;
                return std::unexpected(CryptoError::ParameterError);
            }
            return k.target_pk;
        }
        std::cerr << "Error: recipient keybundle lacks the key this mode needs" << std::endl;
        return std::unexpected(CryptoError::ParameterError);
    };

    std::vector<std::string> tmp_paths;
    auto write_tmp_spki = [&](const std::vector<uint8_t>& spki_der, const std::string& tag) -> std::string {
        std::string tp = std::filesystem::temp_directory_path().string() + "/nkct-rcpt-" + tag + "-" +
                         std::to_string((unsigned long)now) + "-" + std::to_string(rand()) + ".pem";
        std::ofstream ofs(tp);
        ofs << nkCryptoToolUtils::wrapToPem(spki_der, "PUBLIC KEY");
        tmp_paths.push_back(tp);
        return tp;
    };

    if (mode == CryptoMode::PQC) {
        auto raw = pick(nk::keybundle::KEY_USAGE_ENC); if (!raw) return std::unexpected(raw.error());
        auto spki = backend->spkiFromRawPublicKey(*raw, kem_algo); if (!spki) return std::unexpected(spki.error());
        key_paths["recipient-pubkey"] = write_tmp_spki(*spki, "mlkem");
    } else if (mode == CryptoMode::ECC) {
        auto spki = pick(nk::keybundle::KEY_USAGE_HYBRID); if (!spki) return std::unexpected(spki.error());
        key_paths["recipient-pubkey"] = write_tmp_spki(*spki, "p256"); // P-256 stored as SPKI already
    } else {
        auto raw = pick(nk::keybundle::KEY_USAGE_ENC); if (!raw) return std::unexpected(raw.error());
        auto spki_kem = backend->spkiFromRawPublicKey(*raw, kem_algo); if (!spki_kem) return std::unexpected(spki_kem.error());
        auto spki_ecc = pick(nk::keybundle::KEY_USAGE_HYBRID); if (!spki_ecc) return std::unexpected(spki_ecc.error());
        key_paths["recipient-mlkem-pubkey"] = write_tmp_spki(*spki_kem, "mlkem");
        key_paths["recipient-ecdh-pubkey"] = write_tmp_spki(*spki_ecc, "p256");
    }
    return tmp_paths;
}

} // namespace

int main(int argc, char* argv[]) {
    cxxopts::Options options("nkCryptoTool", "A command-line tool for advanced cryptographic operations");
    
    options.add_options()
        ("m,mode", "Specify the cryptographic mode: 'ecc', 'pqc', or 'hybrid'", cxxopts::value<std::string>()->default_value("ecc"))
        ("o,output-file", "Path to the output file", cxxopts::value<std::string>())
        ("encrypt", "Perform encryption")
        ("decrypt", "Perform decryption")
        ("sign", "Perform signing")
        ("verify", "Perform verification")
        ("gen-enc-key", "Generate encryption key pair")
        ("gen-sign-key", "Generate signing key pair")
        ("gen-keybundle", "Generate a signed recipient KeyBundle (.nkkb)")
        ("keybundle-handle", "KeyBundle handle/label", cxxopts::value<std::string>())
        ("keybundle-output", "KeyBundle output path", cxxopts::value<std::string>())
        ("keybundle-expiry-secs", "KeyBundle key expiry (seconds from now)", cxxopts::value<uint64_t>())
        ("recipient-keybundle", "Recipient's signed KeyBundle for encryption", cxxopts::value<std::string>())
        ("recipient-fingerprint", "Pinned owner fingerprint (64-hex) for --recipient-keybundle", cxxopts::value<std::string>())
        ("serve-chat", "P2P: listen for one chat peer over iroh (prints a ticket)")
        ("connect", "P2P: connect to a chat peer by its nkct1 ticket", cxxopts::value<std::string>())
        ("allow-unauth", "P2P: accept an anonymous (unauthenticated) peer")
        ("scp-get", "P2P: download REMOTE from the peer (with --connect)", cxxopts::value<std::string>())
        ("scp-local", "P2P: local path for --scp-get", cxxopts::value<std::string>())
        ("key-dir", "Directory to store generated keys", cxxopts::value<std::string>()->default_value("keys"))
        ("recipient-pubkey", "The recipient's public key for encryption", cxxopts::value<std::string>())
        ("recipient-ecdh-pubkey", "The recipient's ECDH public key", cxxopts::value<std::string>())
        ("recipient-mlkem-pubkey", "The recipient's ML-KEM public key", cxxopts::value<std::string>())
        ("user-privkey", "The user's private key for decryption", cxxopts::value<std::string>())
        ("user-ecdh-privkey", "The user's ECDH private key", cxxopts::value<std::string>())
        ("user-mlkem-privkey", "The user's ML-KEM private key", cxxopts::value<std::string>())
        ("signing-privkey", "The signer's private key for signing", cxxopts::value<std::string>())
        ("signing-pubkey", "The signer's public key for verification", cxxopts::value<std::string>())
        ("signature", "Path to the signature file", cxxopts::value<std::string>())
        ("digest-algo", "Hashing algorithm", cxxopts::value<std::string>()->default_value("SHA3-512"))
        ("aead-algo", "AEAD algorithm: 'AES-256-GCM' or 'ChaCha20-Poly1305'", cxxopts::value<std::string>()->default_value("AES-256-GCM"))
        ("kem-algo", "PQC KEM algorithm", cxxopts::value<std::string>()->default_value("ML-KEM-768"))
        ("dsa-algo", "PQC DSA algorithm", cxxopts::value<std::string>()->default_value("ML-DSA-65"))
        ("tpm", "Use TPM to protect private keys")
        ("r,recursive", "Process directories recursively")
        ("force", "Overwrite existing files")
        ("input-dir", "Directory for recursive input", cxxopts::value<std::string>())
        ("output-dir", "Directory for recursive output", cxxopts::value<std::string>())
        ("input-files", "Input files", cxxopts::value<std::vector<std::string>>());

    options.parse_positional({"input-files"});

    try {
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        CryptoConfig config;
        config.mode = get_mode_from_string(result["mode"].as<std::string>());

        if (result.count("gen-keybundle")) {
            std::string kd = result.count("key-dir") ? result["key-dir"].as<std::string>() : "keys";
            return runGenKeybundle(result, config.mode, kd);
        }

        if (result.count("serve-chat") || result.count("connect")) {
#ifdef NKCT_ENABLE_P2P
            std::string sp = result.count("signing-privkey") ? result["signing-privkey"].as<std::string>() : "";
            std::string su = result.count("signing-pubkey")  ? result["signing-pubkey"].as<std::string>()  : "";
            if (result.count("connect")) {
                if (result.count("scp-get")) {
                    std::string local = result.count("scp-local") ? result["scp-local"].as<std::string>()
                                                                  : result["scp-get"].as<std::string>();
                    return nk::p2p::connectScpGet(result["connect"].as<std::string>(),
                                                  result["scp-get"].as<std::string>(), local, sp, su);
                }
                return nk::p2p::connectChat(result["connect"].as<std::string>(), sp, su);
            }
            return nk::p2p::serveChat(sp, su, result.count("allow-unauth") > 0);
#else
            std::cerr << "Error: this build has no P2P support. Rebuild with "
                         "-DNKCT_ENABLE_P2P=ON -DUSE_BACKEND=OpenSSL (needs a Rust toolchain)."
                      << std::endl;
            return 1;
#endif
        }
        config.force = result.count("force") > 0;
        config.is_recursive = result.count("recursive") > 0;
        
        if (result.count("encrypt")) config.operation = Operation::Encrypt;
        else if (result.count("decrypt")) config.operation = Operation::Decrypt;
        else if (result.count("sign")) config.operation = Operation::Sign;
        else if (result.count("verify")) config.operation = Operation::Verify;
        else if (result.count("gen-enc-key")) config.operation = Operation::GenerateEncKey;
        else if (result.count("gen-sign-key")) config.operation = Operation::GenerateSignKey;

        if (result.count("output-file")) config.output_file = result["output-file"].as<std::string>();
        if (result.count("signature")) config.signature_file = result["signature"].as<std::string>();
        
        std::string key_dir = result.count("key-dir") ? result["key-dir"].as<std::string>() : "keys";
        config.key_paths["key-dir"] = key_dir;

        if (result.count("recipient-pubkey")) config.key_paths["recipient-pubkey"] = result["recipient-pubkey"].as<std::string>();
        if (result.count("recipient-ecdh-pubkey")) config.key_paths["recipient-ecdh-pubkey"] = result["recipient-ecdh-pubkey"].as<std::string>();
        if (result.count("recipient-mlkem-pubkey")) config.key_paths["recipient-mlkem-pubkey"] = result["recipient-mlkem-pubkey"].as<std::string>();
        if (result.count("user-privkey")) config.key_paths["user-privkey"] = result["user-privkey"].as<std::string>();
        if (result.count("user-ecdh-privkey")) config.key_paths["user-ecdh-privkey"] = result["user-ecdh-privkey"].as<std::string>();
        if (result.count("user-mlkem-privkey")) config.key_paths["user-mlkem-privkey"] = result["user-mlkem-privkey"].as<std::string>();
        
        // CryptoProcessor.cpp の期待名 (signing-privkey / signing-pubkey) に合わせる
        if (result.count("signing-privkey")) config.key_paths["signing-privkey"] = result["signing-privkey"].as<std::string>();
        if (result.count("signing-pubkey")) config.key_paths["signing-pubkey"] = result["signing-pubkey"].as<std::string>();
        
        if (config.mode == CryptoMode::Hybrid) {
            if (!result.count("recipient-ecdh-pubkey") && !result.count("recipient-pubkey"))
                config.key_paths["recipient-ecdh-pubkey"] = key_dir + "/public_enc_ecc.key";
            if (!result.count("recipient-mlkem-pubkey"))
                config.key_paths["recipient-mlkem-pubkey"] = key_dir + "/public_enc_pqc.key";
            if (!result.count("user-ecdh-privkey") && !result.count("user-privkey"))
                config.key_paths["user-ecdh-privkey"] = key_dir + "/private_enc_ecc.key";
            if (!result.count("user-mlkem-privkey"))
                config.key_paths["user-mlkem-privkey"] = key_dir + "/private_enc_pqc.key";
            
            if (!result.count("signing-privkey"))
                config.key_paths["signing-privkey"] = key_dir + "/private_sign_pqc.key";
            if (!result.count("signing-pubkey"))
                config.key_paths["signing-pubkey"] = key_dir + "/public_sign_pqc.key";
        }

        if (result.count("kem-algo")) {
            config.pqc_kem_algo = result["kem-algo"].as<std::string>();
            config.key_paths["kem-algo"] = config.pqc_kem_algo;
        }
        if (result.count("dsa-algo")) {
            config.pqc_dsa_algo = result["dsa-algo"].as<std::string>();
            config.key_paths["dsa-algo"] = config.pqc_dsa_algo;
        }

        if (config.operation == Operation::GenerateEncKey) {
            if (config.mode == CryptoMode::Hybrid) {
                config.key_paths["public-ecdh-key"] = key_dir + "/public_enc_ecc.key";
                config.key_paths["private-ecdh-key"] = key_dir + "/private_enc_ecc.key";
                config.key_paths["public-mlkem-key"] = key_dir + "/public_enc_pqc.key";
                config.key_paths["private-mlkem-key"] = key_dir + "/private_enc_pqc.key";
                config.key_paths["recipient-ecdh-pubkey"] = config.key_paths["public-ecdh-key"];
                config.key_paths["recipient-mlkem-pubkey"] = config.key_paths["public-mlkem-key"];
                config.key_paths["recipient-pubkey"] = config.key_paths["public-ecdh-key"]; // Fallback
            } else {
                std::string prefix = (config.mode == CryptoMode::PQC) ? "pqc" : "ecc";
                config.key_paths["public-key"] = key_dir + "/public_enc_" + prefix + ".key";
                config.key_paths["private-key"] = key_dir + "/private_enc_" + prefix + ".key";
                config.key_paths["recipient-pubkey"] = config.key_paths["public-key"];
                config.key_paths["user-privkey"] = config.key_paths["private-key"];
            }
        } else if (config.operation == Operation::GenerateSignKey) {
            if (config.mode == CryptoMode::Hybrid) {
                // ハイブリッド署名は現在 PQC 署名のみを想定 (または PQC + ECC)
                // ここでは PQC 署名鍵をデフォルトとする
                config.key_paths["public-key"] = key_dir + "/public_sign_pqc.key";
                config.key_paths["private-key"] = key_dir + "/private_sign_pqc.key";
                config.key_paths["signing-pubkey"] = config.key_paths["public-key"];
                config.key_paths["signing-privkey"] = config.key_paths["private-key"];
            } else {
                std::string prefix = (config.mode == CryptoMode::PQC) ? "pqc" : "ecc";
                config.key_paths["public-key"] = key_dir + "/public_sign_" + prefix + ".key";
                config.key_paths["private-key"] = key_dir + "/private_sign_" + prefix + ".key";
                config.key_paths["signing-pubkey"] = config.key_paths["public-key"];
                config.key_paths["signing-privkey"] = config.key_paths["private-key"];
            }
        }

        if (result.count("digest-algo")) config.digest_algo = result["digest-algo"].as<std::string>();
        if (result.count("aead-algo")) {
            config.aead_algo = result["aead-algo"].as<std::string>();
            config.key_paths["aead-algo"] = config.aead_algo;
        }
        
        bool tpm = result.count("tpm") > 0;
        if (tpm) config.key_paths["use-tpm"] = "true";

        if (config.operation == Operation::GenerateEncKey || 
            config.operation == Operation::GenerateSignKey) {
             config.passphrase = get_and_verify_passphrase("Enter passphrase for new key pair: ");
             config.passphrase_was_provided = true;
        }

        if (result.count("input-files")) {
            config.input_files = result["input-files"].as<std::vector<std::string>>();
        }

        if (config.input_files.empty() && (config.operation == Operation::Encrypt || config.operation == Operation::Decrypt || config.operation == Operation::Sign || config.operation == Operation::Verify)) {
            std::cerr << "Error: No input files specified" << std::endl;
            return 1;
        }

        std::vector<std::string> rcpt_tmp;
        if (config.operation == Operation::Encrypt && result.count("recipient-keybundle")) {
            std::string ka = result.count("kem-algo") ? result["kem-algo"].as<std::string>() : "ML-KEM-768";
            auto tmps = consumeRecipientBundle(result, config.mode, ka, config.key_paths);
            if (!tmps) return 1;
            rcpt_tmp = *tmps;
        }

        struct TmpCleanup { std::vector<std::string>& p; ~TmpCleanup(){ for (auto& f : p) { std::error_code e; std::filesystem::remove(f, e); } } } cleanup{rcpt_tmp};

        CryptoProcessor processor(config);
        
        std::shared_ptr<nk::IKeyProvider> provider;
        if (tpm) {
            auto tpm_provider = std::make_shared<nk::TpmKeyProvider>();
            if (tpm_provider->isAvailable()) {
                provider = tpm_provider;
            } else {
                std::cerr << "Warning: TPM not available, falling back to software provider" << std::endl;
            }
        }
        processor.setKeyProvider(provider);

        if (result.count("recursive")) {
            asio::io_context recursive_io_context;
            config.input_dir = result["input-dir"].as<std::string>();
            config.output_dir = result["output-dir"].as<std::string>();
            
            auto file_operation = [&](const std::filesystem::path& in, const std::filesystem::path& out) {
                CryptoConfig single_config = config;
                single_config.input_files = {in.string()};
                single_config.output_file = out.string();
                CryptoProcessor single_processor(single_config);
                single_processor.setKeyProvider(provider);
                auto future = single_processor.run();
                future.get();
            };

            processDirectory(recursive_io_context, config.input_dir, config.output_dir, file_operation);
        } else {
            auto future = processor.run();
            future.get();
        }

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
