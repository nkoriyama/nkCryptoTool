# Security Policy

## Overview

nkCryptoTool is designed with a strong focus on minimizing exposure of sensitive key material.
The architecture separates cryptographic operations from key protection and enforces strict memory lifecycle controls.

---

## Security Design Principles

### 1. Ephemeral Key Usage

Sensitive data protection keys (e.g., AES keys) are:

* Generated or derived only when needed
* Never persisted to disk
* Stored only in memory for the shortest possible duration
* Key lifetime is strictly bound to the processing scope and does not exceed the lifetime of the owning object.

Keys are derived using HKDF and exist only during active cryptographic operations.

---

### 2. Memory Protection

Sensitive data is protected in memory using:

* Custom `SecureAllocator`
* `mlock` to prevent swapping to disk
* Explicit zeroization using `OPENSSL_cleanse`

All sensitive buffers are stored in secure containers (e.g., `SecureVector`).

---

### 3. Guaranteed Cleanup (RAII)

Key material is tied to object lifetime using C++ RAII:

* Destructors are guaranteed to run during normal execution and exception-based stack unwinding
* Sensitive buffers are explicitly wiped before deallocation
* Allocator-level zeroization provides a fail-safe mechanism

---

### 4. Secure Key Management Abstraction

Key handling is abstracted via `IKeyProvider`:

* Supports TPM-backed protection via wrapping/unwrapping
* Decouples cryptographic operations from key storage
* Enables future extension (e.g., KMS, HSM)

The system does not rely on TPM for bulk encryption, only for secure key wrapping.

---

### 5. TPM Security

When TPM is used:

* Operations are performed using TPM 2.0 HMAC sessions
* No secrets are passed via command-line arguments
* Secure process execution avoids shell invocation (`posix_spawn`)

---

### 6. Process-Level Hardening

To prevent sensitive data leakage:

* Core dumps are disabled at process startup (`setrlimit(RLIMIT_CORE, 0)`)
* Shell execution (`system()`) is not used
* Command execution is performed with argument vectors (no shell expansion)

---

## Security Boundaries

### Guaranteed Protections

The system ensures:

* No key material is written to disk
* No exposure through command-line arguments
* Memory is wiped on normal execution and exception paths
* No cross-process memory leakage (enforced by OS isolation)

---

### Known Limitations

The following are outside the scope of user-space protections:

* Abrupt process termination (e.g., `SIGKILL`, `abort`, OOM killer) prevents destructor execution
* Physical memory attacks (e.g., cold boot attacks)
* Compromised or untrusted operating system kernels
* Privileged attackers (e.g., root access, ptrace)

In such cases:

* Sensitive data may temporarily remain in RAM
* However, it is never written to disk due to `mlock` and disabled core dumps

---

## Threat Model

This tool is designed to protect against:

* Accidental data leakage
* Memory scraping from user-space processes
* Command injection attacks
* Disk persistence of sensitive material

**Assumed attacker capabilities:**
* Unprivileged local user
* Ability to inspect process memory (limited)
* No kernel or root-level access

This tool does **not** defend against:

* Physical attacks on memory hardware
* Kernel-level compromise
* Advanced side-channel attacks

---

## Best Practices for Deployment

For maximum security:

* Run on a trusted operating system
* Disable core dumps system-wide if possible
* Restrict access to the host (no untrusted users)
* Avoid running with unnecessary privileges

---

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

* Open an issue (if non-sensitive), or
* Contact the maintainer privately

Please include:

* Description of the issue
* Steps to reproduce
* Potential impact

---

## Summary

nkCryptoTool enforces a strict security model:

* Keys are ephemeral
* Memory is protected and wiped
* Disk exposure is prevented
* Security boundaries are explicitly defined

This design reflects the practical limits of user-space cryptographic security while maximizing protection within those constraints.

**This document reflects the actual implementation and is kept in sync with the codebase.**
