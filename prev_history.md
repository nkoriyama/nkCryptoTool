# Project History

This document outlines the development history of the nkCryptoTool project, from its initial commit to its current state.

## 🐣 Initial Phase (April 2025)

*   **2025-04-08:** The project began with an "Initial Commit". At this stage, it was a simple command-line tool for basic encryption and decryption.

## 🔒 ECC and Security Enhancements (Mid-May 2025)

*   **2025-05-14:** **ECC (Elliptic Curve Cryptography)** was introduced, significantly strengthening the tool's cryptographic capabilities.
*   **2025-05-15:** Security was further enhanced by:
    *   Implementing **ECDH (Elliptic Curve Diffie-Hellman)** for secure key exchange.
    *   Adding the use of `OPENSSL_cleanse` to securely zero out sensitive data in memory, mitigating risks of information leakage.
*   **2025-05-18:** **Digital signature and verification** capabilities were added, allowing for data integrity and sender authentication.

## 🏗️ Major Refactoring and PQC Integration (Late May 2025)

This phase marked a significant architectural evolution in preparation for future challenges.

*   **2025-05-24:** The codebase was refactored into a class-based structure (`nkCryptoToolBase`, `nkCryptoToolECC`, etc.) to improve modularity and prepare for the integration of Post-Quantum Cryptography (PQC).
*   **2025-05-25:** A **CMake build system** was introduced, professionalizing the build process and improving cross-platform compatibility.
*   **2025-05-27:** **PQC (Post-Quantum Cryptography)** support was implemented for both encryption/decryption and digital signatures. This made the tool resilient against potential threats from future quantum computers.
*   **2025-05-28:** Documentation was updated to reflect the new PQC features.

## ✨ Final Touches (End of May 2025)

*   **2025-05-31:** The project underwent final refinements, including changing the tool and class names to be more intuitive and removing obsolete files.

## Summary

The project evolved from a basic encryption utility into a sophisticated, multi-functional cryptography tool. It progressively adopted modern cryptographic standards like ECC and ECDH, and ultimately future-proofed itself by integrating Post-Quantum Cryptography. The transition to a class-based, CMake-managed structure represents a key milestone in its maturation into a robust and extensible software project.
