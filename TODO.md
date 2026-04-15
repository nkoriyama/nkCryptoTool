# TODO: nkCryptoTool Technical Debt & Known Issues

## 1. GCM Integrity Check Failure (RESOLVED)
- **Status**: Fixed in April 2026.
- **Verification**: Manually confirmed success with ECC, PQC, and Hybrid modes using absolute paths and manual command execution. Fix involved strict GCM initialization order and clearing OpenSSL error queues.

## 2. E2E Test Suite Failures (Pending Investigation)
- **Current Status**: E2E test pass rate is ~55%. TPM encryption/decryption tests generally pass, but Hybrid and Signing scenarios fail.
- **Issue A: Hybrid Mode "Invalid argument"**:
    - **Symptom**: `E2E_Hybrid_Encryption` fails during the encryption stage.
    - **Analysis**: Likely caused by internal state mismatch (algorithm names or key mappings) when `HybridStrategy` delegates to sub-strategies. Manual reproduction also shows intermittent failures.
- **Issue B: Wrap/Unwrap File Path Mismatch**:
    - **Symptom**: `Wrapped key file not found`.
    - **Analysis**: `TPMUtils` now uses randomized temporary files (`/tmp/nk_...`) for thread safety and parallel E2E execution. However, the E2E test script expects specific output file names in relative directories.
- **Issue C: Async Signing Race Conditions**:
    - **Symptom**: `Input/output error` during signing or verification.
    - **Analysis**: CLI exit might be occurring before the asynchronous coroutines have completely flushed data to disk or finalized the OpenSSL context.

## 3. TPM Implementation Improvements
- **Current Status**: Envelope Encryption (AES-GCM + TPM Sealing) is implemented and verified for ECC and PQC.
- **Future Enhancements**:
    - Refine `TPMUtils` to balance between thread-safe random paths and E2E-friendly deterministic paths (perhaps via an environment variable).
    - Support for TPM-backed authorization (PIN/PCR).
    - Migrate from `system()` calls to `libtpm2-tss` for better performance.

