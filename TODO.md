# TODO: nkCryptoTool Technical Debt & Known Issues

## 1. GCM Integrity Check Failure (RESOLVED)
- **Status**: Fixed in April 2026.
- **Root Causes & Solutions**:
    1. **Context Initialization**: OpenSSL 3.x GCM requires a strict initialization order (Cipher -> IVLEN -> Key/IV). Recreating the context with `EVP_CIPHER_CTX_new()` during decryption ensured a clean state.
    2. **Error Queue Interference**: Transient OpenSSL errors from header parsing were interfering with the final tag verification. Adding `ERR_clear_error()` before decryption initialization solved this.
    3. **Exact Header Offsets**: Updated `deserializeHeader()` to return the exact number of bytes consumed, ensuring that the async pipeline starts reading the ciphertext at the precise byte offset.
- **Verification**: Confirmed fix across ECC and PQC modes, with and without TPM, ensuring 100% hash match and successful GCM tag validation.

## 2. TPM Implementation Improvements
- **Current Status**: Envelope Encryption (AES-GCM + TPM Sealing) is implemented and verified for ECC and PQC.
- **Future Enhancements**:
    - Support for TPM-backed authorization (PIN/PCR).
    - Migrate from `system()` calls to `libtpm2-tss` for better performance and error handling (if environment stability allows).
    - Refine cleanup logic for temporary files (`/tmp/nk_...`) in case of unexpected crashes.

## 3. Path Logic Refinement
- **Issue**: Default key path prefixing in `nkCryptoToolMain.cpp` sometimes conflicts with absolute paths in E2E tests.
- **Action Required**: Implement more robust path resolution that respects absolute paths while maintaining user-friendly relative path defaults.
