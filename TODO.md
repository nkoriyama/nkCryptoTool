# TODO: nkCryptoTool Technical Debt & Known Issues

## 1. GCM Integrity Check Failure (Pending Investigation)
- **Issue**: AES-GCM decryption often fails at the finalization stage (`EVP_DecryptFinal_ex`) with "Signature verification failed", resulting in an "Input/output error" in the CLI.
- **Current Status**: 
    - **Crucially, the decrypted data is 100% correct and matches the original file hash.**
    - The issue appears in both TPM and non-TPM (normal) modes.
    - Extensive testing shows that HKDF-derived keys, IVs, and salts are consistent between encryption and decryption.
- **Suspected Causes**:
    - Interaction between `PipelineManager` (async I/O) and OpenSSL GCM context. Possible byte offset mismatch when identifying the ciphertext vs. the 16-byte tag at the end of the file.
    - OpenSSL 3.x specific behavior regarding GCM context reuse or parameter setting order.
- **Action Required**: 
    - Deep dive into `nkCryptoToolBase::decryptFileWithPipeline` offset logic.
    - Verify if `EVP_EncryptFinal_ex` contributes non-zero length to ciphertext during encryption that is not accounted for during decryption.

## 2. TPM Implementation Improvements
- **Current Status**: Envelope Encryption (AES-GCM + TPM Sealing) is implemented and verified for ECC and PQC.
- **Future Enhancements**:
    - Support for TPM-backed authorization (PIN/PCR).
    - Migrate from `system()` calls to `libtpm2-tss` for better performance and error handling (if environment stability allows).
    - Refine cleanup logic for temporary files (`/tmp/nk_...`) in case of unexpected crashes.

## 3. Path Logic Refinement
- **Issue**: Default key path prefixing in `nkCryptoToolMain.cpp` sometimes conflicts with absolute paths in E2E tests.
- **Action Required**: Implement more robust path resolution that respects absolute paths while maintaining user-friendly relative path defaults.
