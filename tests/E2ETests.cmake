# ===================================================================
# End-to-End Test Script for nkCryptoTool
# This script is executed by CTest via `cmake -P`
# ===================================================================

# --- Generic Encryption/Decryption Scenario Function ---
function(run_encryption_scenario MODE USE_PARALLEL PASSPHRASE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if(USE_PARALLEL)
        set(SCENARIO_VARIANT " (in parallel)")
        set(PARALLEL_FLAG "--parallel")
    else()
        set(SCENARIO_VARIANT "")
        set(PARALLEL_FLAG "")
    endif()

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption${SCENARIO_VARIANT}${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Build command arguments ---
    set(ENCRYPT_ARGS --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}" ${PARALLEL_FLAG})
    set(DECRYPT_ARGS --mode "${MODE}" --decrypt -o "${DECRYPTED_FILE}" ${PARALLEL_FLAG} ${PASS_ARGS})

    if("${MODE}" STREQUAL "hybrid")
        list(APPEND ENCRYPT_ARGS --recipient-mlkem-pubkey "${KEY_DIR}/public_enc_hybrid_mlkem.key")
        list(APPEND ENCRYPT_ARGS --recipient-ecdh-pubkey "${KEY_DIR}/public_enc_hybrid_ecdh.key")
        list(APPEND DECRYPT_ARGS --recipient-mlkem-privkey "${KEY_DIR}/private_enc_hybrid_mlkem.key")
        list(APPEND DECRYPT_ARGS --recipient-ecdh-privkey "${KEY_DIR}/private_enc_hybrid_ecdh.key")
    else()
        list(APPEND ENCRYPT_ARGS --recipient-pubkey "${KEY_DIR}/public_enc_${MODE}.key")
        list(APPEND DECRYPT_ARGS --user-privkey "${KEY_DIR}/private_enc_${MODE}.key")
    endif()
    list(APPEND ENCRYPT_ARGS "${TEST_INPUT_FILE}")
    list(APPEND DECRYPT_ARGS "${ENCRYPTED_FILE}")

    # --- Encryption ---
    message(STATUS "  -> Encrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase ${ENCRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase ${DECRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} decryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification ---
    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Decrypted file does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: Info Inspection ---
function(run_info_scenario MODE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Info Inspection")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Encryption ---
    set(ENCRYPT_ARGS --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}")
    if("${MODE}" STREQUAL "hybrid")
        list(APPEND ENCRYPT_ARGS --recipient-mlkem-pubkey "${KEY_DIR}/public_enc_hybrid_mlkem.key")
        list(APPEND ENCRYPT_ARGS --recipient-ecdh-pubkey "${KEY_DIR}/public_enc_hybrid_ecdh.key")
    else()
        list(APPEND ENCRYPT_ARGS --recipient-pubkey "${KEY_DIR}/public_enc_${MODE}.key")
    endif()
    list(APPEND ENCRYPT_ARGS "${TEST_INPUT_FILE}")

    message(STATUS "  -> Encrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase ${ENCRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Info Inspection ---
    message(STATUS "  -> Inspecting encrypted file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --info "${ENCRYPTED_FILE}" OUTPUT_VARIABLE info_output RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} info inspection failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification of output ---
    message(STATUS "  -> Verifying info output...")
    # Using a case-insensitive match by converting output to uppercase for comparison
    string(TOUPPER "${info_output}" info_output_upper)
    if(NOT info_output_upper MATCHES "STRATEGY:.*${SCENARIO_NAME_UPPERCASE}")
        message(STATUS "  [FAILED] Info output does not contain correct strategy/mode: ${info_output}")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Info Inspection")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: TPM Encryption/Decryption ---
function(run_tpm_encryption_scenario MODE PASSPHRASE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} TPM Encryption/Decryption${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation with TPM ---
    message(STATUS "  -> Generating ${MODE} keys with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --tpm --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} TPM key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    get_filename_component(KEY_DIR_ABS "${KEY_DIR}" ABSOLUTE)
    get_filename_component(ENCRYPTED_FILE_ABS "${ENCRYPTED_FILE}" ABSOLUTE)
    get_filename_component(DECRYPTED_FILE_ABS "${DECRYPTED_FILE}" ABSOLUTE)
    get_filename_component(TEST_INPUT_FILE_ABS "${TEST_INPUT_FILE}" ABSOLUTE)

    # --- Encryption ---
    set(ENCRYPT_ARGS --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE_ABS}")
    if("${MODE}" STREQUAL "hybrid")
        list(APPEND ENCRYPT_ARGS --recipient-mlkem-pubkey "${KEY_DIR_ABS}/public_enc_hybrid_mlkem.key")
        list(APPEND ENCRYPT_ARGS --recipient-ecdh-pubkey "${KEY_DIR_ABS}/public_enc_hybrid_ecdh.key")
    else()
        list(APPEND ENCRYPT_ARGS --recipient-pubkey "${KEY_DIR_ABS}/public_enc_${MODE}.key")
    endif()
    list(APPEND ENCRYPT_ARGS "${TEST_INPUT_FILE_ABS}")

    message(STATUS "  -> Encrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase ${ENCRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption with TPM ---
    set(DECRYPT_ARGS --mode "${MODE}" --decrypt --tpm -o "${DECRYPTED_FILE_ABS}" ${PASS_ARGS})
    if("${MODE}" STREQUAL "hybrid")
        list(APPEND DECRYPT_ARGS --recipient-mlkem-privkey "${KEY_DIR_ABS}/private_enc_hybrid_mlkem.key")
        list(APPEND DECRYPT_ARGS --recipient-ecdh-privkey "${KEY_DIR_ABS}/private_enc_hybrid_ecdh.key")
    else()
        list(APPEND DECRYPT_ARGS --user-privkey "${KEY_DIR_ABS}/private_enc_${MODE}.key")
    endif()
    list(APPEND DECRYPT_ARGS "${ENCRYPTED_FILE_ABS}")

    message(STATUS "  -> Decrypting file with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase ${DECRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} TPM decryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification ---
    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Decrypted file does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} TPM Encryption/Decryption")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: TPM Wrap/Unwrap ---
function(run_tpm_wrap_unwrap_scenario MODE PASSPHRASE KEY_TYPE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)
    
    if("${KEY_TYPE}" STREQUAL "sign")
        set(KEY_VARIANT " Signing")
        set(GEN_FLAG "--gen-sign-key")
        set(FILE_PREFIX "private_sign")
    else()
        set(KEY_VARIANT " Encryption")
        set(GEN_FLAG "--gen-enc-key")
        set(FILE_PREFIX "private_enc")
    endif()

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE}${KEY_VARIANT} TPM Wrap/Unwrap${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- 1. Generate Raw Keys ---
    message(STATUS "  -> Generating raw ${MODE}${KEY_VARIANT} keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" ${GEN_FLAG} --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Raw key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    set(RAW_PRIV "${KEY_DIR}/${FILE_PREFIX}_${MODE}.key")
    set(WRAPPED_PRIV "${KEY_DIR}/${FILE_PREFIX}_${MODE}.tpmkey")
    set(UNWRAPPED_PRIV "${KEY_DIR}/${FILE_PREFIX}_${MODE}.rawkey")

    # --- 2. Wrap the Key with TPM ---
    message(STATUS "  -> Wrapping key with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --wrap-existing "${RAW_PRIV}" --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Key wrapping failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    if(NOT EXISTS "${WRAPPED_PRIV}")
        message(STATUS "  [FAILED] Wrapped key file not found: ${WRAPPED_PRIV}")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- 3. Unwrap the Key from TPM ---
    message(STATUS "  -> Unwrapping key from TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --unwrap-key "${WRAPPED_PRIV}" --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Key unwrapping failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    if(NOT EXISTS "${UNWRAPPED_PRIV}")
        message(STATUS "  [FAILED] Unwrapped key file not found: ${UNWRAPPED_PRIV}")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- 4. Verify the Unwrapped Key matches the Original ---
    message(STATUS "  -> Verifying unwrapped key content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${RAW_PRIV}" "${UNWRAPPED_PRIV}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Unwrapped key does not match original raw key.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE}${KEY_VARIANT} TPM Wrap/Unwrap${PASS_DESC}")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: Signing/Verification ---
function(run_signing_scenario MODE USE_TPM PASSPHRASE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if(USE_TPM)
        set(SCENARIO_VARIANT " (with TPM)")
        set(TPM_FLAG "--tpm")
    else()
        set(SCENARIO_VARIANT "")
        set(TPM_FLAG "")
    endif()

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Signing/Verification${SCENARIO_VARIANT}${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(SIGNATURE_FILE "${SCENARIO_DIR}/test.sig")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    get_filename_component(KEY_DIR_ABS "${KEY_DIR}" ABSOLUTE)
    get_filename_component(SIGNATURE_FILE_ABS "${SIGNATURE_FILE}" ABSOLUTE)
    get_filename_component(TEST_INPUT_FILE_ABS "${TEST_INPUT_FILE}" ABSOLUTE)

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} signing keys${SCENARIO_VARIANT}...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-sign-key ${TPM_FLAG} --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file${SCENARIO_VARIANT}...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --sign ${TPM_FLAG} --signature "${SIGNATURE_FILE_ABS}" --signing-privkey "${KEY_DIR_ABS}/private_sign_${MODE}.key" "${TEST_INPUT_FILE_ABS}"
        ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --verify --signature "${SIGNATURE_FILE_ABS}" --signing-pubkey "${KEY_DIR_ABS}/public_sign_${MODE}.key" "${TEST_INPUT_FILE_ABS}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signature verification failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()
    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Signing/Verification${SCENARIO_VARIANT}${PASS_DESC}")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: Regenerate Public Key and Use for Decryption ---
function(run_regenerate_pubkey_test MODE PASSPHRASE USE_TPM)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if(USE_TPM)
        set(SCENARIO_VARIANT " (with TPM)")
        set(TPM_FLAG "--tpm")
    else()
        set(SCENARIO_VARIANT "")
        set(TPM_FLAG "")
    endif()

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption (Regen Pubkey)${SCENARIO_VARIANT}${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
    set(ORIGINAL_PUBLIC_KEY "${KEY_DIR}/public_enc_${MODE}.key")
    set(REGENERATED_PUBLIC_KEY "${KEY_DIR}/public_enc_${MODE}_regenerated.key")
    set(PRIVATE_KEY "${KEY_DIR}/private_enc_${MODE}.key")

    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} keys${SCENARIO_VARIANT}...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key ${TPM_FLAG} --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Regenerate Public Key ---
    message(STATUS "  -> Regenerating public key from private key${SCENARIO_VARIANT}...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --regenerate-pubkey ${TPM_FLAG} "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Compare original and regenerated public keys ---
    message(STATUS "  -> Verifying regenerated public key matches original...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${ORIGINAL_PUBLIC_KEY}" "${REGENERATED_PUBLIC_KEY}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Regenerated public key does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Encryption with regenerated key ---
    message(STATUS "  -> Encrypting file using regenerated key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}" --recipient-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --decrypt ${TPM_FLAG} -o "${DECRYPTED_FILE}" --user-privkey "${PRIVATE_KEY}" ${PASS_ARGS} "${ENCRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} decryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification ---
    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Decrypted file does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption (Regen Pubkey)${SCENARIO_VARIANT}${PASS_DESC}")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: Regenerate Signing Public Key and Use for Verification ---
function(run_regenerate_sign_pubkey_test MODE PASSPHRASE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Signing/Verification (Regen Pubkey)${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(SIGNATURE_FILE "${SCENARIO_DIR}/test.sig")
    set(ORIGINAL_PUBLIC_KEY "${KEY_DIR}/public_sign_${MODE}.key")
    set(REGENERATED_PUBLIC_KEY "${KEY_DIR}/public_sign_${MODE}_regenerated.key")
    set(PRIVATE_KEY "${KEY_DIR}/private_sign_${MODE}.key")

    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} signing keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-sign-key --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Regenerate Public Key ---
    message(STATUS "  -> Regenerating signing public key from private key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --regenerate-pubkey "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Compare original and regenerated public keys ---
    message(STATUS "  -> Verifying regenerated public key matches original...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${ORIGINAL_PUBLIC_KEY}" "${REGENERATED_PUBLIC_KEY}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Regenerated public key does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${PRIVATE_KEY}" ${PASS_ARGS} "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification with regenerated key ---
    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signature verification failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verify signing metadata ---
    message(STATUS "  -> Verifying signing metadata...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --info "${SIGNATURE_FILE}" OUTPUT_VARIABLE info_output RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} info inspection failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # Using a case-insensitive match by converting output to uppercase for comparison
    string(TOUPPER "${info_output}" info_output_upper)
    if(NOT info_output_upper MATCHES "STRATEGY:.*${SCENARIO_NAME_UPPERCASE}")
        message(STATUS "  [FAILED] Info output does not contain correct strategy/mode: ${info_output}")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Signing/Verification (Regen Pubkey)${PASS_DESC}")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: TPM Regenerate Public Key and Use for Decryption ---
function(run_tpm_regenerate_pubkey_test MODE PASSPHRASE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if("${PASSPHRASE}" STREQUAL "")
        set(PASS_ARGS "--no-passphrase")
        set(PASS_DESC " [No Passphrase]")
    else()
        set(PASS_ARGS "--passphrase=${PASSPHRASE}")
        set(PASS_DESC " [With Passphrase]")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption (TPM Regen Pubkey)${PASS_DESC}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
    set(ORIGINAL_PUBLIC_KEY "${KEY_DIR}/public_enc_${MODE}.key")
    set(REGENERATED_PUBLIC_KEY "${KEY_DIR}/public_enc_${MODE}_regenerated.key")
    set(PRIVATE_KEY "${KEY_DIR}/private_enc_${MODE}.key")

    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation with TPM ---
    message(STATUS "  -> Generating ${MODE} keys with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --tpm --key-dir "${KEY_DIR}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} TPM key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    get_filename_component(KEY_DIR_ABS "${KEY_DIR}" ABSOLUTE)
    get_filename_component(ENCRYPTED_FILE_ABS "${ENCRYPTED_FILE}" ABSOLUTE)
    get_filename_component(DECRYPTED_FILE_ABS "${DECRYPTED_FILE}" ABSOLUTE)
    get_filename_component(TEST_INPUT_FILE_ABS "${TEST_INPUT_FILE}" ABSOLUTE)

    # --- Regenerate Public Key with TPM ---
    message(STATUS "  -> Regenerating public key from private key with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --regenerate-pubkey --tpm "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" ${PASS_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Compare original and regenerated public keys ---
    message(STATUS "  -> Verifying regenerated public key matches original...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${ORIGINAL_PUBLIC_KEY}" "${REGENERATED_PUBLIC_KEY}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Regenerated public key does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Encryption with regenerated key ---
    message(STATUS "  -> Encrypting file using regenerated key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE_ABS}" --recipient-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE_ABS}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --decrypt --tpm -o "${DECRYPTED_FILE_ABS}" --user-privkey "${PRIVATE_KEY}" ${PASS_ARGS} "${ENCRYPTED_FILE_ABS}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} decryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification ---
    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Decrypted file does not match original.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verify encryption metadata ---
    message(STATUS "  -> Verifying encryption metadata...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --info "${ENCRYPTED_FILE_ABS}" OUTPUT_VARIABLE info_output RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} info inspection failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # Using a case-insensitive match by converting output to uppercase for comparison
    string(TOUPPER "${info_output}" info_output_upper)
    if(NOT info_output_upper MATCHES "STRATEGY:.*${SCENARIO_NAME_UPPERCASE}")
        message(STATUS "  [FAILED] Info output does not contain correct strategy/mode: ${info_output}")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption (TPM Regen Pubkey)${PASS_DESC}")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# Logic to execute a specific scenario when called via cmake -P
if(DEFINED SCENARIO_MODE)
    if(NOT DEFINED SCENARIO_PASSPHRASE)
        set(SCENARIO_PASSPHRASE "")
    endif()

    # --- Check for TPM availability if requested ---
    if(SCENARIO_TPM OR SCENARIO_WRAP)
        message(STATUS "Checking for TPM functionality before running scenario...")
        # Try a simple TPM key generation to see if it works
        execute_process(COMMAND "${NK_TOOL_EXE}" --mode ecc --gen-enc-key --tpm --no-passphrase --key-dir "${TEST_OUTPUT_DIR}/tpm_check"
                        RESULT_VARIABLE tpm_res
                        OUTPUT_VARIABLE tpm_out
                        ERROR_VARIABLE tpm_err)
        file(REMOVE_RECURSE "${TEST_OUTPUT_DIR}/tpm_check")
        
        if(NOT tpm_res EQUAL 0)
            message(STATUS "TPM is NOT available or NOT correctly configured.")
            message(STATUS "TPM Error: ${tpm_err}")
            message(STATUS "Skipping TPM-related test scenario.")
            return()
        endif()
        message(STATUS "TPM is functional. Proceeding with the scenario.")
    endif()

    if(SCENARIO_SIGNING)
        run_signing_scenario(${SCENARIO_MODE} ${SCENARIO_TPM} "${SCENARIO_PASSPHRASE}")
    elseif(SCENARIO_REGENERATE_PUBKEY)
        run_regenerate_pubkey_test(${SCENARIO_MODE} "${SCENARIO_PASSPHRASE}" ${SCENARIO_TPM})
    elseif(SCENARIO_REGENERATE_SIGN_PUBKEY)
        run_regenerate_sign_pubkey_test(${SCENARIO_MODE} "${SCENARIO_PASSPHRASE}")
    elseif(SCENARIO_INFO)
        run_info_scenario(${SCENARIO_MODE})
    elseif(SCENARIO_TPM)
        if(SCENARIO_REGENERATE_PUBKEY)
            run_tpm_regenerate_pubkey_test(${SCENARIO_MODE} "${SCENARIO_PASSPHRASE}")
        else()
            run_tpm_encryption_scenario(${SCENARIO_MODE} "${SCENARIO_PASSPHRASE}")
        endif()
    elseif(SCENARIO_WRAP)
        if(NOT DEFINED SCENARIO_KEY_TYPE)
            set(SCENARIO_KEY_TYPE "enc")
        endif()
        run_tpm_wrap_unwrap_scenario(${SCENARIO_MODE} "${SCENARIO_PASSPHRASE}" ${SCENARIO_KEY_TYPE})
    else()
        run_encryption_scenario(${SCENARIO_MODE} ${SCENARIO_PARALLEL} "${SCENARIO_PASSPHRASE}")
    endif()
    # Exit with the test result
    if(TEST_RESULT EQUAL 0)
        message(STATUS "Scenario ${SCENARIO_MODE} completed successfully.")
    else()
        message(FATAL_ERROR "Scenario ${SCENARIO_MODE} failed.")
    endif()
endif()
