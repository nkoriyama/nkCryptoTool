# ===================================================================
# End-to-End Test Script for nkCryptoTool
# This script is executed by CTest via `cmake -P`
# ===================================================================

# --- Generic Encryption/Decryption Scenario Function ---
function(run_encryption_scenario MODE USE_PARALLEL)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    if(USE_PARALLEL)
        set(SCENARIO_VARIANT " (in parallel)")
        set(SCENARIO_SUFFIX "_parallel")
    else()
        set(SCENARIO_VARIANT "")
        set(SCENARIO_SUFFIX "")
    endif()

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption${SCENARIO_VARIANT}")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
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

    # --- Build command arguments ---
    set(ENCRYPT_ARGS --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}")
    set(DECRYPT_ARGS --mode "${MODE}" --decrypt -o "${DECRYPTED_FILE}")

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
function(run_tpm_encryption_scenario MODE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} TPM Encryption/Decryption")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation with TPM ---
    message(STATUS "  -> Generating ${MODE} keys with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --tpm --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
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
    set(DECRYPT_ARGS --mode "${MODE}" --decrypt --tpm -o "${DECRYPTED_FILE_ABS}")
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
function(run_tpm_wrap_unwrap_scenario MODE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} TPM Wrap/Unwrap")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- 1. Generate Raw Keys ---
    message(STATUS "  -> Generating raw ${MODE} keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Raw key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    set(RAW_PRIV "${KEY_DIR}/private_enc_${MODE}.key")
    set(WRAPPED_PRIV "${KEY_DIR}/private_enc_${MODE}.tpmkey")
    set(UNWRAPPED_PRIV "${KEY_DIR}/private_enc_${MODE}.rawkey")

    # --- 2. Wrap the Key with TPM ---
    message(STATUS "  -> Wrapping key with TPM...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --wrap-existing "${RAW_PRIV}" --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --unwrap-key "${WRAPPED_PRIV}" --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
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
    # Note: We compare original raw vs unwrapped raw. They should be identical PEMs.
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${RAW_PRIV}" "${UNWRAPPED_PRIV}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] Verification failed: Unwrapped key does not match original raw key.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} TPM Wrap/Unwrap")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: Signing/Verification ---
function(run_signing_scenario MODE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Signing/Verification")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(SIGNATURE_FILE "${SCENARIO_DIR}/test.sig")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} signing keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-sign-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${KEY_DIR}/private_sign_${MODE}.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${KEY_DIR}/public_sign_${MODE}.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signature verification failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()
    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Signing/Verification")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# --- Scenario Definition: Regenerate Public Key and Use for Decryption ---
function(run_regenerate_pubkey_test MODE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption")
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
    message(STATUS "  -> Generating ${MODE} keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Regenerate Public Key ---
    message(STATUS "  -> Regenerating public key from private key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --regenerate-pubkey "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Encryption with regenerated key ---
    message(STATUS "  -> Encrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}" --recipient-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --decrypt -o "${DECRYPTED_FILE}" --user-privkey "${PRIVATE_KEY}" "${ENCRYPTED_FILE}" RESULT_VARIABLE res)
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

# --- Scenario Definition: Regenerate Signing Public Key and Use for Verification ---
function(run_regenerate_sign_pubkey_test MODE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption")
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --gen-sign-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Regenerate Public Key ---
    message(STATUS "  -> Regenerating signing public key from private key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --regenerate-pubkey "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --no-passphrase --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${PRIVATE_KEY}" "${TEST_INPUT_FILE}"
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
    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption")
    set(TEST_RESULT 0 PARENT_SCOPE)
endfunction()

# Logic to execute a specific scenario when called via cmake -P
if(DEFINED SCENARIO_MODE)
    if(SCENARIO_SIGNING)
        run_signing_scenario(${SCENARIO_MODE})
    elseif(SCENARIO_REGENERATE_PUBKEY)
        run_regenerate_pubkey_test(${SCENARIO_MODE})
    elseif(SCENARIO_REGENERATE_SIGN_PUBKEY)
        run_regenerate_sign_pubkey_test(${SCENARIO_MODE})
    elseif(SCENARIO_INFO)
        run_info_scenario(${SCENARIO_MODE})
    elseif(SCENARIO_TPM)
        run_tpm_encryption_scenario(${SCENARIO_MODE})
    elseif(SCENARIO_WRAP)
        run_tpm_wrap_unwrap_scenario(${SCENARIO_MODE})
    else()
        run_encryption_scenario(${SCENARIO_MODE} ${SCENARIO_PARALLEL})
    endif()
    # Exit with the test result
    if(TEST_RESULT EQUAL 0)
        message(STATUS "Scenario ${SCENARIO_MODE} completed successfully.")
    else()
        message(FATAL_ERROR "Scenario ${SCENARIO_MODE} failed.")
    endif()
endif()
