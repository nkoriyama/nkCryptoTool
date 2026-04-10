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
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
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
    execute_process(COMMAND "${NK_TOOL_EXE}" ${ENCRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" ${DECRYPT_ARGS} RESULT_VARIABLE res)
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
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
    execute_process(COMMAND "${NK_TOOL_EXE}" ${ENCRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Info Inspection ---
    message(STATUS "  -> Inspecting encrypted file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --info "${ENCRYPTED_FILE}" OUTPUT_VARIABLE info_output RESULT_VARIABLE res)
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-sign-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${KEY_DIR}/private_sign_${MODE}.key" --passphrase "" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${KEY_DIR}/public_sign_${MODE}.key" "${TEST_INPUT_FILE}"
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Regenerate Public Key ---
    message(STATUS "  -> Regenerating public key from private key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --regenerate-pubkey "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" --passphrase "" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Encryption with regenerated key ---
    message(STATUS "  -> Encrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}" --recipient-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --decrypt -o "${DECRYPTED_FILE}" --user-privkey "${PRIVATE_KEY}" --passphrase "" "${ENCRYPTED_FILE}" RESULT_VARIABLE res)
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-sign-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Regenerate Public Key ---
    message(STATUS "  -> Regenerating signing public key from private key...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --regenerate-pubkey "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" --passphrase "" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${PRIVATE_KEY}" --passphrase "" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification with regenerated key ---
    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE}"
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
