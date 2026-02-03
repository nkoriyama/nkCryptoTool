# ===================================================================
# End-to-End Test Script for nkCryptoTool
# This script is executed by CTest via `cmake -P`
# ===================================================================

# --- Generic Encryption/Decryption Scenario Function ---
# This function handles a full encryption/decryption cycle for any mode.
#
# Arguments:
#   MODE:         The crypto mode (ecc, pqc, hybrid)
#   USE_PARALLEL: BOOL true to enable parallel processing, false otherwise
#
function(run_encryption_scenario MODE USE_PARALLEL)
    set(TEST_RESULT 0)

    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    # --- Determine scenario name and suffix based on options ---
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

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/${MODE}_encryption${SCENARIO_SUFFIX}")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    # --- Key Generation ---
    message(STATUS "  -> Generating ${MODE} keys...")
    # For hybrid mode, we generate both key types. Other modes generate their specific key.
    if("${MODE}" STREQUAL "hybrid")
        execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
    else()
        execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-enc-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
    endif()

    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Build command arguments ---
    set(ENCRYPT_ARGS --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}")
    set(DECRYPT_ARGS --mode "${MODE}" --decrypt -o "${DECRYPTED_FILE}")

    if(USE_PARALLEL)
        list(APPEND ENCRYPT_ARGS --parallel)
        list(APPEND DECRYPT_ARGS --parallel)
    endif()

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

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption${SCENARIO_VARIANT}")
endfunction()


# --- Scenario Definition: Signing/Verification (remains specific) ---
function(run_signing_scenario MODE)
    set(TEST_RESULT 0)

    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Signing/Verification")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/${MODE}_signing")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(SIGNATURE_FILE "${SCENARIO_DIR}/test.sig")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    message(STATUS "  -> Generating ${MODE} signing keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --gen-sign-key --key-dir "${KEY_DIR}" --passphrase "" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} sign key generation failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  -> Signing file...")
    execute_process(COMMAND env)
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${KEY_DIR}/private_sign_${MODE}.key" "${TEST_INPUT_FILE}"
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
endfunction()

# --- Scenario Definition: Regenerate Signing Public Key and Use for Verification ---
function(run_regenerate_sign_pubkey_test MODE)
    set(TEST_RESULT 0)

    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ${SCENARIO_NAME_UPPERCASE} Regenerate Signing Public Key Test")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/${MODE}_regenerate_sign_pubkey")
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
    execute_process(COMMAND "${NK_TOOL_EXE}" --regenerate-pubkey "${PRIVATE_KEY}" "${REGENERATED_PUBLIC_KEY}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing public key regeneration failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Signing ---
    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${PRIVATE_KEY}" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    # --- Verification using Regenerated Public Key ---
    message(STATUS "  -> Verifying signature using regenerated public key...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${REGENERATED_PUBLIC_KEY}" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(STATUS "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signature verification with regenerated key failed.")
        set(TEST_RESULT 1 PARENT_SCOPE)
        return()
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Regenerate Signing Public Key Test")
endfunction()






# ===================================================================
# --- Main script execution: Call all scenarios
# ===================================================================

# This part is now commented out as individual tests will be added from CMakeLists.txt
# --- Run Standard Encryption Scenarios ---
# run_encryption_scenario(hybrid OFF OFF)
# run_encryption_scenario(pqc    OFF OFF)
# run_encryption_scenario(ecc    OFF OFF)

# --- Run Parallel Encryption Scenarios ---
# run_encryption_scenario(hybrid ON  OFF)
# run_encryption_scenario(pqc    ON  OFF)
# run_encryption_scenario(ecc    ON  OFF)

# --- Run Pipeline Encryption Scenarios ---
# run_encryption_scenario(pqc    OFF ON)
# run_encryption_scenario(hybrid OFF ON)
# run_encryption_scenario(ecc    OFF ON)

# --- Run Signing Scenarios ---
# run_signing_scenario(pqc)
# run_signing_scenario(ecc)

# Macro to define an E2E test for CTest
macro(add_e2e_test TEST_NAME MODE PARALLEL SIGNING REGENERATE_PUBKEY REGENERATE_SIGN_PUBKEY)
    add_test(
        NAME ${TEST_NAME}
        COMMAND "${CMAKE_COMMAND}"
            -D NK_TOOL_EXE=$<TARGET_FILE:nkCryptoTool>
            -D TEST_INPUT_FILE=${E2E_TEST_INPUT_FILE}
            -D TEST_OUTPUT_DIR=${CMAKE_BINARY_DIR}/E2ETestOutput
            -P "${CMAKE_SOURCE_DIR}/tests/E2ETests.cmake"
            -D SCENARIO_MODE=${MODE}
            -D SCENARIO_PARALLEL=${PARALLEL}
            -D SCENARIO_SIGNING=${SIGNING}
            -D SCENARIO_REGENERATE_PUBKEY=${REGENERATE_PUBKEY}
            -D SCENARIO_REGENERATE_SIGN_PUBKEY=${REGENERATE_SIGN_PUBKEY}
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    )
endmacro()

# Logic to execute a specific scenario when called via cmake -P
if(DEFINED SCENARIO_MODE)
    if(SCENARIO_SIGNING)
        run_signing_scenario(${SCENARIO_MODE})
    elseif(SCENARIO_REGENERATE_PUBKEY)
        run_regenerate_pubkey_test(${SCENARIO_MODE})
    elseif(SCENARIO_REGENERATE_SIGN_PUBKEY)
        run_regenerate_sign_pubkey_test(${SCENARIO_MODE})
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
