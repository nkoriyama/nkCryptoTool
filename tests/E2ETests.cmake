# ===================================================================
# End-to-End Test Script for nkCryptoTool
# This script is executed by CTest via `cmake -P`
# ===================================================================

# --- Generic Encryption/Decryption Scenario Function ---
# This function handles a full encryption/decryption cycle for any mode.
#
# Arguments:
#   MODE:         The crypto mode (ecc, pqc, hybrid)
#   USE_COMPRESS: BOOL true to enable lz4 compression, false otherwise
#   USE_PARALLEL: BOOL true to enable parallel processing, false otherwise
#   USE_PIPELINE: BOOL true to enable pipeline processing, false otherwise
#
function(run_encryption_scenario MODE USE_COMPRESS USE_PARALLEL USE_PIPELINE)
    set(SCENARIO_NAME_UPPERCASE "${MODE}")
    string(TOUPPER "${SCENARIO_NAME_UPPERCASE}" SCENARIO_NAME_UPPERCASE)

    # --- Determine scenario name and suffix based on options ---
    if(USE_COMPRESS)
        set(SCENARIO_VARIANT " (with LZ4 compression)")
        set(SCENARIO_SUFFIX "_compressed")
    elseif(USE_PARALLEL)
        set(SCENARIO_VARIANT " (in parallel)")
        set(SCENARIO_SUFFIX "_parallel")
    elseif(USE_PIPELINE)
        set(SCENARIO_VARIANT " (in pipeline)")
        set(SCENARIO_SUFFIX "_pipeline")
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
        message(FATAL_ERROR "  [FAILED] ${SCENARIO_NAME_UPPERCASE} key generation failed.")
    endif()

    # --- Build command arguments ---
    set(ENCRYPT_ARGS --mode "${MODE}" --encrypt -o "${ENCRYPTED_FILE}")
    set(DECRYPT_ARGS --mode "${MODE}" --decrypt -o "${DECRYPTED_FILE}")

    if(USE_COMPRESS)
        list(APPEND ENCRYPT_ARGS --compress lz4)
    endif()

    if(USE_PARALLEL)
        list(APPEND ENCRYPT_ARGS --parallel)
        list(APPEND DECRYPT_ARGS --parallel)
    endif()
    
    if(USE_PIPELINE)
        list(APPEND ENCRYPT_ARGS --pipeline)
        list(APPEND DECRYPT_ARGS --pipeline)
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
        message(FATAL_ERROR "  [FAILED] ${SCENARIO_NAME_UPPERCASE} encryption failed.")
    endif()

    # --- Decryption ---
    message(STATUS "  -> Decrypting file...")
    execute_process(COMMAND "${NK_TOOL_EXE}" ${DECRYPT_ARGS} RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ${SCENARIO_NAME_UPPERCASE} decryption failed.")
    endif()

    # --- Verification ---
    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Verification failed: Decrypted file does not match original.")
    endif()

    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Encryption/Decryption${SCENARIO_VARIANT}")
endfunction()


# --- Scenario Definition: Signing/Verification (remains specific) ---
function(run_signing_scenario MODE)
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
        message(FATAL_ERROR "  [FAILED] ${SCENARIO_NAME_UPPERCASE} sign key generation failed.")
    endif()

    message(STATUS "  -> Signing file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${KEY_DIR}/private_sign_${MODE}.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signing failed.")
    endif()

    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode "${MODE}" --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${KEY_DIR}/public_sign_${MODE}.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ${SCENARIO_NAME_UPPERCASE} signature verification failed.")
    endif()
    message(STATUS "  [PASSED] Scenario: ${SCENARIO_NAME_UPPERCASE} Signing/Verification")
endfunction()


# ===================================================================
# --- Main script execution: Call all scenarios
# ===================================================================

# --- Run Standard Encryption Scenarios (without compression) ---
run_encryption_scenario(hybrid OFF OFF OFF)
run_encryption_scenario(pqc    OFF OFF OFF)
run_encryption_scenario(ecc    OFF OFF OFF)

# --- Run Encryption Scenarios (WITH compression) ---
run_encryption_scenario(hybrid ON  OFF OFF)
run_encryption_scenario(pqc    ON  OFF OFF)
run_encryption_scenario(ecc    ON  OFF OFF)

# --- Run Parallel Encryption Scenarios (compression is not supported) ---
run_encryption_scenario(pqc    OFF ON  OFF)
run_encryption_scenario(ecc    OFF ON  OFF)

# --- ★ Run Pipeline Encryption Scenarios (compression/parallel are not supported) ---
run_encryption_scenario(ecc    OFF OFF ON)

# --- Run Signing Scenarios ---
run_signing_scenario(pqc)
run_signing_scenario(ecc)
