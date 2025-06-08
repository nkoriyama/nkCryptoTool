# End-to-End Test Script for nkCryptoTool
# This script is executed by CTest via `cmake -P`

# --- Scenario Definition: Hybrid Encryption/Decryption ---
function(run_hybrid_encryption_scenario)
    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: Hybrid Encryption/Decryption")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/hybrid_encryption")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted_hybrid.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted_hybrid.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    message(STATUS "  -> Generating hybrid keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode hybrid --gen-enc-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Hybrid key generation failed.")
    endif()

    message(STATUS "  -> Encrypting file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode hybrid --encrypt
                --recipient-mlkem-pubkey "${KEY_DIR}/public_enc_hybrid_mlkem.key"
                --recipient-ecdh-pubkey "${KEY_DIR}/public_enc_hybrid_ecdh.key"
                -o "${ENCRYPTED_FILE}" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Hybrid encryption failed.")
    endif()

    message(STATUS "  -> Decrypting file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode hybrid --decrypt
                --recipient-mlkem-privkey "${KEY_DIR}/private_enc_hybrid_mlkem.key"
                --recipient-ecdh-privkey "${KEY_DIR}/private_enc_hybrid_ecdh.key"
                -o "${DECRYPTED_FILE}" "${ENCRYPTED_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Hybrid decryption failed.")
    endif()

    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Verification failed: Decrypted hybrid file does not match original.")
    endif()
    message(STATUS "  [PASSED] Scenario: Hybrid Encryption/Decryption")
endfunction()


# --- Scenario Definition: PQC Encryption/Decryption ---
function(run_pqc_encryption_scenario)
    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: PQC Encryption/Decryption")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/pqc_encryption")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted_pqc.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted_pqc.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    message(STATUS "  -> Generating PQC encryption keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode pqc --gen-enc-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] PQC enc key generation failed.")
    endif()

    message(STATUS "  -> Encrypting file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode pqc --encrypt --recipient-pubkey "${KEY_DIR}/public_enc_pqc.key" -o "${ENCRYPTED_FILE}" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] PQC encryption failed.")
    endif()

    message(STATUS "  -> Decrypting file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode pqc --decrypt --user-privkey "${KEY_DIR}/private_enc_pqc.key" -o "${DECRYPTED_FILE}" "${ENCRYPTED_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] PQC decryption failed.")
    endif()

    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Verification failed: Decrypted PQC file does not match original.")
    endif()
    message(STATUS "  [PASSED] Scenario: PQC Encryption/Decryption")
endfunction()


# --- Scenario Definition: ECC Encryption/Decryption ---
function(run_ecc_encryption_scenario)
    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ECC Encryption/Decryption")
    message(STATUS "=============================================")
    
    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/ecc_encryption")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(ENCRYPTED_FILE "${SCENARIO_DIR}/encrypted_ecc.bin")
    set(DECRYPTED_FILE "${SCENARIO_DIR}/decrypted_ecc.txt")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    message(STATUS "  -> Generating ECC encryption keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode ecc --gen-enc-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ECC enc key generation failed.")
    endif()

    message(STATUS "  -> Encrypting file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode ecc --encrypt --recipient-pubkey "${KEY_DIR}/public_enc_ecc.key" -o "${ENCRYPTED_FILE}" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ECC encryption failed.")
    endif()

    message(STATUS "  -> Decrypting file...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode ecc --decrypt --user-privkey "${KEY_DIR}/private_enc_ecc.key" -o "${DECRYPTED_FILE}" "${ENCRYPTED_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ECC decryption failed.")
    endif()

    message(STATUS "  -> Verifying file content...")
    execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files --ignore-eol "${TEST_INPUT_FILE}" "${DECRYPTED_FILE}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] Verification failed: Decrypted ECC file does not match original.")
    endif()
    message(STATUS "  [PASSED] Scenario: ECC Encryption/Decryption")
endfunction()


# --- Scenario Definition: PQC Signing/Verification ---
function(run_pqc_signing_scenario)
    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: PQC Signing/Verification")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/pqc_signing")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(SIGNATURE_FILE "${SCENARIO_DIR}/test_pqc.sig")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    message(STATUS "  -> Generating PQC signing keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode pqc --gen-sign-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] PQC sign key generation failed.")
    endif()

    message(STATUS "  -> Signing file...")
    execute_process(
        # 修正: 入力ファイル (${TEST_INPUT_FILE}) をコマンドの最後に移動
        COMMAND "${NK_TOOL_EXE}" --mode pqc --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${KEY_DIR}/private_sign_pqc.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] PQC signing failed.")
    endif()

    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode pqc --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${KEY_DIR}/public_sign_pqc.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] PQC signature verification failed.")
    endif()
    message(STATUS "  [PASSED] Scenario: PQC Signing/Verification")
endfunction()


# --- Scenario Definition: ECC Signing/Verification ---
function(run_ecc_signing_scenario)
    message(STATUS "\n=============================================")
    message(STATUS " E2E SCENARIO: ECC Signing/Verification")
    message(STATUS "=============================================")

    set(SCENARIO_DIR "${TEST_OUTPUT_DIR}/ecc_signing")
    set(KEY_DIR "${SCENARIO_DIR}/keys")
    set(SIGNATURE_FILE "${SCENARIO_DIR}/test_ecc.sig")
    file(REMOVE_RECURSE "${SCENARIO_DIR}")
    file(MAKE_DIRECTORY "${KEY_DIR}")

    message(STATUS "  -> Generating ECC signing keys...")
    execute_process(COMMAND "${NK_TOOL_EXE}" --mode ecc --gen-sign-key --key-dir "${KEY_DIR}" RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ECC sign key generation failed.")
    endif()

    message(STATUS "  -> Signing file...")
    execute_process(
        # 修正: 入力ファイル (${TEST_INPUT_FILE}) をコマンドの最後に移動
        COMMAND "${NK_TOOL_EXE}" --mode ecc --sign --signature "${SIGNATURE_FILE}" --signing-privkey "${KEY_DIR}/private_sign_ecc.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ECC signing failed.")
    endif()

    message(STATUS "  -> Verifying signature...")
    execute_process(
        COMMAND "${NK_TOOL_EXE}" --mode ecc --verify --signature "${SIGNATURE_FILE}" --signing-pubkey "${KEY_DIR}/public_sign_ecc.key" "${TEST_INPUT_FILE}"
        RESULT_VARIABLE res)
    if(NOT res EQUAL 0)
        message(FATAL_ERROR "  [FAILED] ECC signature verification failed.")
    endif()
    message(STATUS "  [PASSED] Scenario: ECC Signing/Verification")
endfunction()


# --- Main script execution: Call all scenarios ---
run_hybrid_encryption_scenario()
run_pqc_encryption_scenario()
run_ecc_encryption_scenario()
run_pqc_signing_scenario()
run_ecc_signing_scenario()
