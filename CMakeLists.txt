# CMakeの最小バージョンを指定します。FetchContentを安定して使用するため3.11以上を推奨します。
cmake_minimum_required(VERSION 3.11)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# プロジェクト名を定義します。
project(nkCryptoTool CXX C)

# バックエンド選択オプション (デフォルトは OpenSSL)
option(USE_BACKEND "Cryptographic backend to use (OpenSSL, WolfSSL, Rust)" "OpenSSL")

# Linux/MacでRPATHを設定
if(UNIX)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH "$ORIGIN")
    list(APPEND CMAKE_INSTALL_RPATH "@loader_path")
endif()

# Add io_uring support for Asio on Linux
if(UNIX AND NOT APPLE)
  add_compile_definitions(ASIO_HAS_IO_URING)
endif()

# C++23標準を使用
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FetchContent
include(FetchContent)

# --- 依存関係の取得 ---
FetchContent_Declare(asio GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git GIT_TAG asio-1-28-1)
FetchContent_MakeAvailable(asio)

FetchContent_Declare(cxxopts GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git GIT_TAG v3.1.1)
FetchContent_MakeAvailable(cxxopts)

FetchContent_Declare(googletest GIT_REPOSITORY https://github.com/google/googletest.git GIT_TAG v1.15.2)
set(gtest_disable_pthreads ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(benchmark GIT_REPOSITORY https://github.com/google/benchmark.git GIT_TAG v1.8.4)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable building benchmark's tests" FORCE)
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "Disable -Werror for benchmark" FORCE)
FetchContent_MakeAvailable(benchmark)

FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json.git GIT_TAG v3.11.3)
FetchContent_MakeAvailable(nlohmann_json)

find_package(Threads REQUIRED)

# --- バックエンド固有の設定 ---
set(BACKEND_SOURCES)
set(BACKEND_LIBS)

if(USE_BACKEND STREQUAL "OpenSSL")
    message(STATUS "Using OpenSSL backend")
    add_definitions(-DUSE_BACKEND_OPENSSL)
    set(OPENSSL_ROOT_DIR /usr)
    find_package(OpenSSL 3.0 REQUIRED)
    list(APPEND BACKEND_SOURCES backend/OpenSslBackend.cpp)
    list(APPEND BACKEND_LIBS OpenSSL::SSL OpenSSL::Crypto)
elseif(USE_BACKEND STREQUAL "WolfSSL")
    message(STATUS "Using WolfSSL backend")
    add_definitions(-DUSE_BACKEND_WOLFSSL)
    find_package(WolfSSL REQUIRED)
    message(FATAL_ERROR "WolfSSL backend implementation is not yet completed")
else()
    message(FATAL_ERROR "Unsupported backend: ${USE_BACKEND}")
endif()

# 実行可能ファイルとライブラリの出力ディレクトリ
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# 共有ライブラリのソースファイル
set(NKCRYPTO_SHARED_SOURCES
    PipelineManager.cpp
    CryptoProcessor.cpp
    nkCryptoToolBase.cpp
    ECCStrategy.cpp
    PQCStrategy.cpp
    HybridStrategy.cpp
    nkCryptoToolUtils.cpp
    nkcrypto_ffi.cpp
    ${BACKEND_SOURCES}
)

# 共有ライブラリ nkcrypto_shared を作成
add_library(nkcrypto_shared SHARED ${NKCRYPTO_SHARED_SOURCES})
set_target_properties(nkcrypto_shared PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nkcrypto_shared PRIVATE -O3 -march=native -mtune=native -flto -funroll-loops)
endif()

target_include_directories(nkcrypto_shared PUBLIC
  ${PROJECT_SOURCE_DIR}
  ${asio_SOURCE_DIR}/asio/include
)
target_link_libraries(nkcrypto_shared PUBLIC
    ${BACKEND_LIBS}
    Threads::Threads
    nlohmann_json::nlohmann_json
)
if(UNIX AND NOT APPLE)
  target_link_libraries(nkcrypto_shared PUBLIC uring)
endif()

# 実行可能ファイル
add_executable(nkCryptoTool nkCryptoToolMain.cpp)
target_include_directories(nkCryptoTool PRIVATE ${cxxopts_SOURCE_DIR}/include)
target_link_libraries(nkCryptoTool PRIVATE nkcrypto_shared benchmark benchmark_main)
target_compile_definitions(nkCryptoTool PRIVATE BENCHMARK_STATIC_LIB)

add_executable(nkCryptoToolBenchmark nkCryptoToolBenchmark.cpp)
target_link_libraries(nkCryptoToolBenchmark PRIVATE nkcrypto_shared benchmark benchmark_main)
target_compile_definitions(nkCryptoToolBenchmark PRIVATE BENCHMARK_STATIC_LIB)

if(WIN32)
    target_link_libraries(nkCryptoTool PRIVATE ws2_32)
    target_link_libraries(nkCryptoToolBenchmark PRIVATE ws2_32)
endif()

# ==============================================================================
# Testing Configuration (CTest)
# ==============================================================================

# CTestを有効にする
enable_testing()

# --- ユニットテスト ---
add_executable(unit_tests tests/unit/unit_tests.cpp)
target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(unit_tests PRIVATE nkcrypto_shared GTest::gtest_main Threads::Threads)
include(GoogleTest)
gtest_discover_tests(unit_tests)

# E2Eテスト用のダミー入力ファイルを作成
set(E2E_TEST_INPUT_FILE "${CMAKE_BINARY_DIR}/e2e_test_input.txt")
file(WRITE "${E2E_TEST_INPUT_FILE}" "This is the test file for the nkCryptoTool end-to-end scenarios.")

# E2Eテスト用のヘルパーマクロ
macro(add_e2e_test TEST_NAME MODE PARALLEL SIGNING NEGATIVE REGEN_PUB REGEN_SIGN_PUB RECURSIVE INFO TPM WRAP PASSPHRASE KEY_TYPE)
    add_test(NAME ${TEST_NAME}
        COMMAND ${CMAKE_COMMAND}
            -DNK_TOOL_EXE=$<TARGET_FILE:nkCryptoTool>
            -DTEST_INPUT_FILE=${E2E_TEST_INPUT_FILE}
            -DTEST_OUTPUT_DIR=${CMAKE_BINARY_DIR}/tests/${TEST_NAME}
            -DSCENARIO_MODE=${MODE}
            -DSCENARIO_PARALLEL=${PARALLEL}
            -DSCENARIO_SIGNING=${SIGNING}
            -DSCENARIO_NEGATIVE=${NEGATIVE}
            -DSCENARIO_REGENERATE_PUBKEY=${REGEN_PUB}
            -DSCENARIO_REGENERATE_SIGN_PUBKEY=${REGEN_SIGN_PUB}
            -DSCENARIO_RECURSIVE=${RECURSIVE}
            -DSCENARIO_INFO=${INFO}
            -DSCENARIO_TPM=${TPM}
            -DSCENARIO_WRAP=${WRAP}
            -DSCENARIO_PASSPHRASE=${PASSPHRASE}
            -DSCENARIO_KEY_TYPE=${KEY_TYPE}
            -P "${CMAKE_SOURCE_DIR}/tests/E2ETests.cmake"
    )
    set_tests_properties(${TEST_NAME} PROPERTIES SKIP_REGULAR_EXPRESSION "Skipping TPM-related test scenario")
endmacro()

# Include the E2E test definitions
include("${CMAKE_SOURCE_DIR}/tests/E2ETests.cmake")

# --- Run Standard Encryption Scenarios ---
add_e2e_test(E2E_Hybrid_Encryption hybrid OFF OFF OFF OFF OFF OFF OFF OFF OFF "" "enc")
add_e2e_test(E2E_PQC_Encryption    pqc    OFF OFF OFF OFF OFF OFF OFF OFF OFF "" "enc")
add_e2e_test(E2E_ECC_Encryption    ecc    OFF OFF OFF OFF OFF OFF OFF OFF OFF "" "enc")

add_e2e_test(E2E_Hybrid_Encryption_Pass hybrid OFF OFF OFF OFF OFF OFF OFF OFF OFF "secret123" "enc")
add_e2e_test(E2E_PQC_Encryption_Pass    pqc    OFF OFF OFF OFF OFF OFF OFF OFF OFF "secret123" "enc")
add_e2e_test(E2E_ECC_Encryption_Pass    ecc    OFF OFF OFF OFF OFF OFF OFF OFF OFF "secret123" "enc")

# --- Run Signing Scenarios ---
add_e2e_test(E2E_PQC_Signing pqc OFF ON OFF OFF OFF OFF OFF OFF OFF "" "sign")
add_e2e_test(E2E_ECC_Signing ecc OFF ON OFF OFF OFF OFF OFF OFF OFF "" "sign")

# インストール設定
install(TARGETS nkCryptoTool nkcrypto_shared DESTINATION bin)
