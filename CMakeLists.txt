# CMakeの最小バージョンを指定します。
cmake_minimum_required(VERSION 3.11)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

project(nkCryptoTool CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# バックエンド選択オプション
option(USE_BACKEND "Cryptographic backend to use (OpenSSL, WolfSSL)" "OpenSSL")

# FetchContent
include(FetchContent)

# --- WolfSSL Configuration ---
if(USE_BACKEND STREQUAL "WolfSSL")
    message(STATUS "Configuring WolfSSL")
    set(WOLFSSL_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_CRYPTONLY ON CACHE BOOL "" FORCE)
    set(WOLFSSL_TLS OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_OPENSSLEXTRA ON CACHE BOOL "" FORCE)
    set(WOLFSSL_OPENSSLALL ON CACHE BOOL "" FORCE)
    set(WOLFSSL_AESGCM ON CACHE BOOL "" FORCE)
    set(WOLFSSL_SHA3 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_ECC ON CACHE BOOL "" FORCE)
    set(WOLFSSL_KEYGEN ON CACHE BOOL "" FORCE)
    set(WOLFSSL_HKDF ON CACHE BOOL "" FORCE)
    set(WOLFSSL_PKCS8 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_ASN_TEMPLATE ON CACHE BOOL "" FORCE) # これが必要な場合がある
    set(WOLFSSL_WERROR OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(wolfssl
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG v5.7.0-stable
    )
    FetchContent_MakeAvailable(wolfssl)
endif()

# --- Other Dependencies ---
FetchContent_Declare(asio GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git GIT_TAG asio-1-28-1)
FetchContent_MakeAvailable(asio)

FetchContent_Declare(cxxopts GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git GIT_TAG v3.1.1)
FetchContent_MakeAvailable(cxxopts)

FetchContent_Declare(googletest GIT_REPOSITORY https://github.com/google/googletest.git GIT_TAG v1.15.2)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

FetchContent_Declare(benchmark GIT_REPOSITORY https://github.com/google/benchmark.git GIT_TAG v1.8.4)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
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
    find_package(OpenSSL 3.0 REQUIRED)
    list(APPEND BACKEND_SOURCES backend/OpenSslBackend.cpp)
    list(APPEND BACKEND_LIBS OpenSSL::SSL OpenSSL::Crypto)
elseif(USE_BACKEND STREQUAL "WolfSSL")
    message(STATUS "Using WolfSSL backend")
    add_definitions(-DUSE_BACKEND_WOLFSSL)
    list(APPEND BACKEND_SOURCES backend/WolfSslBackend.cpp)
    list(APPEND BACKEND_LIBS wolfssl)
endif()

# ソースファイル
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

add_library(nkcrypto_shared STATIC ${NKCRYPTO_SHARED_SOURCES})
set_target_properties(nkcrypto_shared PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(nkcrypto_shared PROPERTIES CXX_STANDARD 23)
target_compile_options(nkcrypto_shared PRIVATE -fPIC -Wno-error -Wno-stringop-overflow)
target_compile_options(nkcrypto_shared PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-fcoroutines>)

target_include_directories(nkcrypto_shared PUBLIC
  ${PROJECT_SOURCE_DIR}
  ${asio_SOURCE_DIR}/asio/include
)

if(USE_BACKEND STREQUAL "WolfSSL")
    target_include_directories(nkcrypto_shared PRIVATE ${wolfssl_SOURCE_DIR}/.. ${wolfssl_BINARY_DIR})
endif()

target_link_libraries(nkcrypto_shared PUBLIC
    ${BACKEND_LIBS}
    Threads::Threads
    nlohmann_json::nlohmann_json
)
if(UNIX AND NOT APPLE)
  target_link_libraries(nkcrypto_shared PUBLIC uring)
endif()

add_executable(nkCryptoTool nkCryptoToolMain.cpp)
set_target_properties(nkCryptoTool PROPERTIES CXX_STANDARD 23)
target_compile_options(nkCryptoTool PRIVATE -fcoroutines -Wno-error)
target_include_directories(nkCryptoTool PRIVATE ${cxxopts_SOURCE_DIR}/include)
target_link_libraries(nkCryptoTool PRIVATE nkcrypto_shared benchmark benchmark_main)

# --- ユニットテスト ---
add_executable(unit_tests tests/unit/unit_tests.cpp)
set_target_properties(unit_tests PROPERTIES CXX_STANDARD 23)
target_compile_options(unit_tests PRIVATE -fcoroutines -Wno-error)
target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(unit_tests PRIVATE nkcrypto_shared GTest::gtest_main GTest::gmock Threads::Threads)
include(GoogleTest)
gtest_discover_tests(unit_tests)

# E2Eテスト
enable_testing()
set(E2E_TEST_INPUT_FILE "${CMAKE_BINARY_DIR}/e2e_test_input.txt")
file(WRITE "${E2E_TEST_INPUT_FILE}" "This is the test file for the nkCryptoTool end-to-end scenarios.")

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
endmacro()

add_e2e_test(E2E_ECC_Encryption ecc OFF OFF OFF OFF OFF OFF OFF OFF OFF "" "enc")
add_e2e_test(E2E_ECC_Signing    ecc OFF ON  OFF OFF OFF OFF OFF OFF OFF "" "sign")
