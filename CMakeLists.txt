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
    set(WOLFSSL_AESNI ON CACHE BOOL "" FORCE)
    set(WOLFSSL_INTELASM ON CACHE BOOL "" FORCE)
    set(WOLFSSL_SHA3 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_ECC ON CACHE BOOL "" FORCE)
    set(WOLFSSL_KEYGEN ON CACHE BOOL "" FORCE)
    set(WOLFSSL_HKDF ON CACHE BOOL "" FORCE)
    set(WOLFSSL_PKCS8 ON CACHE BOOL "" FORCE)
    set(WOLFSSL_KYBER ON CACHE BOOL "" FORCE)
    set(WOLFSSL_EXPERIMENTAL ON CACHE BOOL "" FORCE)
    set(WOLFSSL_ASN_TEMPLATE ON CACHE BOOL "" FORCE)
    set(WOLFSSL_WERROR OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_DILITHIUM OFF CACHE BOOL "" FORCE)
    
    add_compile_definitions(WOLFSSL_AESGCM_STREAM)
    add_compile_definitions(HAVE_AESGCM)
    add_compile_definitions(HAVE_HKDF)
    add_compile_definitions(HAVE_ECC)
    add_compile_definitions(WOLFSSL_HAVE_KYBER)
    add_compile_definitions(WOLFSSL_WC_KYBER)
    add_compile_definitions(WOLFSSL_SHA3)
    add_compile_definitions(WOLFSSL_AESNI)
    add_compile_definitions(WOLFSSL_X86_64_BUILD)

    set(CMAKE_C_FLAGS "-fPIC -maes -mpclmul -mavx2 -Wno-error -Wno-stringop-overflow -DWOLFSSL_AESGCM_STREAM -DHAVE_AESGCM -DHAVE_HKDF -DHAVE_ECC -DWOLFSSL_HAVE_KYBER -DWOLFSSL_WC_KYBER" CACHE STRING "" FORCE)
    set(CMAKE_CXX_FLAGS "-fPIC -maes -mpclmul -mavx2 -fcoroutines -Wno-error -DWOLFSSL_AESGCM_STREAM -DHAVE_AESGCM -DHAVE_HKDF -DHAVE_ECC -DWOLFSSL_HAVE_KYBER -DWOLFSSL_WC_KYBER" CACHE STRING "" FORCE)

    FetchContent_Declare(wolfssl
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG v5.7.6-stable
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
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON CACHE BOOL "" FORCE)
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
    list(APPEND BACKEND_SOURCES 
        backend/WolfSslBackend.cpp
    )
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
target_include_directories(nkCryptoTool PRIVATE ${cxxopts_SOURCE_DIR}/include)
target_link_libraries(nkCryptoTool PRIVATE nkcrypto_shared benchmark benchmark_main)

# --- ユニットテスト ---
add_executable(unit_tests tests/unit/unit_tests.cpp)
target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(unit_tests PRIVATE nkcrypto_shared GTest::gtest_main GTest::gmock Threads::Threads)
include(GoogleTest)
gtest_discover_tests(unit_tests)

enable_testing()
