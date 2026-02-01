# CMakeの最小バージョンを指定します。FetchContentを安定して使用するため3.11以上を推奨します。
cmake_minimum_required(VERSION 3.11)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    # set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
endif()

# プロジェクト名を定義します。C++とCの両方を扱うことを明示します。
project(nkCryptoTool CXX C)

# Linux/MacでRPATHを設定し、実行ファイルが同じディレクトリにあるライブラリを見つけられるようにする
if(UNIX)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
    set(CMAKE_INSTALL_RPATH "$ORIGIN")
    # For macOS compatibility
    list(APPEND CMAKE_INSTALL_RPATH "@loader_path")
endif()

# Add io_uring support for Asio on Linux
if(UNIX AND NOT APPLE)
  add_compile_definitions(ASIO_HAS_IO_URING)
endif()

# C++23標準を使用するように設定します。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FetchContentモジュールをインクルードします。
include(FetchContent)

# --- 依存関係の取得: Asio ---
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG        asio-1-28-1 # 安定したバージョンタグを指定
)
FetchContent_MakeAvailable(asio)

# --- 依存関係の取得: cxxopts ---
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG        v3.1.1 # 安定したバージョンタグを指定
)
FetchContent_MakeAvailable(cxxopts)

# --- 依存関係の取得: Google Benchmark ---
FetchContent_Declare(
  benchmark
  GIT_REPOSITORY https://github.com/google/benchmark.git
  GIT_TAG        v1.8.4
)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "Disable building benchmark's tests" FORCE)
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "Disable -Werror for benchmark" FORCE)
FetchContent_MakeAvailable(benchmark)

# --- 依存関係の取得: Threads ---
find_package(Threads REQUIRED)

# --- 依存関係の取得: OpenSSL ---
find_package(OpenSSL REQUIRED)

# 実行可能ファイルとライブラリの出力ディレクトリを build/bin に設定します。
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# 共有ライブラリのソースファイルを定義します。
set(NKCRYPTO_SHARED_SOURCES
    PipelineManager.cpp
    CryptoProcessor.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
    nkCryptoToolUtils.cpp
)

# 共有ライブラリ nkcrypto_shared を作成します。
add_library(nkcrypto_shared SHARED ${NKCRYPTO_SHARED_SOURCES})

# FFI連携のためにPosition Independent Codeを有効化します。
set_target_properties(nkcrypto_shared PROPERTIES POSITION_INDEPENDENT_CODE ON)

# 共有ライブラリに最適化フラグを適用します。
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(nkcrypto_shared PRIVATE
        -O3                # 最大最適化
        -march=native      # CPU固有の命令セット（AES-NI、AVX2など）
        -mtune=native      # CPUアーキテクチャに最適化
        -flto              # リンク時最適化（Link Time Optimization）
        -funroll-loops     # ループ展開（AES-256-GCMに有効）
    )
    # デバッグ用にRelWithDebInfoで-gを有効にします。
    if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        target_compile_options(nkcrypto_shared PRIVATE -g)
    endif()
endif()

# 共有ライブラリに必要なインクルードディレクトリとライブラリをリンクします。
target_include_directories(nkcrypto_shared PUBLIC
  ${PROJECT_SOURCE_DIR}
  ${asio_SOURCE_DIR}/asio/include
)
target_link_libraries(nkcrypto_shared PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
if(UNIX AND NOT APPLE)
  target_link_libraries(nkcrypto_shared PUBLIC uring)
endif()

# CLI実行可能ファイルを作成します。
add_executable(nkCryptoTool nkCryptoToolMain.cpp)

# ベンチマーク実行可能ファイルを作成します。
add_executable(nkCryptoToolBenchmark nkCryptoToolBenchmark.cpp)

# CLI実行可能ファイルにライブラリをリンクします。
target_include_directories(nkCryptoTool PRIVATE ${cxxopts_SOURCE_DIR}/include)
target_link_libraries(nkCryptoTool PRIVATE
    nkcrypto_shared
    # Note: The main executable links benchmark, which is unusual. Preserving for now.
    benchmark
    benchmark_main
)
target_compile_definitions(nkCryptoTool PRIVATE BENCHMARK_STATIC_LIB)

# ベンチマーク実行可能ファイルにライブラリをリンクします。
target_link_libraries(nkCryptoToolBenchmark PRIVATE
    nkcrypto_shared
    benchmark
    benchmark_main
)
target_compile_definitions(nkCryptoToolBenchmark PRIVATE BENCHMARK_STATIC_LIB)

# Windows固有のライブラリを追加でリンクします。
if(WIN32)
    target_link_libraries(nkCryptoTool PRIVATE ws2_32)
    target_link_libraries(nkCryptoToolBenchmark PRIVATE ws2_32)
endif()

# インストールルールに共有ライブラリも追加します。
install(TARGETS nkCryptoTool nkcrypto_shared DESTINATION bin)

# ==============================================================================
# Testing Configuration (CTest)
# ==============================================================================

# CTestを有効にする
enable_testing()

# E2Eテスト用のダミー入力ファイルを作成
set(E2E_TEST_INPUT_FILE "${CMAKE_BINARY_DIR}/e2e_test_input.txt")
file(WRITE "${E2E_TEST_INPUT_FILE}" "This is the test file for the nkCryptoTool end-to-end scenarios.")

# Include the E2E test definitions
include("${CMAKE_SOURCE_DIR}/tests/E2ETests.cmake")

# --- Run Standard Encryption Scenarios ---
add_e2e_test(E2E_Hybrid_Encryption hybrid OFF OFF OFF OFF OFF)
add_e2e_test(E2E_PQC_Encryption    pqc    OFF OFF OFF OFF OFF)
add_e2e_test(E2E_ECC_Encryption    ecc    OFF OFF OFF OFF OFF)

# --- Run Parallel Encryption Scenarios ---
add_e2e_test(E2E_Hybrid_Parallel_Encryption hybrid ON  OFF OFF OFF OFF)
add_e2e_test(E2E_PQC_Parallel_Encryption    pqc    ON  OFF OFF OFF OFF)
add_e2e_test(E2E_ECC_Parallel_Encryption    ecc    ON  OFF OFF OFF OFF)

# --- Run Signing Scenarios ---
add_e2e_test(E2E_PQC_Signing pqc OFF OFF ON OFF OFF)
add_e2e_test(E2E_ECC_Signing ecc OFF OFF ON OFF OFF)

# --- Run Regenerate Public Key Tests ---
add_e2e_test(E2E_ECC_Regenerate_Pubkey ecc OFF OFF OFF ON OFF)
add_e2e_test(E2E_PQC_Regenerate_Pubkey pqc OFF OFF OFF ON OFF)

# --- Run Regenerate Signing Public Key Tests ---
add_e2e_test(E2E_ECC_Regenerate_Sign_Pubkey ecc OFF OFF OFF OFF ON)
add_e2e_test(E2E_PQC_Regenerate_Sign_Pubkey pqc OFF OFF OFF OFF ON)

# MinGW DLLのコピーとインストール設定
if(MINGW)
    # MinGWのDLLパスを環境変数から取得、なければデフォルト値を使用
    if(DEFINED ENV{MINGW_PREFIX})
        set(MINGW_DLL_DIR "$ENV{MINGW_PREFIX}/bin")
    else()
        set(MINGW_DLL_DIR "C:/msys64/mingw64/bin")
        message(WARNING "MINGW_PREFIX environment variable is not set. "
                        "Defaulting to '${MINGW_DLL_DIR}'. "
                        "Set MINGW_PREFIX to your MinGW installation path if this is incorrect.")
    endif()

    # 必要なDLLのリスト
    set(MINGW_DLLS
        libgcc_s_seh-1.dll
        libwinpthread-1.dll
        libstdc++-6.dll
        libcrypto-3-x64.dll
    )

    # DLLをビルド後にコピー
    foreach(dll ${MINGW_DLLS})
        add_custom_command(TARGET nkCryptoTool POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MINGW_DLL_DIR}/${dll}"
            "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${dll}"
        )
    endforeach()

    # DLLをインストール対象に追加
    foreach(dll ${MINGW_DLLS})
        install(FILES "${MINGW_DLL_DIR}/${dll}" DESTINATION bin)
    endforeach()
endif()

# ==============================================================================
# Packaging Configuration (CPack)
# ==============================================================================
include(InstallRequiredSystemLibraries)
set(CPACK_GENERATOR "ZIP")
set(CPACK_PACKAGE_NAME "nkCryptoTool")

# --- Gitタグからパッケージバージョンを自動設定 ---
find_package(Git QUIET)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --dirty=-dirty --always
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_VERSION_STRING
        RESULT_VARIABLE GIT_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(GIT_RESULT EQUAL 0 AND GIT_VERSION_STRING)
        # 先頭の "v" または "V" を削除
        string(REGEX REPLACE "^[vV]" "" GIT_VERSION_STRING "${GIT_VERSION_STRING}")
        # RPMなどのために、最初のハイフン(-)をドット(.)に置換 (例: 1.2.3-4 -> 1.2.3.4)
        string(REGEX REPLACE "^([0-9]+\.[0-9]+\.[0-9]+)-" "\\1." GIT_VERSION_STRING "${GIT_VERSION_STRING}")
        set(CPACK_PACKAGE_VERSION "${GIT_VERSION_STRING}")
    else()
        # Gitコマンドが失敗した場合 (Gitリポジトリでない、タグがないなど)
        set(CPACK_PACKAGE_VERSION "0.0.0-dev")
    endif()
else()
    # Gitが見つからなかった場合
    set(CPACK_PACKAGE_VERSION "0.0.0-nogit")
endif()

message(STATUS "CPACK: Package version set to: ${CPACK_PACKAGE_VERSION}")
# --- Gitバージョン設定ここまで ---

include(CPack)
