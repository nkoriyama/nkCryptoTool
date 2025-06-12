# CMakeの最小バージョンを指定します。FetchContentを安定して使用するため3.11以上を推奨します。
cmake_minimum_required(VERSION 3.11)

# プロジェクト名を定義します。C++とCの両方を扱うことを明示します。
project(nkCryptoTool CXX C)

# C++17標準を使用するように設定します。
set(CMAKE_CXX_STANDARD 17)
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

# --- 依存関係の取得: LZ4 (ソース取得のみ) ---
FetchContent_Declare(
  lz4
  GIT_REPOSITORY https://github.com/lz4/lz4.git
  GIT_TAG        v1.9.4 # 安定したバージョンタグを指定
)
# Populateを使い、ソースコードのダウンロードのみ行います。
FetchContent_Populate(lz4)

# --- LZ4のソースから静的ライブラリを作成 ---
add_library(lz4_lib STATIC
    "${lz4_SOURCE_DIR}/lib/lz4.c"
    "${lz4_SOURCE_DIR}/lib/lz4frame.c"
    "${lz4_SOURCE_DIR}/lib/lz4hc.c"
)
target_include_directories(lz4_lib PUBLIC
    "${lz4_SOURCE_DIR}/lib"
)
# --- 依存関係の定義ここまで ---

# OpenSSLライブラリを見つけます。
find_package(OpenSSL REQUIRED)

# 実行可能ファイルの出力ディレクトリを build/bin に設定します。
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ソースファイルから実行可能ファイルを作成します。
# Windows環境で不要なgetopt_long.cを削除しました。
add_executable(nkCryptoTool
    nkCryptoToolMain.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
)

# インクルードディレクトリを追加します。
target_include_directories(nkCryptoTool PRIVATE
    "${asio_SOURCE_DIR}/asio/include"
)

# 実行可能ファイルにライブラリをリンクします。
target_link_libraries(nkCryptoTool PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    lz4_lib  # 作成した静的ライブラリターゲットをリンク
)

# Windows固有のライブラリを追加でリンクします。
if(WIN32)
    target_link_libraries(nkCryptoTool PRIVATE ws2_32)
endif()

# インストールルールを設定します（オプション）。
install(TARGETS nkCryptoTool DESTINATION bin)

# ==============================================================================
# Testing Configuration (CTest)
# ==============================================================================

# CTestを有効にする
enable_testing()

# E2Eテスト用のダミー入力ファイルを作成
set(E2E_TEST_INPUT_FILE "${CMAKE_BINARY_DIR}/e2e_test_input.txt")
file(WRITE "${E2E_TEST_INPUT_FILE}" "This is the test file for the nkCryptoTool end-to-end scenarios.")

# CTestにE2Eテストスクリプトを追加
# NAME: CTestに表示されるテスト名
# COMMAND: 実行するコマンド。cmake -P でCMakeスクリプトを実行します。
# WORKING_DIRECTORY: コマンドの実行ディレクトリ。ビルドディレクトリを指定します。
add_test(
    NAME nkCryptoTool_E2E_Tests
    COMMAND "${CMAKE_COMMAND}"
        -D NK_TOOL_EXE=$<TARGET_FILE:nkCryptoTool>
        -D TEST_INPUT_FILE=${E2E_TEST_INPUT_FILE}
        -D TEST_OUTPUT_DIR=${CMAKE_BINARY_DIR}/E2ETestOutput
        -P "${CMAKE_SOURCE_DIR}/tests/E2ETests.cmake"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
)
