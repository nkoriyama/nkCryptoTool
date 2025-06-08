# CMakeの最小バージョンを指定します。
cmake_minimum_required(VERSION 3.14)

# プロジェクト名を定義します。
project(nkCryptoTool CXX C)

# C++23標準を使用するように設定します。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CTestを有効化
enable_testing()

# --- 依存関係をFetchContentで取得 ---
include(FetchContent)

# FetchContentがタイムスタンプを扱う際のポリシーを設定 (警告の解消)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

# 1. Googletest (gtest) を取得
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# gtestはビルドが必要なため、MakeAvailableでサブディレクトリとして追加
FetchContent_MakeAvailable(googletest)

# 2. Asio を取得 (ヘッダーオンリー)
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG        asio-1-30-2
)
# asioはヘッダーオンリーなので、ソースの場所を取得するだけ
FetchContent_GetProperties(asio)
if(NOT asio_POPULATED)
  FetchContent_Populate(asio)
endif()


# --- ライブラリの検索 ---
# OpenSSLライブラリを見つけます。
find_package(OpenSSL REQUIRED)


# --- 実行可能ファイルの設定 ---
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# メインの実行可能ファイルを定義
add_executable(nkCryptoTool
    nkCryptoToolMain.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
    getopt_long.c
)

# 実行可能ファイルにライブラリをリンクします
set(LIBS OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    list(APPEND LIBS ws2_32)
endif()
target_link_libraries(nkCryptoTool PRIVATE ${LIBS})

# 必要なインクルードパスを明示的に追加
# 修正点: 正しいディレクトリ構造に合わせてパスを修正
target_include_directories(nkCryptoTool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${asio_SOURCE_DIR}/asio/include
)


# ===== ユニットテスト用の設定 =====
add_executable(runUnitTests
    tests/crypto_tool_test.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
    getopt_long.c
)

# ユニットテストに必要なライブラリをリンク
target_link_libraries(runUnitTests PRIVATE
    GTest::gtest_main
    ${LIBS}
)

# ユニットテストに必要なインクルードパスを明示的に追加
# 修正点: 正しいディレクトリ構造に合わせてパスを修正
target_include_directories(runUnitTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} # nkCryptoTool*.hpp を見つけるため
    ${asio_SOURCE_DIR}/asio/include
)

# CTestにユニットテストを登録
add_test(NAME UnitTests COMMAND $<TARGET_FILE:runUnitTests>)


# ===== E2E (End-to-End) テスト用の設定 =====
set(E2E_TEST_INPUT_FILE "${CMAKE_BINARY_DIR}/E2E_README.md")
file(WRITE ${E2E_TEST_INPUT_FILE} "This is a test file for nkCryptoTool.\nIt contains multiple lines of text to verify encryption and signing.\n1234567890\n!@#$%^&*()")

set(E2E_TEST_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/tests/E2ETests.cmake")

add_test(
    NAME EndToEndTests
    COMMAND "${CMAKE_COMMAND}"
            -D NK_TOOL_EXE=$<TARGET_FILE:nkCryptoTool>
            -D TEST_INPUT_FILE=${E2E_TEST_INPUT_FILE}
            -D TEST_OUTPUT_DIR=${CMAKE_BINARY_DIR}/E2E_Test_Output
            -P "${E2E_TEST_SCRIPT}"
)


# ===== インストール設定（オプション） =====
install(TARGETS nkCryptoTool DESTINATION bin)
