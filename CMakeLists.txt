# CMakeの最小バージョンを指定します。
cmake_minimum_required(VERSION 3.14) # FetchContentのためバージョンを少し上げます

# プロジェクト名を定義します。
# CXX (C++) に加えて C 言語も使用することを明示的に宣言します。
project(nkCryptoTool CXX C)

# C++23標準を使用するように設定します。
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# CTestを有効化
enable_testing()

# FetchContentでgtestを取得
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# googletestをローカルで利用可能にします
FetchContent_MakeAvailable(googletest)


# OpenSSLライブラリを見つけます。
find_package(OpenSSL REQUIRED)

# 実行可能ファイルの出力ディレクトリを設定します。
# これにより、ビルド構成（Debug/Release）に関わらず、
# 実行ファイルが build/bin に直接配置されるようになります。
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# メインの実行可能ファイルを定義
add_executable(nkCryptoTool
    nkCryptoToolMain.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
    getopt_long.c
)

# asioのインクルードディレクトリを追加します。
target_include_directories(nkCryptoTool PRIVATE
    "${CMAKE_SOURCE_DIR}/../asio/asio/include")


# 実行可能ファイルにOpenSSLライブラリをリンクします。
set(LIBS OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    list(APPEND LIBS ws2_32)
endif()
target_link_libraries(nkCryptoTool PRIVATE ${LIBS})


# ===== ユニットテスト用の設定 =====

# ユニットテスト用の実行可能ファイルを追加
add_executable(runUnitTests
    tests/crypto_tool_test.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
    getopt_long.c
)

# ユニットテストに必要なインクルードパスを追加
target_include_directories(runUnitTests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} # nkCryptoTool*.hpp を見つけるため
    "${CMAKE_SOURCE_DIR}/../asio/asio/include"
)

# ユニットテストに必要なライブラリをリンク
# (GTest::gtest_main はgtestとmain関数を含むモダンなCMakeターゲット)
target_link_libraries(runUnitTests PRIVATE
    GTest::gtest_main
    ${LIBS}
)

# CTestにユニットテストを登録
add_test(NAME UnitTests COMMAND $<TARGET_FILE:runUnitTests>)


# ===== E2E (End-to-End) テスト用の設定 =====

# テスト用のダミー入力ファイルを作成
set(E2E_TEST_INPUT_FILE "${CMAKE_BINARY_DIR}/E2E_README.md")
file(WRITE ${E2E_TEST_INPUT_FILE} "This is a test file for nkCryptoTool.\nIt contains multiple lines of text to verify encryption and signing.\n1234567890\n!@#$%^&*()")

# E2Eテストスクリプトのパス
set(E2E_TEST_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/tests/E2ETests.cmake")

# CTestにE2Eテストを登録
add_test(
    NAME EndToEndTests
    COMMAND "${CMAKE_COMMAND}"
            # テストスクリプト内で使用する変数を定義して渡す
            -D NK_TOOL_EXE=$<TARGET_FILE:nkCryptoTool>
            -D TEST_INPUT_FILE=${E2E_TEST_INPUT_FILE}
            -D TEST_OUTPUT_DIR=${CMAKE_BINARY_DIR}/E2E_Test_Output
            -P "${E2E_TEST_SCRIPT}"
)


# インストールルールを設定します（オプション）。
install(TARGETS nkCryptoTool DESTINATION bin)
