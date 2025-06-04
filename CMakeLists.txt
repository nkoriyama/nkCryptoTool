
# CMakeの最小バージョンを指定します。
cmake_minimum_required(VERSION 3.10)

# プロジェクト名を定義します。
project(nkCryptoTool CXX)

# C++20標準を使用するように設定します。
# std::filesystem を使用するには C++17 が必要です。
# coroutines を使用するには C++20 が必要です。
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenSSLライブラリを見つけます。
# OPENSSL_ROOT_DIR 変数が設定されていることを確認してください。
find_package(OpenSSL REQUIRED)

# 実行可能ファイルの出力ディレクトリを build/bin に設定します。
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
# ソースファイルから実行可能ファイルを作成します。
# ご提示いただいたファイル名に合わせて修正しました。
add_executable(nkCryptoTool
    nkCryptoToolMain.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolBase.hpp # ヘッダーファイルは直接追加する必要はありませんが、CMakeが依存関係を追跡するためにリストに含める場合があります
    nkCryptoToolECC.cpp
    nkCryptoToolECC.hpp  # 同上
    nkCryptoToolPQC.cpp
    nkCryptoToolPQC.hpp  # 同上
    getopt_long.c
)

# asioのインクルードディレクトリを追加します。
# プロジェクトルートからの相対パスを指定します。
target_include_directories(nkCryptoTool PRIVATE
    "${CMAKE_SOURCE_DIR}/../asio/asio/include")

# 実行可能ファイルにOpenSSLライブラリをリンクします。
target_link_libraries(nkCryptoTool PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# インストールルールを設定します（オプション）。
install(TARGETS nkCryptoTool DESTINATION bin)
