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

# --- NEW: LZ4のソースから静的ライブラリを作成 ---
# これにより、LZ4のビルドシステムに依存せず、我々のプロジェクト内で完結します。
add_library(lz4_lib STATIC
    "${lz4_SOURCE_DIR}/lib/lz4.c"
    "${lz4_SOURCE_DIR}/lib/lz4frame.c"
    "${lz4_SOURCE_DIR}/lib/lz4hc.c"
)
# このライブラリが自身のヘッダーを見つけられるようにインクルードパスを設定します。
target_include_directories(lz4_lib PUBLIC
    "${lz4_SOURCE_DIR}/lib"
)
# --- 依存関係の定義ここまで ---

# OpenSSLライブラリを見つけます。
find_package(OpenSSL REQUIRED)

# 実行可能ファイルの出力ディレクトリを build/bin に設定します。
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ソースファイルから実行可能ファイルを作成します。
add_executable(nkCryptoTool
    nkCryptoToolMain.cpp
    nkCryptoToolBase.cpp
    nkCryptoToolECC.cpp
    nkCryptoToolPQC.cpp
    getopt_long.c
)

# インクルードディレクトリを追加します。
# lz4のパスは、lz4_libターゲットから自動的に継承されるため不要です。
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
