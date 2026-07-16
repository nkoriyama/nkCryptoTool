# CMake toolchain for cross-building the Windows nkCryptoTool from Linux with
# mingw-w64 (the toolchain the project originally used natively on Windows).
#
#   cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
#         -DUSE_BACKEND=OpenSSL -DNKCT_ENABLE_P2P=ON -DNKCT_ENABLE_KEYRING=ON \
#         -DOPENSSL_ROOT_DIR=/path/to/openssl-mingw
#
# Needs: gcc/g++-mingw-w64-x86-64, OpenSSL 3.x built for mingw, and the Rust
# shim cross-built for x86_64-pc-windows-gnu (CMakeLists passes --target).

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)
set(CMAKE_C_COMPILER   ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_RC_COMPILER  ${TOOLCHAIN_PREFIX}-windres)

# The Rust target the shim is cross-built to; CMakeLists uses it for the cargo
# --target and the artifact path.
set(NKCT_RUST_TARGET x86_64-pc-windows-gnu CACHE STRING "Rust cross target")

# Find libs/headers only under the mingw sysroot + any provided roots (e.g.
# OpenSSL); run host programs (cargo) from the host.
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

# Prefer OpenSSL's static archives (we built it no-shared).
set(OPENSSL_USE_STATIC_LIBS ON)

# Self-contained .exe: fold the gcc/stdc++/winpthread runtimes in so it runs
# under Wine / a bare Windows box without extra DLLs.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static -static-libgcc -static-libstdc++")
