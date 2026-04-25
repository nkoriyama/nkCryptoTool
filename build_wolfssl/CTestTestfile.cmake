# CMake generated Testfile for 
# Source directory: /var/home/bazzite/ドキュメント/src/nkCryptoTool
# Build directory: /var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
include("/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/unit_tests[1]_include.cmake")
add_test(E2E_ECC_Encryption "/home/linuxbrew/.linuxbrew/bin/cmake" "-DNK_TOOL_EXE=/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/nkCryptoTool" "-DTEST_INPUT_FILE=/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/e2e_test_input.txt" "-DTEST_OUTPUT_DIR=/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/tests/E2E_ECC_Encryption" "-DSCENARIO_MODE=ecc" "-DSCENARIO_PARALLEL=OFF" "-DSCENARIO_SIGNING=OFF" "-DSCENARIO_NEGATIVE=OFF" "-DSCENARIO_REGENERATE_PUBKEY=OFF" "-DSCENARIO_REGENERATE_SIGN_PUBKEY=OFF" "-DSCENARIO_RECURSIVE=OFF" "-DSCENARIO_INFO=OFF" "-DSCENARIO_TPM=OFF" "-DSCENARIO_WRAP=OFF" "-DSCENARIO_PASSPHRASE=" "-DSCENARIO_KEY_TYPE=enc" "-P" "/var/home/bazzite/ドキュメント/src/nkCryptoTool/tests/E2ETests.cmake")
set_tests_properties(E2E_ECC_Encryption PROPERTIES  _BACKTRACE_TRIPLES "/var/home/bazzite/ドキュメント/src/nkCryptoTool/CMakeLists.txt;139;add_test;/var/home/bazzite/ドキュメント/src/nkCryptoTool/CMakeLists.txt;160;add_e2e_test;/var/home/bazzite/ドキュメント/src/nkCryptoTool/CMakeLists.txt;0;")
add_test(E2E_ECC_Signing "/home/linuxbrew/.linuxbrew/bin/cmake" "-DNK_TOOL_EXE=/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/nkCryptoTool" "-DTEST_INPUT_FILE=/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/e2e_test_input.txt" "-DTEST_OUTPUT_DIR=/var/home/bazzite/ドキュメント/src/nkCryptoTool/build_wolfssl/tests/E2E_ECC_Signing" "-DSCENARIO_MODE=ecc" "-DSCENARIO_PARALLEL=OFF" "-DSCENARIO_SIGNING=ON" "-DSCENARIO_NEGATIVE=OFF" "-DSCENARIO_REGENERATE_PUBKEY=OFF" "-DSCENARIO_REGENERATE_SIGN_PUBKEY=OFF" "-DSCENARIO_RECURSIVE=OFF" "-DSCENARIO_INFO=OFF" "-DSCENARIO_TPM=OFF" "-DSCENARIO_WRAP=OFF" "-DSCENARIO_PASSPHRASE=" "-DSCENARIO_KEY_TYPE=sign" "-P" "/var/home/bazzite/ドキュメント/src/nkCryptoTool/tests/E2ETests.cmake")
set_tests_properties(E2E_ECC_Signing PROPERTIES  _BACKTRACE_TRIPLES "/var/home/bazzite/ドキュメント/src/nkCryptoTool/CMakeLists.txt;139;add_test;/var/home/bazzite/ドキュメント/src/nkCryptoTool/CMakeLists.txt;161;add_e2e_test;/var/home/bazzite/ドキュメント/src/nkCryptoTool/CMakeLists.txt;0;")
subdirs("_deps/wolfssl-build")
subdirs("_deps/cxxopts-build")
subdirs("_deps/googletest-build")
subdirs("_deps/benchmark-build")
subdirs("_deps/nlohmann_json-build")
