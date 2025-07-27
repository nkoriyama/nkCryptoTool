#ifndef NKCRYPTOTOOL_UTILS_HPP
#define NKCRYPTOTOOL_UTILS_HPP

#include <string>

// パスフレーズをコンソールから安全に入力するための関数
std::string get_masked_passphrase();

// パスフレーズを2回入力させ、一致を確認する関数
std::string get_and_verify_passphrase(const std::string& prompt);

// OpenSSLが秘密鍵のパスフレーズを要求する際に呼び出すコールバック関数
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata);

#endif // NKCRYPTOTOOL_UTILS_HPP