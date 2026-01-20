#include "nkCryptoToolUtils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <format>

#if defined(_WIN32) || defined(_WIN64)
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void processDirectory(
    asio::io_context& io_context,
    const std::filesystem::path& input_dir,
    const std::filesystem::path& output_dir,
    const std::function<void(const std::filesystem::path&, const std::filesystem::path&)>& file_operation)
{
    if (!std::filesystem::exists(input_dir)) {
        std::cerr << "Error: Input directory does not exist: " << input_dir.string() << std::endl;
        return;
    }
    if (!std::filesystem::is_directory(input_dir)) {
        std::cerr << "Error: Input path is not a directory: " << input_dir.string() << std::endl;
        return;
    }

    std::cout << "Starting recursive processing of directory: " << input_dir.string() << std::endl;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(input_dir)) {
        if (entry.is_regular_file()) {
            const auto& input_path = entry.path();
            // Calculate relative path from the input directory
            auto relative_path = std::filesystem::relative(input_path, input_dir);
            // Construct the full output path
            auto output_path = output_dir / relative_path;

            // Ensure the output directory for the current file exists
            if (!output_path.parent_path().empty() && !std::filesystem::exists(output_path.parent_path())) {
                try {
                    std::filesystem::create_directories(output_path.parent_path());
                } catch (const std::filesystem::filesystem_error& e) {
                    std::cerr << "Error creating output directory " << output_path.parent_path().string() << ": " << e.what() << std::endl;
                    continue; // Skip to the next file
                }
            }

            std::cout << "  Processing: " << input_path.string() << "\n      -> to: " << output_path.string() << std::endl;
            // Execute the provided operation (encryption/decryption)
            file_operation(input_path, output_path);
        }
    }
}


// パスフレーズをコンソールから安全に入力するための関数
std::string get_masked_passphrase() {
    std::string passphrase_input;
#if defined(_WIN32) || defined(_WIN64)
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!passphrase_input.empty()) {
                passphrase_input.pop_back();
                std::cout << "\b \b";
            }
        } else {
            passphrase_input.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
#else
    if (!isatty(STDIN_FILENO)) {
        std::getline(std::cin, passphrase_input);
        return passphrase_input;
    }
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, passphrase_input);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
#endif
    return passphrase_input;
}

// パスフレーズを2回入力させ、一致を確認する関数
std::string get_and_verify_passphrase(const std::string& prompt) {
    std::string pass1, pass2;
    do {
        std::cout << prompt;
        std::cout.flush();
        pass1 = get_masked_passphrase();
        if (pass1.empty()) {
            return "";
        }
        std::cout << "Verifying - Enter same passphrase again: ";
        std::cout.flush();
        pass2 = get_masked_passphrase();
        if (pass1 != pass2) {
            std::cerr << "\nPassphrases do not match. Please try again." << std::endl;
        }
    } while (pass1 != pass2);
    return pass1;
}

// OpenSSLが秘密鍵のパスフレーズを要求する際に呼び出すコールバック関数
int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    (void)rwflag;
    const char* key_description = static_cast<const char*>(userdata);
    if (key_description && *key_description) {
        std::cout << std::format("Enter passphrase for {}: ", key_description);
    } else {
        std::cout << "Enter passphrase for private key: ";
    }
    std::cout.flush();
    std::string final_passphrase = get_masked_passphrase();
    if (std::cin.eof()) { return 0; }
    if (final_passphrase.length() >= (unsigned int)size) {
        std::cerr << "\nError: Passphrase is too long." << std::endl;
        return 0;
    }
    strncpy(buf, final_passphrase.c_str(), size);
    buf[size - 1] = '\0';
    return static_cast<int>(strlen(buf));
}