#include "nkCryptoToolUtils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <format>
#include "TPMConstants.hpp"

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

    for (const auto& entry : std::filesystem::recursive_directory_iterator(input_dir)) {
        if (entry.is_regular_file()) {
            const auto& input_path = entry.path();
            auto relative_path = std::filesystem::relative(input_path, input_dir);
            auto output_path = output_dir / relative_path;

            if (!output_path.parent_path().empty() && !std::filesystem::exists(output_path.parent_path())) {
                try {
                    std::filesystem::create_directories(output_path.parent_path());
                } catch (const std::filesystem::filesystem_error& e) {
                    std::cerr << "Error creating output directory " << output_path.parent_path().string() << ": " << e.what() << std::endl;
                    continue;
                }
            }
            file_operation(input_path, output_path);
        }
    }
}

SecureString get_masked_passphrase() {
    SecureString passphrase_input;
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
        std::cout << std::endl;
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

SecureString get_and_verify_passphrase(const std::string& prompt) {
    SecureString pass1, pass2;
    do {
        std::cout << prompt;
        std::cout.flush();
        pass1 = get_masked_passphrase();
        if (pass1.empty()) return "";
        std::cout << "Verifying - Enter same passphrase again: ";
        std::cout.flush();
        pass2 = get_masked_passphrase();
        if (pass1 != pass2) std::cerr << "\nPassphrases do not match. Please try again." << std::endl;
    } while (pass1 != pass2);
    return pass1;
}

int ossl_passphrase_cb(char *pass, size_t pass_max, size_t *pass_len, const OSSL_PARAM params[], void *arg) {
    if (arg == nullptr) return 0;
    const SecureString* passphrase = static_cast<const SecureString*>(arg);
    size_t len = passphrase->length();
    if (len >= pass_max) return 0;
    std::memcpy(pass, passphrase->c_str(), len);
    pass[len] = '\0';
    if (pass_len) *pass_len = len;
    return 1;
}

int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata) {
    if (userdata == nullptr) return 0;
    const SecureString* passphrase = static_cast<const SecureString*>(userdata);
    size_t len = passphrase->length();
    if (len >= static_cast<size_t>(size)) return 0;
    std::memcpy(buf, passphrase->c_str(), len);
    buf[len] = '\0';
    return (int)len;
}

namespace nkCryptoToolUtils {

std::string wrapToPem(const std::vector<uint8_t>& der, const std::string& label) {
    std::string b64 = TPMUtils::base64_encode(der);
    std::string pem = "-----BEGIN " + label + "-----\n";
    for (size_t i = 0; i < b64.length(); i += 64) {
        pem += b64.substr(i, 64) + "\n";
    }
    pem += "-----END " + label + "-----\n";
    return pem;
}

std::expected<std::vector<uint8_t>, CryptoError> unwrapFromPem(const std::string& pem, const std::string& label) {
    std::string header = "-----BEGIN " + label + "-----";
    std::string footer = "-----END " + label + "-----";
    
    size_t start = pem.find(header);
    if (start == std::string::npos) return std::unexpected(CryptoError::FileReadError);
    start += header.length();
    
    size_t end = pem.find(footer, start);
    if (end == std::string::npos) return std::unexpected(CryptoError::FileReadError);
    
    std::string body = pem.substr(start, end - start);
    std::string filtered;
    for (char c : body) {
        if (!std::isspace(static_cast<unsigned char>(c))) filtered += c;
    }
    
    return TPMUtils::base64_decode(filtered);
}

} // namespace nkCryptoToolUtils
