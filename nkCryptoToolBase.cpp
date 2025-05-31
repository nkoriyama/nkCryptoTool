// nkCryptoToolBase.cpp

#include "nkCryptoToolBase.hpp"
#include <fstream>
#include <iostream>

// Initialize static member variables
std::string nkCryptoToolBase::key_base_directory = "keys"; // Default directory
#if defined(_WIN32) || defined(__WIN32__) || defined(__MINGW32__)
const std::string nkCryptoToolBase::PATH_SEPARATOR = "\\";
#else
const std::string nkCryptoToolBase::PATH_SEPARATOR = "/";
#endif

nkCryptoToolBase::nkCryptoToolBase() {
    // Constructor
}

nkCryptoToolBase::~nkCryptoToolBase() {
    // Destructor
}

void nkCryptoToolBase::setKeyBaseDirectory(const std::string& dir) {
    key_base_directory = dir;
    // Attempt to create the directory if it doesn't exist
    try {
      if (!std::filesystem::exists(key_base_directory)) {
        std::filesystem::create_directories(key_base_directory);
      }
    } catch (const std::filesystem::filesystem_error& e) {
      // Handle potential errors during directory creation
      // For example, log the error, throw an exception, or exit
      // std::cerr << "Error creating directory " << key_base_directory << ": " << e.what() << std::endl;
      // Or rethrow:
      // throw;
      // For this example, we'll just acknowledge it.
      // In a real application, you'd want robust error handling.
      // For now, we'll simply print to stderr for demonstration.
      std::cerr << "Error creating directory '" << key_base_directory << "': " << e.what() << std::endl;
    }
}

std::string nkCryptoToolBase::getKeyBaseDirectory() {
    return key_base_directory;
}

std::vector<unsigned char> nkCryptoToolBase::readFile(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file for reading: " << filepath << std::endl;
        throw std::runtime_error("Could not open file for reading");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << "Error: Could not read file content: " << filepath << std::endl;
        throw std::runtime_error("Could not read file content");
    }
    return buffer;
}

bool nkCryptoToolBase::writeFile(const std::string& filepath, const std::vector<unsigned char>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file for writing: " << filepath << std::endl;
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}
