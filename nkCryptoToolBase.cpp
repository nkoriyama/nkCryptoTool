// nkCryptoToolBase.cpp

#include "nkCryptoToolBase.hpp"
#include <fstream>
#include <iostream>

// Initialize non-static member variables in constructor
nkCryptoToolBase::nkCryptoToolBase() : key_base_directory("keys") { // Default directory
    // Attempt to create the directory if it doesn't exist
    try {
      if (!std::filesystem::exists(key_base_directory)) {
        std::filesystem::create_directories(key_base_directory);
      }
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Error creating directory '" << key_base_directory << "': " << e.what() << std::endl;
    }
}

nkCryptoToolBase::~nkCryptoToolBase() {
    // Destructor
}

// Non-static method
void nkCryptoToolBase::setKeyBaseDirectory(const std::filesystem::path& dir) {
    key_base_directory = dir;
    // Attempt to create the directory if it doesn't exist
    try {
      if (!std::filesystem::exists(key_base_directory)) {
        std::filesystem::create_directories(key_base_directory);
      }
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Error creating directory '" << key_base_directory << "': " << e.what() << std::endl;
    }
}

// Non-static method
std::filesystem::path nkCryptoToolBase::getKeyBaseDirectory() const {
    return key_base_directory;
}

std::vector<unsigned char> nkCryptoToolBase::readFile(const std::filesystem::path& filepath) {
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

bool nkCryptoToolBase::writeFile(const std::filesystem::path& filepath, const std::vector<unsigned char>& data) {
    std::ofstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file for writing: " << filepath << std::endl;
        // Do not throw, just return false, as some calls might expect non-throwing behavior.
        // Or, if throwing is preferred, it should be consistent. For now, matching original logic.
        return false;
    }

    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        std::cerr << "Error: Could not write file content: " << filepath << std::endl;
        return false;
    }
    return true;
}

