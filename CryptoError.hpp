// CryptoError.hpp
#ifndef CRYPTO_ERROR_HPP
#define CRYPTO_ERROR_HPP

#include <string>

enum class CryptoError {
    Success = 0,
    FileCreationError,
    FileReadError,
    FileWriteError,
    KeyGenerationInitError,
    KeyGenerationError,
    ParameterError,
    PrivateKeyWriteError,
    PublicKeyWriteError,
    PrivateKeyLoadError,
    PublicKeyLoadError,
    SignatureVerificationError,
    OpenSSLError,
};

inline std::string toString(CryptoError err) {
    switch (err) {
        case CryptoError::Success: return "Success";
        case CryptoError::FileCreationError: return "Error creating file";
        case CryptoError::FileReadError: return "Error reading file";
        case CryptoError::FileWriteError: return "Error writing to file";
        case CryptoError::KeyGenerationInitError: return "Failed to initialize key generation context";
        case CryptoError::KeyGenerationError: return "Failed to generate key pair";
        case CryptoError::ParameterError: return "Failed to set parameters";
        case CryptoError::PrivateKeyWriteError: return "Failed to write private key to file";
        case CryptoError::PublicKeyWriteError: return "Failed to write public key to file";
        case CryptoError::PrivateKeyLoadError: return "Failed to load private key";
        case CryptoError::PublicKeyLoadError: return "Failed to load public key";
        case CryptoError::SignatureVerificationError: return "Signature verification failed";
        case CryptoError::OpenSSLError: return "An OpenSSL error occurred";
        default: return "Unknown error";
    }
}

#endif // CRYPTO_ERROR_HPP
