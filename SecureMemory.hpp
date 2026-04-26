#ifndef SECURE_MEMORY_HPP
#define SECURE_MEMORY_HPP

#include <vector>
#include <string>
#include <memory>
#include <algorithm>
#include "backend/IBackend.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

/**
 * メモリを安全に消去し、スワップアウトを防ぐためのアロケータ
 */
template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() = default;
    template <typename U> SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        std::size_t size = n * sizeof(T);
        T* p = static_cast<T*>(::operator new(size));
        if (p) {
#ifdef _WIN32
            VirtualLock(p, size);
#else
            mlock(p, size);
#endif
        }
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept {
        std::size_t size = n * sizeof(T);
        // バックエンド経由で安全に消去
        ::get_nk_backend()->cleanse(p, size);
#ifdef _WIN32
        VirtualUnlock(p, size);
#else
        munlock(p, size);
#endif
        ::operator delete(p);
    }
};

template <typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) { return true; }

template <typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) { return false; }

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

template <typename T>
using SecureVector = std::vector<T, SecureAllocator<T>>;

#endif // SECURE_MEMORY_HPP
