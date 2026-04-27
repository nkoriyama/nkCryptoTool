/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef SECURE_MEMORY_HPP
#define SECURE_MEMORY_HPP

#include <vector>
#include <string>
#include <memory>
#include <algorithm>

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
        // メモリを安全に消去 (最適化による削除を防止)
        if (p) {
            volatile unsigned char* v_ptr = reinterpret_cast<volatile unsigned char*>(p);
            for (std::size_t i = 0; i < size; ++i) v_ptr[i] = 0;
        }
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
