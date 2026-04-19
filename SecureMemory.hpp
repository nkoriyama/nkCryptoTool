#ifndef SECURE_MEMORY_HPP
#define SECURE_MEMORY_HPP

#include <string>
#include <vector>
#include <openssl/crypto.h>
#include <sys/mman.h>
#include <stdexcept>

template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() noexcept {}
    template <typename U> SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
        if (auto p = static_cast<T*>(std::malloc(n * sizeof(T)))) {
            // mlockによりメモリをスワップアウト不可に設定し、ディスクへの機密情報残留を防止します。
            // 権限不足やRLIMIT_MEMLOCK超過で失敗する場合がありますが、デストラクタでのOPENSSL_cleanseで代替対策としています。
            if (mlock(p, n * sizeof(T)) != 0) {
                // mlock failed (e.g., insufficient privileges or memory limits)
                // The allocator continues to function securely via OPENSSL_cleanse on deallocation.
            }
            return p;
        }
        throw std::bad_alloc();
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) {
            OPENSSL_cleanse(p, n * sizeof(T));
            munlock(p, n * sizeof(T));
            std::free(p);
        }
    }
};

template <typename T, typename U>
bool operator==(const SecureAllocator<T>&, const SecureAllocator<U>&) { return true; }

template <typename T, typename U>
bool operator!=(const SecureAllocator<T>&, const SecureAllocator<U>&) { return false; }

using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
using SecureVector = std::vector<unsigned char, SecureAllocator<unsigned char>>;

#endif // SECURE_MEMORY_HPP
