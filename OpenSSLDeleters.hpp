/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#ifndef OPENSSL_DELETERS_HPP
#define OPENSSL_DELETERS_HPP

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>

struct EVP_PKEY_Deleter { void operator()(EVP_PKEY *p) const { if(p) EVP_PKEY_free(p); } };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX *p) const { if(p) EVP_PKEY_CTX_free(p); } };
struct EVP_CIPHER_CTX_Deleter { void operator()(EVP_CIPHER_CTX *p) const { if(p) EVP_CIPHER_CTX_free(p); } };
struct EVP_MD_CTX_Deleter { void operator()(EVP_MD_CTX *p) const { if(p) EVP_MD_CTX_free(p); } };
struct BIO_Deleter { void operator()(BIO *b) const { if(b) BIO_free_all(b); } };
struct EVP_KDF_Deleter { void operator()(EVP_KDF *p) const { if(p) EVP_KDF_free(p); } };
struct EVP_KDF_CTX_Deleter { void operator()(EVP_KDF_CTX *p) const { if(p) EVP_KDF_CTX_free(p); } };

#endif // OPENSSL_DELETERS_HPP
