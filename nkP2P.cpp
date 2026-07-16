/*
 * Copyright (c) 2024-2026 Naohiro KORIYAMA <nkoriyama@gmail.com>
 *
 * This file is part of nkCryptoTool.
 */

#include "nkP2P.hpp"
#include "nkCryptoToolUtils.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

// The shell SERVER's pseudo-terminal is handled cross-platform by the Rust shim
// (portable-pty: openpty on unix, ConPTY on Windows) — no forkpty here. The
// headers below are for the interactive shell CLIENT's local terminal (raw mode
// + initial window size + stdin reads), abstracted per platform by the helpers
// in the anonymous namespace (RawGuard / term_size / stdin_read).
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <termios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#ifdef NKCT_ENABLE_KEYRING
extern "C" int nkct_kr_pairing_register(const char* db, const unsigned char* bundle, size_t bundle_len,
                                        const unsigned char* client_fp, unsigned char grants, char** out_msg);
extern "C" void nkct_kr_string_free(char*);
#endif

// --- iroh shim C ABI (built from p2p-shim/) --------------------------------
extern "C" {
char*  nkct_p2p_version(void);
void   nkct_string_free(char*);
void*  nkct_endpoint_bind(const uint8_t*, size_t);
int    nkct_endpoint_node_id(void*, uint8_t*);
char*  nkct_endpoint_direct_addrs(void*);
int    nkct_ticket_fingerprints(const char*, uint8_t*, uint8_t*);
void*  nkct_endpoint_connect(void*, const char*, const uint8_t*, size_t);
void*  nkct_endpoint_accept(void*);
int    nkct_conn_remote_node_id(void*, uint8_t*);
void*  nkct_conn_open_bi(void*);
void*  nkct_conn_accept_bi(void*);
int    nkct_stream_write(void*, const uint8_t*, size_t);
int    nkct_stream_finish(void*);
long   nkct_stream_read(void*, uint8_t*, size_t);
void   nkct_stream_free(void*);
void   nkct_conn_free(void*);
void   nkct_endpoint_free(void*);
// Cross-platform PTY (openpty on unix, ConPTY on Windows) for the shell server.
void*  nkct_pty_spawn(const char*, uint16_t, uint16_t);
long   nkct_pty_read(void*, uint8_t*, size_t);
long   nkct_pty_write(void*, const uint8_t*, size_t);
void   nkct_pty_resize(void*, uint16_t, uint16_t);
int    nkct_pty_wait(void*);
void   nkct_pty_kill(void*);
void   nkct_pty_free(void*);
}

namespace {

using Bytes = std::vector<uint8_t>;
constexpr const char* ALPN_CHAT = "nkct/chat/2";
constexpr const char* ALPN_SCP = "nkct/scp/2";
constexpr const char* ALPN_SHELL = "nkct/shell/2";
constexpr const char* ALPN_PAIRING = "nkct/pairing/1";
constexpr const char* HS_CTX = "nkct-handshake-iroh-v1";

[[noreturn]] void fail(const std::string& m) { std::fprintf(stderr, "[p2p] error: %s\n", m.c_str()); std::exit(1); }

// ---- portable local-terminal helpers (interactive shell CLIENT only) -------
// Raw mode, window size, and blocking stdin reads differ by platform; the shell
// SERVER's PTY is the shim's job, this is just the local console the user types
// at. Windows uses the Console API, unix uses termios/ioctl.
#ifdef _WIN32
struct RawGuard {
    HANDLE h = INVALID_HANDLE_VALUE; DWORD old = 0; bool active = false;
    void enter() {
        h = GetStdHandle(STD_INPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &old)) {
            SetConsoleMode(h, old & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT));
            active = true;
        }
    }
    void leave() { if (active) { SetConsoleMode(h, old); active = false; } }
};
void term_size(uint16_t& cols, uint16_t& rows) {
    CONSOLE_SCREEN_BUFFER_INFO ci{};
    HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE);
    if (o != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(o, &ci)) {
        cols = (uint16_t)(ci.srWindow.Right - ci.srWindow.Left + 1);
        rows = (uint16_t)(ci.srWindow.Bottom - ci.srWindow.Top + 1);
    }
}
long stdin_read(uint8_t* buf, size_t n) { return (long)_read(_fileno(stdin), buf, (unsigned)n); }
bool running_as_root() { return false; } // Windows: no euid (Administrator check TBD)
#else
struct RawGuard {
    termios oldt{}; bool active = false;
    void enter() {
        if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &oldt) == 0) {
            termios nt = oldt; cfmakeraw(&nt); tcsetattr(STDIN_FILENO, TCSANOW, &nt); active = true;
        }
    }
    void leave() { if (active) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); active = false; } }
};
void term_size(uint16_t& cols, uint16_t& rows) {
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col) { cols = ws.ws_col; rows = ws.ws_row; }
}
long stdin_read(uint8_t* buf, size_t n) { return (long)::read(STDIN_FILENO, buf, n); }
bool running_as_root() { return ::geteuid() == 0; }
#endif

// ---- shim stream framing ----
void swrite(void* s, const uint8_t* p, size_t n) { if (nkct_stream_write(s, p, n) != 0) fail("stream write"); }
Bytes sread_exact(void* s, size_t n) {
    Bytes out; out.reserve(n); uint8_t buf[16384];
    while (out.size() < n) {
        size_t want = std::min(sizeof(buf), n - out.size());
        long r = nkct_stream_read(s, buf, want);
        if (r < 0) fail("stream read"); if (r == 0) fail("unexpected EOF");
        out.insert(out.end(), buf, buf + r);
    }
    return out;
}
void wvec(void* s, const Bytes& v) {
    uint32_t l = (uint32_t)v.size();
    uint8_t lp[4] = {(uint8_t)l,(uint8_t)(l>>8),(uint8_t)(l>>16),(uint8_t)(l>>24)};
    swrite(s, lp, 4); if (!v.empty()) swrite(s, v.data(), v.size());
}
Bytes rvec(void* s) {
    Bytes lp = sread_exact(s, 4);
    uint32_t l = (uint32_t)lp[0]|((uint32_t)lp[1]<<8)|((uint32_t)lp[2]<<16)|((uint32_t)lp[3]<<24);
    if (l > 8192) fail("vec too large"); return sread_exact(s, l);
}

struct Transcript {
    Bytes buf;
    void raw(const uint8_t* p, size_t n) { buf.insert(buf.end(), p, p+n); }
    void raw(const Bytes& b) { buf.insert(buf.end(), b.begin(), b.end()); }
    void lp(const Bytes& b) {
        uint32_t l=(uint32_t)b.size(); uint8_t x[4]={(uint8_t)l,(uint8_t)(l>>8),(uint8_t)(l>>16),(uint8_t)(l>>24)};
        buf.insert(buf.end(),x,x+4); buf.insert(buf.end(),b.begin(),b.end());
    }
};

// ---- OpenSSL primitives (same as the C++ backend's OpenSSL path) ----
Bytes sha3_256(const Bytes& in) { Bytes o(32); unsigned n=0; if(EVP_Digest(in.data(),in.size(),o.data(),&n,EVP_sha3_256(),nullptr)!=1) fail("sha3"); return o; }
EVP_PKEY* p256_keygen(Bytes& spki){ EVP_PKEY* k=EVP_PKEY_Q_keygen(nullptr,nullptr,"EC","P-256"); if(!k) fail("p256 keygen"); uint8_t* d=nullptr; int n=i2d_PUBKEY(k,&d); if(n<=0) fail("p256 spki"); spki.assign(d,d+n); OPENSSL_free(d); return k; }
Bytes p256_ecdh(EVP_PKEY* my, const Bytes& peer_spki){ const uint8_t* p=peer_spki.data(); EVP_PKEY* pe=d2i_PUBKEY(nullptr,&p,(long)peer_spki.size()); if(!pe) fail("peer spki"); EVP_PKEY_CTX* c=EVP_PKEY_CTX_new(my,nullptr); if(!c||EVP_PKEY_derive_init(c)<=0||EVP_PKEY_derive_set_peer(c,pe)<=0) fail("ecdh init"); size_t sl=0; EVP_PKEY_derive(c,nullptr,&sl); Bytes ss(sl); if(EVP_PKEY_derive(c,ss.data(),&sl)<=0) fail("ecdh"); ss.resize(sl); EVP_PKEY_free(pe); EVP_PKEY_CTX_free(c); return ss; }
EVP_PKEY* mlkem_keygen(Bytes& ek){ EVP_PKEY* k=EVP_PKEY_Q_keygen(nullptr,nullptr,"ML-KEM-768"); if(!k) fail("mlkem keygen"); size_t l=0; if(EVP_PKEY_get_raw_public_key(k,nullptr,&l)<=0) fail("ek len"); ek.resize(l); if(EVP_PKEY_get_raw_public_key(k,ek.data(),&l)<=0) fail("ek"); ek.resize(l); return k; }
void mlkem_encap(const Bytes& ek_raw, Bytes& ss, Bytes& ct){ EVP_PKEY* pk=EVP_PKEY_new_raw_public_key_ex(nullptr,"ML-KEM-768",nullptr,ek_raw.data(),ek_raw.size()); if(!pk) fail("ek import"); EVP_PKEY_CTX* c=EVP_PKEY_CTX_new(pk,nullptr); if(!c||EVP_PKEY_encapsulate_init(c,nullptr)<=0) fail("encap init"); size_t cl=0,sl=0; EVP_PKEY_encapsulate(c,nullptr,&cl,nullptr,&sl); ct.resize(cl); ss.resize(sl); if(EVP_PKEY_encapsulate(c,ct.data(),&cl,ss.data(),&sl)<=0) fail("encap"); ct.resize(cl); ss.resize(sl); EVP_PKEY_CTX_free(c); EVP_PKEY_free(pk); }
Bytes mlkem_decap(EVP_PKEY* my, const Bytes& ct){ EVP_PKEY_CTX* c=EVP_PKEY_CTX_new(my,nullptr); if(!c||EVP_PKEY_decapsulate_init(c,nullptr)<=0) fail("decap init"); size_t sl=0; EVP_PKEY_decapsulate(c,nullptr,&sl,ct.data(),ct.size()); Bytes ss(sl); if(EVP_PKEY_decapsulate(c,ss.data(),&sl,ct.data(),ct.size())<=0) fail("decap"); ss.resize(sl); EVP_PKEY_CTX_free(c); return ss; }
Bytes hkdf(const Bytes& ikm, const Bytes& salt, const char* info, size_t n){ EVP_KDF* k=EVP_KDF_fetch(nullptr,"HKDF",nullptr); EVP_KDF_CTX* c=EVP_KDF_CTX_new(k); EVP_KDF_free(k); Bytes o(n); OSSL_PARAM p[5]; int i=0; p[i++]=OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,(char*)"SHA3-256",0); p[i++]=OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,(void*)ikm.data(),ikm.size()); p[i++]=OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,(void*)salt.data(),salt.size()); p[i++]=OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,(void*)info,strlen(info)); p[i++]=OSSL_PARAM_construct_end(); if(EVP_KDF_derive(c,o.data(),n,p)<=0) fail("hkdf"); EVP_KDF_CTX_free(c); return o; }
Bytes gcm_seal(const Bytes& key,const uint8_t* nonce,const Bytes& pt){ EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new(); EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr); EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_IVLEN,12,nullptr); EVP_EncryptInit_ex(c,nullptr,nullptr,key.data(),nonce); Bytes o(pt.size()+16); int l=0,t=0; EVP_EncryptUpdate(c,o.data(),&l,pt.data(),(int)pt.size()); t=l; EVP_EncryptFinal_ex(c,o.data()+t,&l); t+=l; uint8_t tag[16]; EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_GET_TAG,16,tag); o.resize(t); o.insert(o.end(),tag,tag+16); EVP_CIPHER_CTX_free(c); return o; }
Bytes gcm_open(const Bytes& key,const uint8_t* nonce,const Bytes& ctt){ if(ctt.size()<16) fail("short ct"); size_t cl=ctt.size()-16; EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new(); EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr); EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_IVLEN,12,nullptr); EVP_DecryptInit_ex(c,nullptr,nullptr,key.data(),nonce); Bytes o(cl); int l=0,t=0; EVP_DecryptUpdate(c,o.data(),&l,ctt.data(),(int)cl); t=l; EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_TAG,16,(void*)(ctt.data()+cl)); if(EVP_DecryptFinal_ex(c,o.data()+t,&l)<=0){EVP_CIPHER_CTX_free(c);fail("gcm auth");} t+=l; o.resize(t); EVP_CIPHER_CTX_free(c); return o; }

EVP_PKEY* mldsa_keygen(Bytes& pub){ EVP_PKEY* k=EVP_PKEY_Q_keygen(nullptr,nullptr,"ML-DSA-65"); if(!k) fail("mldsa keygen"); size_t l=0; if(EVP_PKEY_get_raw_public_key(k,nullptr,&l)<=0) fail("dsa pub len"); pub.resize(l); if(EVP_PKEY_get_raw_public_key(k,pub.data(),&l)<=0) fail("dsa pub"); pub.resize(l); return k; }
// Load an ML-DSA-65 signing key from a PKCS#8 PEM file -> (EVP_PKEY priv, raw pub).
EVP_PKEY* mldsa_load(const std::string& path, Bytes& pub){
    std::string content; { FILE* f=std::fopen(path.c_str(),"rb"); if(!f) fail("open "+path); char b[4096]; size_t n; while((n=std::fread(b,1,sizeof b,f))>0) content.append(b,n); std::fclose(f); }
    SecureString pass = nkCryptoToolUtils::getPassphraseIfNeeded(content, SecureString());
    // PEM_read_bio_PrivateKey handles both plaintext and encrypted PKCS#8:
    // when the key is encrypted (e.g. a keyring-resolved identity), `pass` is
    // used as the decryption passphrase; when it is plaintext, `pass` is
    // ignored. This lets --serve-*/--connect use a keyring "me:sign" identity
    // (stored as encrypted PKCS#8) as well as an on-disk plaintext key file.
    BIO* bio = BIO_new_mem_buf(content.data(), (int)content.size());
    if(!bio) fail("bio");
    EVP_PKEY* k = PEM_read_bio_PrivateKey(bio, nullptr, nullptr,
                                          pass.empty() ? nullptr : (void*)pass.c_str());
    BIO_free(bio);
    if(!k) fail("load ML-DSA priv (wrong passphrase, or unsupported key)");
    size_t l=0; if(EVP_PKEY_get_raw_public_key(k,nullptr,&l)<=0) fail("dsa pub len"); pub.resize(l);
    if(EVP_PKEY_get_raw_public_key(k,pub.data(),&l)<=0) fail("dsa pub"); pub.resize(l);
    (void)pass; return k;
}
Bytes mldsa_sign(EVP_PKEY* priv,const Bytes& msg){ EVP_MD_CTX* m=EVP_MD_CTX_new(); OSSL_PARAM ps[2]={OSSL_PARAM_construct_octet_string("context-string",(void*)HS_CTX,strlen(HS_CTX)),OSSL_PARAM_construct_end()}; if(EVP_DigestSignInit_ex(m,nullptr,nullptr,nullptr,nullptr,priv,ps)<=0) fail("sign init"); size_t sl=0; EVP_DigestSign(m,nullptr,&sl,msg.data(),msg.size()); Bytes s(sl); if(EVP_DigestSign(m,s.data(),&sl,msg.data(),msg.size())<=0) fail("sign"); s.resize(sl); EVP_MD_CTX_free(m); return s; }
bool mldsa_verify(const Bytes& pub,const Bytes& msg,const Bytes& sig){ EVP_PKEY* pk=EVP_PKEY_new_raw_public_key_ex(nullptr,"ML-DSA-65",nullptr,pub.data(),pub.size()); if(!pk) fail("dsa pub import"); EVP_MD_CTX* m=EVP_MD_CTX_new(); OSSL_PARAM ps[2]={OSSL_PARAM_construct_octet_string("context-string",(void*)HS_CTX,strlen(HS_CTX)),OSSL_PARAM_construct_end()}; if(EVP_DigestVerifyInit_ex(m,nullptr,nullptr,nullptr,nullptr,pk,ps)<=0) fail("verify init"); int rc=EVP_DigestVerify(m,sig.data(),sig.size(),msg.data(),msg.size()); EVP_MD_CTX_free(m); EVP_PKEY_free(pk); return rc==1; }

// Raw ML-DSA pubkey from a PEM SPKI file (for the ticket's sign fingerprint).
Bytes mldsa_pub_from_file(const std::string& path){
    std::string content; { FILE* f=std::fopen(path.c_str(),"rb"); if(!f) fail("open "+path); char b[4096]; size_t n; while((n=std::fread(b,1,sizeof b,f))>0) content.append(b,n); std::fclose(f); }
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PUBLIC KEY"); if(!der) fail("parse "+path);
    const uint8_t* p=der->data(); EVP_PKEY* k=d2i_PUBKEY(nullptr,&p,(long)der->size()); if(!k) fail("spki");
    size_t l=0; EVP_PKEY_get_raw_public_key(k,nullptr,&l); Bytes raw(l); EVP_PKEY_get_raw_public_key(k,raw.data(),&l); raw.resize(l); EVP_PKEY_free(k); return raw;
}

// Build an NKCT1 ticket (mirrors src/ticket.rs Display).
std::string build_ticket(const uint8_t node_id[32], const std::string& direct_csv, const Bytes& sign_fp, const Bytes& enc_fp){
    Bytes payload;
    payload.push_back(1); // version
    payload.insert(payload.end(), node_id, node_id+32);
    // relay url: empty
    payload.push_back(0); payload.push_back(0);
    // direct addrs
    std::vector<std::string> addrs; { size_t s=0,e; while((e=direct_csv.find(',',s))!=std::string::npos){ if(e>s) addrs.push_back(direct_csv.substr(s,e-s)); s=e+1;} if(s<direct_csv.size()) addrs.push_back(direct_csv.substr(s)); }
    uint16_t na=(uint16_t)addrs.size(); payload.push_back((uint8_t)na); payload.push_back((uint8_t)(na>>8));
    for(auto& a: addrs){ auto colon=a.rfind(':'); std::string ip=a.substr(0,colon); uint16_t port=(uint16_t)std::stoi(a.substr(colon+1)); if(ip.find(':')==std::string::npos){ payload.push_back(4); unsigned o[4]; sscanf(ip.c_str(),"%u.%u.%u.%u",&o[0],&o[1],&o[2],&o[3]); for(int i=0;i<4;i++) payload.push_back((uint8_t)o[i]); } else { payload.push_back(6); Bytes v6(16,0); /* rare on LAN test */ payload.insert(payload.end(),v6.begin(),v6.end()); } payload.push_back((uint8_t)port); payload.push_back((uint8_t)(port>>8)); }
    payload.push_back(1); // pqc_fp_algo
    Bytes sf=sign_fp; sf.resize(32,0); Bytes ef=enc_fp; ef.resize(32,0);
    payload.insert(payload.end(), sf.begin(), sf.end());
    payload.insert(payload.end(), ef.begin(), ef.end());
    // CRC-32/ISO-HDLC over payload
    uint32_t crc = 0xFFFFFFFFu;
    for(uint8_t b: payload){ crc ^= b; for(int i=0;i<8;i++){ crc = (crc>>1) ^ (0xEDB88320u & (uint32_t)(-(int)(crc & 1))); } }
    crc ^= 0xFFFFFFFFu;
    payload.push_back((uint8_t)crc); payload.push_back((uint8_t)(crc>>8)); payload.push_back((uint8_t)(crc>>16)); payload.push_back((uint8_t)(crc>>24));
    // base32 nopad (RFC4648 uppercase)
    static const char* B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out="nkct1"; int bits=0; uint32_t acc=0;
    for(uint8_t b: payload){ acc=(acc<<8)|b; bits+=8; while(bits>=5){ bits-=5; out.push_back(B32[(acc>>bits)&31]); } }
    if(bits>0){ out.push_back(B32[(acc<<(5-bits))&31]); }
    return out;
}

// After the handshake, both keys known; run an interactive chat (two threads).
int chat_loop(void* st, const Bytes& tx_key, const Bytes& rx_key){
    std::atomic<bool> done{false};
    std::thread rx([&]{
        while(!done.load()){
            uint8_t lp[4]; long got=0; { size_t need=4,have=0; while(have<need){ long r=nkct_stream_read(st,lp+have,need-have); if(r<=0){ done=true; return; } have+=r; got+=r; } }
            uint32_t plen=(uint32_t)lp[0]|((uint32_t)lp[1]<<8)|((uint32_t)lp[2]<<16)|((uint32_t)lp[3]<<24);
            if(plen==0){ done=true; return; }
            if(plen<29||plen>70000){ std::fprintf(stderr,"[p2p] bad packet size\n"); done=true; return; }
            Bytes pkt(plen); { size_t have=0; while(have<plen){ long r=nkct_stream_read(st,pkt.data()+have,plen-have); if(r<=0){ done=true; return; } have+=r; } }
            Bytes nonce(pkt.begin(),pkt.begin()+12); Bytes ctt(pkt.begin()+12,pkt.end());
            Bytes pt=gcm_open(rx_key,nonce.data(),ctt);
            std::string msg(pt.begin(),pt.end());
            std::printf("\r[peer] %s\n> ",msg.c_str()); std::fflush(stdout);
        }
    });
    std::printf("> "); std::fflush(stdout);
    std::string line;
    char buf[65536];
    while(!done.load() && std::fgets(buf,sizeof buf,stdin)){
        line=buf; while(!line.empty()&&(line.back()=='\n'||line.back()=='\r')) line.pop_back();
        if(line.empty()){ std::printf("> "); std::fflush(stdout); continue; }
        uint8_t nonce[12]; RAND_bytes(nonce,12);
        Bytes pt(line.begin(),line.end()); Bytes ct=gcm_seal(tx_key,nonce,pt);
        Bytes pkt(nonce,nonce+12); pkt.insert(pkt.end(),ct.begin(),ct.end());
        uint32_t pl=(uint32_t)pkt.size(); uint8_t lp[4]={(uint8_t)pl,(uint8_t)(pl>>8),(uint8_t)(pl>>16),(uint8_t)(pl>>24)};
        swrite(st,lp,4); swrite(st,pkt.data(),pkt.size());
        std::printf("> "); std::fflush(stdout);
    }
    done=true; nkct_stream_finish(st); rx.join(); return 0;
}

// ---- scp (nkct/scp/2) frame protocol -------------------------------------
// Packets are counter-nonce framed: u32 LE len + AES-256-GCM(pt, nonce, no AAD),
// nonce = 4 zero bytes || u64 BE counter, counter++ per packet (per direction).
constexpr uint8_t T_PUT=0x01,T_DATA=0x03,T_EOF=0x04,T_ACK=0x05,T_FAIL=0x06,T_GET=0x07,T_DONE=0x08,T_ERR=0x09;
void ctr_nonce(uint64_t c, uint8_t n[12]){ memset(n,0,12); for(int i=0;i<8;i++) n[4+i]=(uint8_t)(c>>((7-i)*8)); }
void scp_send(void* st, const Bytes& key, uint64_t& ctr, const Bytes& pt){
    uint8_t nonce[12]; ctr_nonce(ctr,nonce);
    Bytes pkt=gcm_seal(key,nonce,pt);
    uint32_t l=(uint32_t)pkt.size(); uint8_t lp[4]={(uint8_t)l,(uint8_t)(l>>8),(uint8_t)(l>>16),(uint8_t)(l>>24)};
    swrite(st,lp,4); swrite(st,pkt.data(),pkt.size()); ctr++;
}
// Returns false on clean EOF (0-length or stream end).
bool scp_recv(void* st, const Bytes& key, uint64_t& ctr, Bytes& out){
    uint8_t lp[4]; size_t have=0; while(have<4){ long r=nkct_stream_read(st,lp+have,4-have); if(r<=0) return false; have+=r; }
    uint32_t l=(uint32_t)lp[0]|((uint32_t)lp[1]<<8)|((uint32_t)lp[2]<<16)|((uint32_t)lp[3]<<24);
    if(l==0) return false;
    Bytes pkt(l); have=0; while(have<l){ long r=nkct_stream_read(st,pkt.data()+have,l-have); if(r<=0) return false; have+=r; }
    uint8_t nonce[12]; ctr_nonce(ctr,nonce); out=gcm_open(key,nonce,pkt); ctr++; return true;
}
void put_u32be(Bytes& v,uint32_t n){ v.push_back((uint8_t)(n>>24)); v.push_back((uint8_t)(n>>16)); v.push_back((uint8_t)(n>>8)); v.push_back((uint8_t)n); }
uint32_t get_u32be(const Bytes& b,size_t o){ return ((uint32_t)b[o]<<24)|((uint32_t)b[o+1]<<16)|((uint32_t)b[o+2]<<8)|b[o+3]; }

// Run the initiator (client) handshake over `st` for a given ticket; fills the
// s2c/c2s keys. Shared by chat and scp (only the ALPN and post-handshake differ).
void initiator_handshake(void* st, const uint8_t my_id[32], const uint8_t srv_id[32],
                         const std::string& ticket, const std::string& signing_priv,
                         Bytes& s2c, Bytes& c2s){
    uint8_t srv_fp[32]; bool mutual = nkct_ticket_fingerprints(ticket.c_str(),srv_fp,nullptr)==0;
    { bool z=true; for(int i=0;i<32;i++) if(srv_fp[i]){z=false;break;} if(z) mutual=false; }
    Transcript tb; tb.raw(my_id,32); tb.raw(srv_id,32);
    Bytes ecc_spki; EVP_PKEY* ecc=p256_keygen(ecc_spki);
    Bytes kem_ek; EVP_PKEY* kem=mlkem_keygen(kem_ek);
    wvec(st,ecc_spki); wvec(st,kem_ek); tb.lp(ecc_spki); tb.lp(kem_ek);
    bool self_auth=!signing_priv.empty(), expects=mutual;
    Bytes my_dsa_pub; EVP_PKEY* dsa=nullptr; if(self_auth) dsa=mldsa_load(signing_priv,my_dsa_pub);
    uint8_t flags=(self_auth?0x01:0)|(expects?0x02:0); swrite(st,&flags,1); tb.raw(&flags,1);
    if(self_auth){ wvec(st,my_dsa_pub); tb.lp(my_dsa_pub); }
    if(expects){ swrite(st,srv_fp,32); tb.raw(srv_fp,32); }
    if(self_auth){ Bytes sig=mldsa_sign(dsa,tb.buf); wvec(st,sig); }
    Bytes s_ecc=rvec(st), kem_ct=rvec(st); Bytes s_flag=sread_exact(st,1);
    tb.lp(s_ecc); tb.lp(kem_ct); tb.raw(s_flag);
    if(expects){
        if((s_flag[0]&0x01)==0) fail("server declined auth (required by ticket pin)");
        Bytes s_dsa=rvec(st); tb.lp(s_dsa); Bytes sig_r=rvec(st); Bytes s_kem=rvec(st); tb.lp(s_kem);
        Bytes fp=sha3_256(s_dsa); if(memcmp(fp.data(),srv_fp,32)!=0) fail("server fingerprint mismatch (MITM?)");
        if(!mldsa_verify(s_dsa,tb.buf,sig_r)) fail("sig_R verify failed");
        std::fprintf(stderr,"[p2p] server authenticated (ML-DSA-65).\n");
    } else if(s_flag[0]!=0) fail("server self-authed but no pin");
    Bytes ss=p256_ecdh(ecc,s_ecc); Bytes k=mlkem_decap(kem,kem_ct); ss.insert(ss.end(),k.begin(),k.end());
    Bytes salt=sha3_256(tb.buf); Bytes okm=hkdf(ss,salt,"nk-auth-v3",88);
    s2c.assign(okm.begin(),okm.begin()+32); c2s.assign(okm.begin()+44,okm.begin()+76);
    EVP_PKEY_free(ecc); EVP_PKEY_free(kem); if(dsa) EVP_PKEY_free(dsa);
}

// Run the responder (server) handshake over `st`. Fills s2c/c2s and, when the
// client self-authenticated, its fingerprint (SHA3-256(client ML-DSA pub)) into
// client_fp[32] with *client_authed=true. `signing_priv` is our own identity PEM
// (empty ⇒ anonymous server). If !allow_unauth and the client is anonymous, or
// any signature/pin check fails, this aborts. Shared by chat/shell/pairing.
void responder_handshake(void* st, const uint8_t cli_id[32], const uint8_t my_id[32],
                         const std::string& signing_priv, bool allow_unauth,
                         Bytes& s2c, Bytes& c2s, uint8_t client_fp[32], bool& client_authed){
    bool self_auth=!signing_priv.empty();
    Bytes my_dsa_pub; EVP_PKEY* dsa=nullptr; Bytes sign_fp(32,0);
    if(self_auth){ dsa=mldsa_load(signing_priv,my_dsa_pub); sign_fp=sha3_256(my_dsa_pub); }
    Transcript tb; tb.raw(cli_id,32); tb.raw(my_id,32);
    Bytes c_ecc=rvec(st), c_kem=rvec(st); tb.lp(c_ecc); tb.lp(c_kem);
    Bytes c_flag=sread_exact(st,1); tb.raw(c_flag);
    bool cli_self_auth=c_flag[0]&0x01, cli_expects=c_flag[0]&0x02;
    Bytes c_dsa;
    if(cli_self_auth){ c_dsa=rvec(st); tb.lp(c_dsa); }
    if(cli_expects){ Bytes fp7=sread_exact(st,32); tb.raw(fp7);
        if(self_auth && memcmp(fp7.data(),sign_fp.data(),32)!=0) fail("initiator's expected-responder fingerprint (#7) does not match this identity"); }
    client_authed=false; memset(client_fp,0,32);
    if(cli_self_auth){ Bytes sig_i=rvec(st); if(!mldsa_verify(c_dsa,tb.buf,sig_i)) fail("client sig_I verify failed");
        Bytes cfp=sha3_256(c_dsa); memcpy(client_fp,cfp.data(),32); client_authed=true;
        std::fprintf(stderr,"[p2p] client authenticated (ML-DSA-65).\n"); }
    else if(!allow_unauth) fail("anonymous client rejected (no --allow-unauth)");
    Bytes s_ecc_spki; EVP_PKEY* s_ecc=p256_keygen(s_ecc_spki);
    Bytes kem_ss, kem_ct; mlkem_encap(c_kem, kem_ss, kem_ct);
    wvec(st,s_ecc_spki); wvec(st,kem_ct); tb.lp(s_ecc_spki); tb.lp(kem_ct);
    uint8_t s_flag=self_auth?0x01:0x00; swrite(st,&s_flag,1); tb.raw(&s_flag,1);
    if(self_auth){ wvec(st,my_dsa_pub); tb.lp(my_dsa_pub); Bytes empty_kem; tb.lp(empty_kem);
        Bytes sig_r=mldsa_sign(dsa,tb.buf); wvec(st,sig_r); wvec(st,empty_kem); }
    Bytes ss=p256_ecdh(s_ecc,c_ecc); ss.insert(ss.end(),kem_ss.begin(),kem_ss.end());
    Bytes salt=sha3_256(tb.buf); Bytes okm=hkdf(ss,salt,"nk-auth-v3",88);
    s2c.assign(okm.begin(),okm.begin()+32); c2s.assign(okm.begin()+44,okm.begin()+76);
    EVP_PKEY_free(s_ecc); if(dsa) EVP_PKEY_free(dsa);
}

// Bind, gather direct addrs, and build+print a ticket carrying our signer
// fingerprint. Returns the endpoint and (via out params) my node id + the loaded
// signer. Shared server prologue for shell/pairing (chat inlines its own).
void* server_bind_and_ticket(const char* alpn, size_t alpn_len, const std::string& signing_priv,
                             uint8_t my_id[32], Bytes& sign_fp){
    void* ep=nkct_endpoint_bind((const uint8_t*)alpn, alpn_len); if(!ep) fail("bind");
    nkct_endpoint_node_id(ep,my_id);
    std::string direct;
    for(int i=0;i<20 && direct.empty();i++){
        char* da=nkct_endpoint_direct_addrs(ep); direct=da?da:""; nkct_string_free(da);
        if(direct.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    sign_fp.assign(32,0);
    if(!signing_priv.empty()){ Bytes pub; EVP_PKEY* d=mldsa_load(signing_priv,pub); sign_fp=sha3_256(pub); EVP_PKEY_free(d); }
    std::string ticket=build_ticket(my_id, direct, sign_fp, Bytes(32,0));
    std::printf("[p2p] ticket: %s\n", ticket.c_str()); std::fflush(stdout);
    std::fprintf(stderr,"[p2p] waiting for a peer (direct: %s)...\n", direct.c_str());
    return ep;
}

} // namespace

namespace nk::p2p {

int connectChat(const std::string& ticket, const std::string& signing_priv, const std::string& signing_pub){
    (void)signing_pub;
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    void* ep=nkct_endpoint_bind((const uint8_t*)ALPN_CHAT, strlen(ALPN_CHAT)); if(!ep) fail("bind");
    uint8_t my_id[32]; nkct_endpoint_node_id(ep,my_id);
    std::fprintf(stderr,"[p2p] connecting...\n");
    void* conn=nkct_endpoint_connect(ep,ticket.c_str(),(const uint8_t*)ALPN_CHAT,strlen(ALPN_CHAT));
    if(!conn) fail("connect (is a listener running with a reachable direct address?)");
    uint8_t srv_id[32]; nkct_conn_remote_node_id(conn,srv_id);
    void* st=nkct_conn_open_bi(conn); if(!st) fail("open_bi");
    Bytes s2c,c2s; initiator_handshake(st,my_id,srv_id,ticket,signing_priv,s2c,c2s);
    std::fprintf(stderr,"[p2p] connected. Ctrl-D to quit.\n");
    int rc = chat_loop(st, c2s, s2c); // client: send c2s, recv s2c
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return rc;
}

int serveChat(const std::string& signing_priv, const std::string& signing_pub, bool allow_unauth){
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    void* ep=nkct_endpoint_bind((const uint8_t*)ALPN_CHAT, strlen(ALPN_CHAT)); if(!ep) fail("bind");
    uint8_t my_id[32]; nkct_endpoint_node_id(ep,my_id);
    // iroh gathers local socket addresses asynchronously after bind; give it a
    // moment so the ticket carries a reachable direct address (relay disabled).
    std::string direct;
    for(int i=0;i<20 && direct.empty();i++){
        char* da=nkct_endpoint_direct_addrs(ep); direct = da?da:""; nkct_string_free(da);
        if(direct.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    bool self_auth = !signing_priv.empty();
    Bytes my_dsa_pub; EVP_PKEY* dsa=nullptr;
    Bytes sign_fp(32,0);
    if(self_auth){ dsa=mldsa_load(signing_priv,my_dsa_pub); sign_fp=sha3_256(my_dsa_pub); }
    std::string ticket=build_ticket(my_id, direct, sign_fp, Bytes(32,0));
    std::printf("[p2p] ticket: %s\n", ticket.c_str());
    std::fflush(stdout); // flush before the blocking accept (stdout may be a pipe)
    std::fprintf(stderr,"[p2p] waiting for a peer (direct: %s)...\n", direct.c_str());

    void* conn=nkct_endpoint_accept(ep); if(!conn) fail("accept");
    uint8_t cli_id[32]; nkct_conn_remote_node_id(conn,cli_id);
    void* st=nkct_conn_accept_bi(conn); if(!st) fail("accept_bi");

    Bytes s2c, c2s; uint8_t cfp[32]; bool cauth=false;
    responder_handshake(st, cli_id, my_id, signing_priv, allow_unauth, s2c, c2s, cfp, cauth);
    std::fprintf(stderr,"[p2p] peer connected. Ctrl-D to quit.\n");
    int rc = chat_loop(st, s2c, c2s); // server: send s2c, recv c2s
    if(dsa) EVP_PKEY_free(dsa);
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return rc;
}

int connectScpGet(const std::string& ticket, const std::string& remote_path, const std::string& local_path,
                  const std::string& signing_priv, const std::string& signing_pub){
    (void)signing_pub;
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    void* ep=nkct_endpoint_bind((const uint8_t*)ALPN_SCP, strlen(ALPN_SCP)); if(!ep) fail("bind");
    uint8_t my_id[32]; nkct_endpoint_node_id(ep,my_id);
    std::fprintf(stderr,"[p2p] connecting (scp get)...\n");
    void* conn=nkct_endpoint_connect(ep,ticket.c_str(),(const uint8_t*)ALPN_SCP,strlen(ALPN_SCP));
    if(!conn) fail("connect (is an scp server running?)");
    uint8_t srv_id[32]; nkct_conn_remote_node_id(conn,srv_id);
    void* st=nkct_conn_open_bi(conn); if(!st) fail("open_bi");
    Bytes s2c,c2s; initiator_handshake(st,my_id,srv_id,ticket,signing_priv,s2c,c2s);
    // client: tx = c2s, rx = s2c. Two independent counters (per direction).
    uint64_t tx=0, rx=0;

    // Send Get{path, recursive=false}.
    Bytes g; g.push_back(T_GET); g.push_back(0);
    put_u32be(g,(uint32_t)remote_path.size()); g.insert(g.end(),remote_path.begin(),remote_path.end());
    scp_send(st,c2s,tx,g);

    // Expect Put{file_id,mode,size,...} then Data* then Eof, then send Ack, expect Done.
    Bytes f; if(!scp_recv(st,s2c,rx,f)||f.empty()) fail("scp: no reply");
    if(f[0]==T_ERR){ std::string m((char*)f.data()+1,f.size()-1); fail("scp get refused: "+m); }
    if(f[0]!=T_PUT||f.size()<20) fail("scp get: expected Put header");
    uint32_t file_id=get_u32be(f,1);
    uint64_t size=0; for(int i=0;i<8;i++) size=(size<<8)|f[9+i];

    FILE* out=std::fopen(local_path.c_str(),"wb"); if(!out) fail("open "+local_path);
    uint64_t got=0;
    for(;;){
        Bytes d; if(!scp_recv(st,s2c,rx,d)||d.empty()) { std::fclose(out); fail("scp: stream closed before Eof"); }
        if(d[0]==T_EOF) break;
        if(d[0]==T_ERR){ std::fclose(out); std::string m((char*)d.data()+1,d.size()-1); fail("scp peer error: "+m); }
        if(d[0]!=T_DATA||d.size()<5){ std::fclose(out); fail("scp: unexpected frame in body"); }
        size_t n=d.size()-5; std::fwrite(d.data()+5,1,n,out); got+=n;
        if(got>size){ std::fclose(out); fail("scp: stream exceeds declared size"); }
    }
    std::fclose(out);
    if(got!=size) fail("scp: size mismatch");
    // Ack, then Done.
    Bytes ack; ack.push_back(T_ACK); put_u32be(ack,file_id); scp_send(st,c2s,tx,ack);
    Bytes done; bool more=scp_recv(st,s2c,rx,done);
    if(more && !done.empty() && done[0]==T_ERR){ std::string m((char*)done.data()+1,done.size()-1); fail("scp get failed: "+m); }
    std::fprintf(stderr,"[p2p] downloaded %s (%llu bytes) -> %s\n", remote_path.c_str(), (unsigned long long)size, local_path.c_str());
    std::printf("PASS: scp get %llu bytes\n",(unsigned long long)size);
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return 0;
}

// ---- shell (nkct/shell/2) ------------------------------------------------
// After the shared handshake, the shell session reuses the scp AEAD framing
// (u32 LE len + AES-256-GCM, nonce = 4 zero bytes || u64 BE counter, AAD empty,
// per-direction counter from 0). Inside each packet a typed Frame; multi-byte
// integers within a Frame are BIG-ENDIAN (opposite of the outer length prefix).
// Mirrors nkCryptoTool-rust src/shell.rs.
namespace shellf {
constexpr uint8_t T_OPEN=0x01, T_DATA=0x02, T_WINSZ=0x03, T_EXIT=0x04, T_ERROR=0x05;
void u16be(Bytes& v, uint16_t n){ v.push_back((uint8_t)(n>>8)); v.push_back((uint8_t)n); }
Bytes open_frame(uint16_t cols, uint16_t rows, const std::string& term, const std::string& cmd){
    Bytes f; f.push_back(T_OPEN); u16be(f,cols); u16be(f,rows);
    u16be(f,(uint16_t)term.size()); f.insert(f.end(),term.begin(),term.end());
    u16be(f,(uint16_t)cmd.size()); f.insert(f.end(),cmd.begin(),cmd.end());
    return f;
}
Bytes winsz_frame(uint16_t cols, uint16_t rows){ Bytes f; f.push_back(T_WINSZ); u16be(f,cols); u16be(f,rows); return f; }
Bytes data_frame(const uint8_t* p, size_t n){ Bytes f; f.push_back(T_DATA); f.insert(f.end(),p,p+n); return f; }
Bytes exit_frame(int code){ Bytes f; f.push_back(T_EXIT); f.push_back((uint8_t)(code>>24)); f.push_back((uint8_t)(code>>16)); f.push_back((uint8_t)(code>>8)); f.push_back((uint8_t)code); return f; }
}

int connectShell(const std::string& ticket, const std::string& signing_priv, const std::string& signing_pub,
                 const std::string& cmd){
    using namespace shellf;
    (void)signing_pub;
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    void* ep=nkct_endpoint_bind((const uint8_t*)ALPN_SHELL, strlen(ALPN_SHELL)); if(!ep) fail("bind");
    uint8_t my_id[32]; nkct_endpoint_node_id(ep,my_id);
    std::fprintf(stderr,"[p2p] connecting (shell)...\n");
    void* conn=nkct_endpoint_connect(ep,ticket.c_str(),(const uint8_t*)ALPN_SHELL,strlen(ALPN_SHELL));
    if(!conn) fail("connect (is a shell server running?)");
    uint8_t srv_id[32]; nkct_conn_remote_node_id(conn,srv_id);
    void* st=nkct_conn_open_bi(conn); if(!st) fail("open_bi");
    // The shell server mandates client self-auth: an empty signing key can never
    // pass, so fail early with a clear message instead of a handshake abort.
    if(signing_priv.empty()) fail("shell requires --signing-privkey (the server mandates mutual auth)");
    Bytes s2c,c2s; initiator_handshake(st,my_id,srv_id,ticket,signing_priv,s2c,c2s);
    uint64_t tx=0, rx=0; // client: tx=c2s, rx=s2c, independent counters

    // Window size + TERM for the OPEN frame.
    uint16_t cols=80, rows=24; term_size(cols, rows);
    const char* te=getenv("TERM"); std::string term=te?te:"xterm-256color";
    scp_send(st,c2s,tx, open_frame(cols,rows,term,cmd));

    bool interactive = cmd.empty();
    int code=0;
    if(!interactive){
        // Non-interactive (--shell-cmd): no stdin, read Data until Exit.
        for(;;){ Bytes f; if(!scp_recv(st,s2c,rx,f)||f.empty()) break;
            if(f[0]==T_DATA){ std::fwrite(f.data()+1,1,f.size()-1,stdout); std::fflush(stdout); }
            else if(f[0]==T_EXIT && f.size()>=5){ code=(int)(((uint32_t)f[1]<<24)|((uint32_t)f[2]<<16)|((uint32_t)f[3]<<8)|f[4]); break; }
            else if(f[0]==T_ERROR){ std::string m((char*)f.data()+1,f.size()-1); std::fprintf(stderr,"[p2p] shell error: %s\n",m.c_str()); code=1; break; }
        }
        nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return code&0xff;
    }

    // Interactive: raw-mode stdin pumped in this thread, server output in a
    // reader thread. Exit(code) ends the session and restores the terminal.
    std::fprintf(stderr,"[p2p] shell session — exit / Ctrl-D to quit.\n");
    RawGuard raw; raw.enter();
    std::atomic<bool> done{false}; std::atomic<int> ecode{0};
    std::thread reader([&]{
        for(;;){ Bytes f; if(!scp_recv(st,s2c,rx,f)||f.empty()){ done=true; return; }
            if(f[0]==T_DATA){ std::fwrite(f.data()+1,1,f.size()-1,stdout); std::fflush(stdout); }
            else if(f[0]==T_EXIT && f.size()>=5){ ecode=(int)(((uint32_t)f[1]<<24)|((uint32_t)f[2]<<16)|((uint32_t)f[3]<<8)|f[4]); done=true; return; }
            else if(f[0]==T_ERROR){ std::string m((char*)f.data()+1,f.size()-1); std::fprintf(stderr,"\r\n[p2p] shell error: %s\r\n",m.c_str()); ecode=1; done=true; return; }
        }
    });
    uint8_t ib[4096];
    while(!done.load()){
        long r=stdin_read(ib, sizeof ib);
        if(r>0){ scp_send(st,c2s,tx, data_frame(ib,(size_t)r)); }
        else { break; } // EOF (Ctrl-D) or error: stop sending stdin
        if(done.load()) break;
    }
    // Let the server finish; wait briefly for a trailing Exit frame.
    for(int i=0;i<50 && !done.load();i++) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    done=true; nkct_stream_finish(st); reader.join();
    raw.leave();
    code=ecode.load();
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return code&0xff;
}

// ---- pairing (nkct/pairing/1) --------------------------------------------
// ssh-copy-id equivalent: after the shared handshake (client self-auths; the
// bundle owner must be the connecting identity), ONE round trip carries the
// client's own signed KeyBundle to the server for registration. Request plaintext
// = LP(token) || LP(bundle) (LP = u32 LE); response = ok:u8 || LP(msg).
// Mirrors nkCryptoTool-rust src/pairing.rs.
int connectPairing(const std::string& ticket, const std::string& token, const Bytes& bundle,
                   const std::string& signing_priv, const std::string& signing_pub){
    (void)signing_pub;
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    if(signing_priv.empty()) fail("pairing requires --signing-privkey (the identity to register)");
    void* ep=nkct_endpoint_bind((const uint8_t*)ALPN_PAIRING, strlen(ALPN_PAIRING)); if(!ep) fail("bind");
    uint8_t my_id[32]; nkct_endpoint_node_id(ep,my_id);
    std::fprintf(stderr,"[p2p] connecting (pairing)...\n");
    void* conn=nkct_endpoint_connect(ep,ticket.c_str(),(const uint8_t*)ALPN_PAIRING,strlen(ALPN_PAIRING));
    if(!conn) fail("connect (is a pairing server running?)");
    uint8_t srv_id[32]; nkct_conn_remote_node_id(conn,srv_id);
    void* st=nkct_conn_open_bi(conn); if(!st) fail("open_bi");
    Bytes s2c,c2s; initiator_handshake(st,my_id,srv_id,ticket,signing_priv,s2c,c2s);
    uint64_t tx=0, rx=0;

    // Request: LP(token) || LP(bundle).  LP = u32 LE length prefix.
    auto put_u32le=[&](Bytes& b, uint32_t n){ b.push_back((uint8_t)n); b.push_back((uint8_t)(n>>8)); b.push_back((uint8_t)(n>>16)); b.push_back((uint8_t)(n>>24)); };
    Bytes req; put_u32le(req,(uint32_t)token.size()); req.insert(req.end(),token.begin(),token.end());
    put_u32le(req,(uint32_t)bundle.size()); req.insert(req.end(),bundle.begin(),bundle.end());
    scp_send(st,c2s,tx,req);

    // Response: ok:u8 || LP(msg). Read BEFORE closing our send side.
    Bytes resp; if(!scp_recv(st,s2c,rx,resp)||resp.empty()) fail("pairing: server closed before responding");
    bool ok = resp[0]!=0;
    std::string msg;
    if(resp.size()>=5){ uint32_t ml=(uint32_t)resp[1]|((uint32_t)resp[2]<<8)|((uint32_t)resp[3]<<16)|((uint32_t)resp[4]<<24);
        if(5+ (size_t)ml<=resp.size()) msg.assign((char*)resp.data()+5, ml); }
    nkct_stream_finish(st);
    if(ok){ std::fprintf(stderr,"[p2p] paired.\n"); std::printf("PASS: paired — %s\n", msg.c_str()); }
    else  { std::fprintf(stderr,"[p2p] pairing refused: %s\n", msg.c_str()); std::printf("FAIL: %s\n", msg.c_str()); }
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return ok?0:1;
}

// ---- shell server (nkct/shell/2) -----------------------------------------
// Mutual-auth mandatory; the allowed client is pinned by its ML-DSA pubkey
// (`allowed_client_pub`). After OPEN, allocate a PTY, spawn the login shell or
// the requested command, and bridge it to the client with the shell frames.
// Refuses to run as root (least privilege), mirroring the Rust server.
int serveShell(const std::string& signing_priv, const std::string& allowed_client_pub){
    using namespace shellf;
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    if(running_as_root()) fail("refusing to serve a shell as root");
    if(signing_priv.empty()) fail("--serve-shell requires --signing-privkey (server identity, mutual auth)");
    if(allowed_client_pub.empty()) fail("--serve-shell requires --signing-pubkey (the client to pin)");
    Bytes allow_pub=mldsa_pub_from_file(allowed_client_pub); Bytes allow_fp=sha3_256(allow_pub);

    uint8_t my_id[32]; Bytes sign_fp;
    void* ep=server_bind_and_ticket(ALPN_SHELL, strlen(ALPN_SHELL), signing_priv, my_id, sign_fp);
    void* conn=nkct_endpoint_accept(ep); if(!conn) fail("accept");
    uint8_t cli_id[32]; nkct_conn_remote_node_id(conn,cli_id);
    void* st=nkct_conn_accept_bi(conn); if(!st) fail("accept_bi");
    Bytes s2c,c2s; uint8_t cfp[32]; bool cauth=false;
    responder_handshake(st, cli_id, my_id, signing_priv, /*allow_unauth=*/false, s2c, c2s, cfp, cauth);
    if(!cauth || memcmp(cfp, allow_fp.data(), 32)!=0) fail("client not authorized (fingerprint not pinned)");
    uint64_t tx=0, rx=0; // server: tx=s2c, rx=c2s

    // First frame MUST be OPEN.
    Bytes of; if(!scp_recv(st,c2s,rx,of)||of.empty()||of[0]!=T_OPEN||of.size()<7) fail("shell: expected OPEN frame");
    size_t p=1; auto rd_u16=[&](void)->uint16_t{ uint16_t x=((uint16_t)of[p]<<8)|of[p+1]; p+=2; return x; };
    uint16_t cols=rd_u16(), rows=rd_u16(), tl=rd_u16();
    if(p+tl+2>of.size()) fail("shell: bad OPEN");
    std::string term((char*)of.data()+p, tl); p+=tl;
    uint16_t cl=((uint16_t)of[p]<<8)|of[p+1]; p+=2;
    if(p+cl>of.size()) fail("shell: bad OPEN cmd");
    std::string cmd((char*)of.data()+p, cl);
    std::fprintf(stderr,"[p2p] shell open (%ux%u, term=%s, %s)\n", cols, rows,
                 term.c_str(), cmd.empty()?"login shell":("cmd: "+cmd).c_str());

    // Spawn the shell under a cross-platform PTY via the shim (openpty on unix,
    // ConPTY on Windows). The C++ side owns only the frame bridge below.
    void* pty=nkct_pty_spawn(cmd.empty()?"":cmd.c_str(), cols, rows);
    if(!pty) fail("pty spawn");

    // PTY output -> client (Data frames), then on child EOF wait for the exit
    // code, send Exit, and close our write side. The tx counter is owned solely
    // by this thread, so it can send Exit without racing. This drives shutdown
    // for --shell-cmd (the client sends no stdin, just awaits output + Exit).
    std::atomic<int> ecode{0};
    std::thread out([&]{
        uint8_t b[16384];
        for(;;){ long n=nkct_pty_read(pty,b,sizeof b); if(n<=0) break; scp_send(st,s2c,tx, data_frame(b,(size_t)n)); }
        int code=nkct_pty_wait(pty);
        ecode=code; scp_send(st,s2c,tx, exit_frame(code)); nkct_stream_finish(st);
    });
    // client -> PTY (stdin / winsize). rx counter owned by this thread. Ends when
    // the client closes its send side (interactive Ctrl-D) or the peer goes away
    // after receiving our Exit (--shell-cmd).
    for(;;){
        Bytes f; if(!scp_recv(st,c2s,rx,f)||f.empty()) break;
        if(f[0]==T_DATA){ if(f.size()>1) nkct_pty_write(pty,f.data()+1,f.size()-1); }
        else if(f[0]==T_WINSZ && f.size()>=5){ nkct_pty_resize(pty, (uint16_t)(((uint16_t)f[1]<<8)|f[2]), (uint16_t)(((uint16_t)f[3]<<8)|f[4])); }
        else if(f[0]==T_EXIT||f[0]==T_ERROR) break;
    }
    // Client stdin closed: terminate the child if it is still running (an
    // interactive shell that never got `exit`), which EOFs the PTY and lets the
    // out thread send Exit. No-op if the child already exited (--shell-cmd).
    nkct_pty_kill(pty);
    out.join();
    nkct_pty_free(pty);
    std::fprintf(stderr,"[p2p] shell session ended (exit %d).\n", ecode.load());
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return 0;
}

// ---- pairing server (nkct/pairing/1) -------------------------------------
// ssh-copy-id server: print a one-time token + ticket + our fingerprint, accept
// one self-authenticated client, receive its signed KeyBundle, verify the token
// (constant-time + deadline), and register the bundle + grant into keyring.db
// via the shim. Refuses to run as root. Needs NKCT_ENABLE_KEYRING (redb writes).
int servePairing(const std::string& signing_priv, const std::string& keyring_db, uint8_t grants){
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    if(running_as_root()) fail("refusing to run pairing as root");
    if(signing_priv.empty()) fail("--serve-pairing requires --signing-privkey (server identity)");
    if(grants==0) fail("--serve-pairing requires --pairing-grant (no default)");
#ifndef NKCT_ENABLE_KEYRING
    fail("this build has no keyring support; rebuild with -DNKCT_ENABLE_KEYRING=ON");
    return 1;
#else
    // One-time token: 5 random bytes -> RFC4648 base32 nopad (8 upper alnum).
    uint8_t rb[5]; RAND_bytes(rb,5);
    static const char* B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string token; { int bits=0; uint32_t acc=0; for(uint8_t b: Bytes(rb,rb+5)){ acc=(acc<<8)|b; bits+=8; while(bits>=5){ bits-=5; token.push_back(B32[(acc>>bits)&31]); } } if(bits>0) token.push_back(B32[(acc<<(5-bits))&31]); }
    uint64_t deadline = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + 300;

    uint8_t my_id[32]; Bytes sign_fp;
    void* ep=server_bind_and_ticket(ALPN_PAIRING, strlen(ALPN_PAIRING), signing_priv, my_id, sign_fp);
    std::printf("[p2p] pairing token (valid 5 min): %s\n", token.c_str());
    { std::string fh; static const char* hx="0123456789abcdef"; for(uint8_t b: sign_fp){ fh.push_back(hx[b>>4]); fh.push_back(hx[b&15]); } std::printf("[p2p] this node's fingerprint: %s\n", fh.c_str()); }
    std::fflush(stdout);

    void* conn=nkct_endpoint_accept(ep); if(!conn) fail("accept");
    uint8_t cli_id[32]; nkct_conn_remote_node_id(conn,cli_id);
    void* st=nkct_conn_accept_bi(conn); if(!st) fail("accept_bi");
    Bytes s2c,c2s; uint8_t cfp[32]; bool cauth=false;
    responder_handshake(st, cli_id, my_id, signing_priv, /*allow_unauth=*/false, s2c, c2s, cfp, cauth);
    if(!cauth) fail("pairing: client must self-authenticate");
    uint64_t tx=0, rx=0;

    // Request: LP(token) LP(bundle). LP = u32 LE.
    Bytes req; if(!scp_recv(st,c2s,rx,req)||req.size()<8) fail("pairing: short request");
    auto rd_u32le=[&](size_t o)->uint32_t{ return (uint32_t)req[o]|((uint32_t)req[o+1]<<8)|((uint32_t)req[o+2]<<16)|((uint32_t)req[o+3]<<24); };
    uint32_t tlen=rd_u32le(0); if(4+ (size_t)tlen+4 > req.size()) fail("pairing: bad token field");
    std::string ctoken((char*)req.data()+4, tlen);
    uint32_t blen=rd_u32le(4+tlen); size_t boff=4+tlen+4; if(boff+ (size_t)blen != req.size()) fail("pairing: bad bundle field");
    Bytes bundle(req.begin()+boff, req.begin()+boff+blen);

    // Verify OTP (constant-time) + deadline BEFORE touching the keyring.
    std::string reason; bool ok=false;
    bool tok_ok=false; { volatile uint8_t diff = (uint8_t)(ctoken.size()^token.size());
        size_t n = std::max(ctoken.size(), token.size());
        for(size_t i=0;i<n;i++){ uint8_t a=i<ctoken.size()?(uint8_t)ctoken[i]:0, b=i<token.size()?(uint8_t)token[i]:0; diff |= (uint8_t)(a^b);} tok_ok = (diff==0); }
    uint64_t now=(uint64_t)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if(!tok_ok) reason="invalid pairing token";
    else if(now>=deadline) reason="pairing token expired";
    else {
        char* msg=nullptr;
        int rc=nkct_kr_pairing_register(keyring_db.c_str(), bundle.data(), bundle.size(), cfp, grants, &msg);
        if(rc==0){ ok=true; reason=msg?msg:"registered"; } else { reason=msg?msg:"registration failed"; }
        if(msg) nkct_kr_string_free(msg);
    }

    // Response: ok:u8 LP(msg).
    Bytes resp; resp.push_back(ok?1:0);
    uint32_t ml=(uint32_t)reason.size(); resp.push_back((uint8_t)ml); resp.push_back((uint8_t)(ml>>8)); resp.push_back((uint8_t)(ml>>16)); resp.push_back((uint8_t)(ml>>24));
    resp.insert(resp.end(), reason.begin(), reason.end());
    scp_send(st,s2c,tx,resp);
    nkct_stream_finish(st);
    if(ok){ std::fprintf(stderr,"[p2p] registered peer.\n"); std::printf("PASS: %s\n", reason.c_str()); }
    else  { std::fprintf(stderr,"[p2p] pairing rejected: %s\n", reason.c_str()); std::printf("FAIL: %s\n", reason.c_str()); }
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return ok?0:1;
#endif
}

} // namespace nk::p2p
