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
}

namespace {

using Bytes = std::vector<uint8_t>;
constexpr const char* ALPN_CHAT = "nkct/chat/2";
constexpr const char* HS_CTX = "nkct-handshake-iroh-v1";

[[noreturn]] void fail(const std::string& m) { std::fprintf(stderr, "[p2p] error: %s\n", m.c_str()); std::exit(1); }

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
    auto der = nkCryptoToolUtils::unwrapFromPem(content, "PRIVATE KEY"); if(!der) fail("parse "+path);
    const uint8_t* p=der->data();
    // Auto-detect the key type from the PKCS#8 AlgorithmIdentifier
    // (unencrypted only; the P2P path does not decrypt private keys).
    EVP_PKEY* k=d2i_AutoPrivateKey(nullptr,&p,(long)der->size());
    if(!k) fail("load ML-DSA priv (encrypted keys unsupported on the P2P path)");
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

} // namespace

namespace nk::p2p {

int connectChat(const std::string& ticket, const std::string& signing_priv, const std::string& signing_pub){
    char* v=nkct_p2p_version(); std::fprintf(stderr,"[p2p] %s\n", v?v:"?"); nkct_string_free(v);
    void* ep=nkct_endpoint_bind((const uint8_t*)ALPN_CHAT, strlen(ALPN_CHAT)); if(!ep) fail("bind");
    uint8_t my_id[32]; nkct_endpoint_node_id(ep,my_id);
    std::fprintf(stderr,"[p2p] connecting...\n");
    void* conn=nkct_endpoint_connect(ep,ticket.c_str(),(const uint8_t*)ALPN_CHAT,strlen(ALPN_CHAT));
    if(!conn) fail("connect (is a listener running with a reachable direct address?)");
    uint8_t srv_id[32]; nkct_conn_remote_node_id(conn,srv_id);
    void* st=nkct_conn_open_bi(conn); if(!st) fail("open_bi");

    uint8_t srv_fp[32]; bool mutual = nkct_ticket_fingerprints(ticket.c_str(),srv_fp,nullptr)==0;
    { bool z=true; for(int i=0;i<32;i++) if(srv_fp[i]){z=false;break;} if(z) mutual=false; }
    if(mutual && signing_priv.empty()) std::fprintf(stderr,"[p2p] note: ticket pins a server identity but no --signing-privkey given; verifying server only\n");

    Transcript tb; tb.raw(my_id,32); tb.raw(srv_id,32);
    Bytes ecc_spki; EVP_PKEY* ecc=p256_keygen(ecc_spki);
    Bytes kem_ek; EVP_PKEY* kem=mlkem_keygen(kem_ek);
    wvec(st,ecc_spki); wvec(st,kem_ek); tb.lp(ecc_spki); tb.lp(kem_ek);

    bool self_auth = !signing_priv.empty();
    bool expects_resp = mutual;
    Bytes my_dsa_pub; EVP_PKEY* dsa=nullptr;
    if(self_auth) dsa=mldsa_load(signing_priv,my_dsa_pub);
    uint8_t flags = (self_auth?0x01:0) | (expects_resp?0x02:0);
    swrite(st,&flags,1); tb.raw(&flags,1);
    if(self_auth){ wvec(st,my_dsa_pub); tb.lp(my_dsa_pub); }
    if(expects_resp){ swrite(st,srv_fp,32); tb.raw(srv_fp,32); }
    if(self_auth){ Bytes sig=mldsa_sign(dsa,tb.buf); wvec(st,sig); }

    Bytes s_ecc=rvec(st), kem_ct=rvec(st); Bytes s_flag=sread_exact(st,1);
    tb.lp(s_ecc); tb.lp(kem_ct); tb.raw(s_flag);
    if(expects_resp){
        if((s_flag[0]&0x01)==0) fail("server declined auth (required by ticket pin)");
        Bytes s_dsa=rvec(st); tb.lp(s_dsa); Bytes sig_r=rvec(st); Bytes s_kem=rvec(st); tb.lp(s_kem);
        Bytes fp=sha3_256(s_dsa); if(memcmp(fp.data(),srv_fp,32)!=0) fail("server fingerprint mismatch (MITM?)");
        if(!mldsa_verify(s_dsa,tb.buf,sig_r)) fail("sig_R verify failed");
        std::fprintf(stderr,"[p2p] server authenticated (ML-DSA-65).\n");
    } else if(s_flag[0]!=0) fail("server self-authed but no pin");

    Bytes ss=p256_ecdh(ecc,s_ecc); Bytes k=mlkem_decap(kem,kem_ct); ss.insert(ss.end(),k.begin(),k.end());
    Bytes salt=sha3_256(tb.buf); Bytes okm=hkdf(ss,salt,"nk-auth-v3",88);
    Bytes s2c(okm.begin(),okm.begin()+32), c2s(okm.begin()+44,okm.begin()+76);
    std::fprintf(stderr,"[p2p] connected. Ctrl-D to quit.\n");
    int rc = chat_loop(st, c2s, s2c); // client: send c2s, recv s2c
    EVP_PKEY_free(ecc); EVP_PKEY_free(kem); if(dsa) EVP_PKEY_free(dsa);
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

    // Responder transcript: #1 client id, #2 server id (same order both sides).
    Transcript tb; tb.raw(cli_id,32); tb.raw(my_id,32);
    Bytes c_ecc=rvec(st), c_kem=rvec(st); tb.lp(c_ecc); tb.lp(c_kem);
    Bytes c_flag=sread_exact(st,1); tb.raw(c_flag);
    bool cli_self_auth = c_flag[0]&0x01; bool cli_expects = c_flag[0]&0x02;
    Bytes c_dsa;
    if(cli_self_auth){ c_dsa=rvec(st); tb.lp(c_dsa); }
    if(cli_expects){
        Bytes fp7=sread_exact(st,32); tb.raw(fp7);
        // A-resp: the initiator's #7 pre-commit must name THIS responder.
        if(self_auth && memcmp(fp7.data(),sign_fp.data(),32)!=0) fail("initiator's expected-responder fingerprint (#7) does not match this identity");
    }
    if(cli_self_auth){ Bytes sig_i=rvec(st); if(!mldsa_verify(c_dsa,tb.buf,sig_i)) fail("client sig_I verify failed"); std::fprintf(stderr,"[p2p] client authenticated (ML-DSA-65).\n"); }
    else if(!allow_unauth) fail("anonymous client rejected (no --allow-unauth)");

    // Server ephemeral ECC + KEM encaps to client's ek.
    Bytes s_ecc_spki; EVP_PKEY* s_ecc=p256_keygen(s_ecc_spki);
    Bytes kem_ss, kem_ct; mlkem_encap(c_kem, kem_ss, kem_ct);
    wvec(st,s_ecc_spki); wvec(st,kem_ct);
    tb.lp(s_ecc_spki); tb.lp(kem_ct);
    uint8_t s_flag = self_auth?0x01:0x00; swrite(st,&s_flag,1); tb.raw(&s_flag,1);
    if(self_auth){
        wvec(st,my_dsa_pub); tb.lp(my_dsa_pub);
        Bytes empty_kem; // no static ML-KEM (#12 empty); ephemeral #9 gives FS
        // sig_R over full transcript #1-#12 (append #12 before signing).
        tb.lp(empty_kem);
        Bytes sig_r=mldsa_sign(dsa,tb.buf); wvec(st,sig_r); wvec(st,empty_kem);
        // NOTE ordering on the wire: #11 pub, sig_R, #12. We already wrote #11.
    }

    Bytes ss=p256_ecdh(s_ecc,c_ecc); ss.insert(ss.end(),kem_ss.begin(),kem_ss.end());
    Bytes salt=sha3_256(tb.buf); Bytes okm=hkdf(ss,salt,"nk-auth-v3",88);
    Bytes s2c(okm.begin(),okm.begin()+32), c2s(okm.begin()+44,okm.begin()+76);
    std::fprintf(stderr,"[p2p] peer connected. Ctrl-D to quit.\n");
    int rc = chat_loop(st, s2c, c2s); // server: send s2c, recv c2s
    EVP_PKEY_free(s_ecc); if(dsa) EVP_PKEY_free(dsa);
    nkct_stream_free(st); nkct_conn_free(conn); nkct_endpoint_free(ep); return rc;
}

} // namespace nk::p2p
