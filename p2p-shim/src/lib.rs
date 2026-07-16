// nkct-p2p-shim — a thin C-ABI wrapper over iroh 1.0's low-level transport.
//
// Step ① of the "P2P in C++" plan: expose exactly the operations the C++
// nkCryptoTool needs (endpoint bind with a custom ALPN, connect / accept,
// open / accept a bidirectional stream, read / write raw bytes, close) as
// `extern "C"` functions, so C++ can drive iroh — the SAME transport the Rust
// implementation uses — and later interoperate over it.
//
// The heavy lifting (NAT hole-punching, relay fallback, QUIC, NodeId) stays
// inside iroh; this file is only a marshalling layer. All handles are opaque
// pointers owned by the caller and freed via the matching `*_free` fn. A single
// shared multi-thread tokio runtime drives every async iroh call; the C-ABI
// functions are synchronous (block_on) so C++ sees a plain blocking API.

use once_cell::sync::Lazy;
use std::ffi::{c_char, c_int, CStr, CString};
use std::str::FromStr;
use tokio::runtime::Runtime;

use iroh::endpoint::{Connection, Endpoint, RecvStream, SendStream};

static RT: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
});

// Opaque handles handed to C++ as raw pointers.
pub struct EndpointHandle(Endpoint);
pub struct ConnectionHandle(Connection);
pub struct BiStreamHandle {
    send: SendStream,
    recv: RecvStream,
}

/// Result codes shared with C++.
pub const NKCT_OK: c_int = 0;
pub const NKCT_ERR: c_int = -1;

/// Library + iroh version string, for the C++ side to log. Caller must free
/// with `nkct_string_free`.
#[no_mangle]
pub extern "C" fn nkct_p2p_version() -> *mut c_char {
    let v = format!("nkct-p2p-shim 0.1.0 (iroh {})", iroh_version());
    CString::new(v).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn iroh_version() -> &'static str {
    // iroh doesn't export a runtime version const; report the compiled crate ver.
    option_env!("DEP_IROH_VERSION").unwrap_or("1.0")
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must be a pointer previously returned by a `nkct_*` function, or null.
#[no_mangle]
pub unsafe extern "C" fn nkct_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Bind an endpoint with a single custom ALPN, relay disabled (direct/LAN),
/// ephemeral node key. Enough to prove the transport comes up from C++.
/// Returns an EndpointHandle* or null on error.
///
/// # Safety
/// `alpn` must point to `alpn_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_bind(
    alpn: *const u8,
    alpn_len: usize,
) -> *mut EndpointHandle {
    if alpn.is_null() {
        return std::ptr::null_mut();
    }
    let alpn = std::slice::from_raw_parts(alpn, alpn_len).to_vec();
    let res = RT.block_on(async move {
        Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![alpn])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
    });
    match res {
        Ok(ep) => Box::into_raw(Box::new(EndpointHandle(ep))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// The endpoint's ticket string (node id + direct addresses), for out-of-band
/// sharing so a peer can connect. Caller frees with `nkct_string_free`.
///
/// # Safety
/// `ep` must be a live EndpointHandle from `nkct_endpoint_bind`.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_addr(ep: *mut EndpointHandle) -> *mut c_char {
    if ep.is_null() {
        return std::ptr::null_mut();
    }
    let ep = &(*ep).0;
    let addr = RT.block_on(async { ep.addr() });
    // Render EndpointAddr as a debug string; the real build will use the
    // project's NKCT1 ticket. For the link PoC this only needs to be non-empty.
    let s = format!("{:?}", addr);
    CString::new(s).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// The endpoint's direct socket addresses as a comma-separated `ip:port` string
/// (for building an NKCT1 ticket). Empty if none yet. Caller frees with
/// `nkct_string_free`. Bound with relay disabled, so these are the only way in.
///
/// # Safety
/// `ep` must be a live EndpointHandle.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_direct_addrs(ep: *mut EndpointHandle) -> *mut c_char {
    if ep.is_null() {
        return std::ptr::null_mut();
    }
    let ep = &(*ep).0;
    let addr = RT.block_on(async { ep.addr() });
    let mut parts: Vec<String> = Vec::new();
    for t in &addr.addrs {
        if let iroh::TransportAddr::Ip(sa) = t {
            parts.push(sa.to_string());
        }
    }
    CString::new(parts.join(","))
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Accept one inbound connection on the bound ALPN (blocks). Returns a
/// ConnectionHandle* or null.
///
/// # Safety
/// `ep` must be a live EndpointHandle.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_accept(ep: *mut EndpointHandle) -> *mut ConnectionHandle {
    if ep.is_null() {
        return std::ptr::null_mut();
    }
    let ep = (*ep).0.clone();
    let res = RT.block_on(async move {
        let incoming = ep.accept().await.ok_or("no incoming")?;
        let conn = incoming.await.map_err(|e| e.to_string())?;
        Ok::<Connection, String>(conn)
    });
    match res {
        Ok(c) => Box::into_raw(Box::new(ConnectionHandle(c))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Open a bidirectional stream on a connection (client side opens, then must
/// write first for the server to see `accept_bi`).
///
/// # Safety
/// `conn` must be a live ConnectionHandle.
#[no_mangle]
pub unsafe extern "C" fn nkct_conn_open_bi(conn: *mut ConnectionHandle) -> *mut BiStreamHandle {
    if conn.is_null() {
        return std::ptr::null_mut();
    }
    let conn = &(*conn).0;
    match RT.block_on(async { conn.open_bi().await }) {
        Ok((send, recv)) => Box::into_raw(Box::new(BiStreamHandle { send, recv })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Accept a bidirectional stream on a connection (server side).
///
/// # Safety
/// `conn` must be a live ConnectionHandle.
#[no_mangle]
pub unsafe extern "C" fn nkct_conn_accept_bi(conn: *mut ConnectionHandle) -> *mut BiStreamHandle {
    if conn.is_null() {
        return std::ptr::null_mut();
    }
    let conn = &(*conn).0;
    match RT.block_on(async { conn.accept_bi().await }) {
        Ok((send, recv)) => Box::into_raw(Box::new(BiStreamHandle { send, recv })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Write all bytes to the stream's send half.
///
/// # Safety
/// `s` live BiStreamHandle; `buf` points to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_stream_write(
    s: *mut BiStreamHandle,
    buf: *const u8,
    len: usize,
) -> c_int {
    if s.is_null() || buf.is_null() {
        return NKCT_ERR;
    }
    let data = std::slice::from_raw_parts(buf, len);
    let send = &mut (*s).send;
    match RT.block_on(async { send.write_all(data).await }) {
        Ok(()) => NKCT_OK,
        Err(_) => NKCT_ERR,
    }
}

/// Signal end of the send half (QUIC FIN) so the peer's read returns EOF.
///
/// # Safety
/// `s` must be a live BiStreamHandle.
#[no_mangle]
pub unsafe extern "C" fn nkct_stream_finish(s: *mut BiStreamHandle) -> c_int {
    if s.is_null() {
        return NKCT_ERR;
    }
    let send = &mut (*s).send;
    match RT.block_on(async { send.finish() }) {
        Ok(()) => NKCT_OK,
        Err(_) => NKCT_ERR,
    }
}

/// Read up to `cap` bytes from the stream's recv half into `out`. Returns the
/// number of bytes read (>= 0), 0 on clean EOF, or NKCT_ERR (< 0) on error.
///
/// # Safety
/// `s` live; `out` points to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_stream_read(
    s: *mut BiStreamHandle,
    out: *mut u8,
    cap: usize,
) -> isize {
    if s.is_null() || out.is_null() {
        return NKCT_ERR as isize;
    }
    // iroh's native RecvStream::read is quinn-style: it fills a caller buffer
    // and returns Ok(Some(n)) / Ok(None) at EOF.
    let dst = std::slice::from_raw_parts_mut(out, cap);
    let recv = &mut (*s).recv;
    let res = RT.block_on(async { recv.read(dst).await });
    match res {
        Ok(Some(n)) => n as isize,
        Ok(None) => 0, // clean EOF
        Err(_) => NKCT_ERR as isize,
    }
}

/// # Safety: pointer must come from the matching constructor (or be null).
#[no_mangle]
pub unsafe extern "C" fn nkct_stream_free(s: *mut BiStreamHandle) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}
/// # Safety: see `nkct_stream_free`.
#[no_mangle]
pub unsafe extern "C" fn nkct_conn_free(c: *mut ConnectionHandle) {
    if !c.is_null() {
        drop(Box::from_raw(c));
    }
}
/// # Safety: see `nkct_stream_free`.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_free(e: *mut EndpointHandle) {
    if !e.is_null() {
        drop(Box::from_raw(e));
    }
}

/// Self-contained link + transport smoke test, callable from C++ with no
/// arguments: bind two endpoints on the same ALPN, connect one to the other
/// over a direct (relay-disabled) path, round-trip a byte string on a
/// bidirectional stream, and assert it matches. Returns NKCT_OK on success.
/// This proves from C++ that the shim links and iroh actually moves bytes.
#[no_mangle]
pub extern "C" fn nkct_p2p_selftest() -> c_int {
    let alpn = b"nkct/selftest/1".to_vec();
    let res: Result<bool, String> = RT.block_on(async move {
        let server = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![alpn.clone()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .map_err(|e| e.to_string())?;
        let client = Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![alpn.clone()])
            .relay_mode(iroh::RelayMode::Disabled)
            .bind()
            .await
            .map_err(|e| e.to_string())?;

        let server_addr = server.addr();
        let alpn_srv = alpn.clone();

        // Server task: accept, accept_bi, echo one message back.
        let srv = tokio::spawn(async move {
            let incoming = server.accept().await.ok_or("no incoming")?;
            let conn = incoming.await.map_err(|e| e.to_string())?;
            let (mut send, mut recv) = conn.accept_bi().await.map_err(|e| e.to_string())?;
            let msg = recv.read_to_end(1024).await.map_err(|e| e.to_string())?;
            send.write_all(&msg).await.map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            // keep conn alive until the client has read the echo
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            Ok::<(), String>(())
        });

        let conn = client
            .connect(server_addr, &alpn_srv)
            .await
            .map_err(|e| e.to_string())?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
        let payload = b"nkct-p2p-roundtrip";
        send.write_all(payload).await.map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        let echoed = recv.read_to_end(1024).await.map_err(|e| e.to_string())?;

        let _ = srv.await;
        Ok(echoed == payload)
    });
    match res {
        Ok(true) => NKCT_OK,
        _ => NKCT_ERR,
    }
}

/// Parse an NKCT1 ticket into (node_id, relay_url, direct_addrs). Mirrors
/// `src/ticket.rs::from_str` in the Rust project byte-for-byte (base32-nopad,
/// CRC-ISO/HDLC over the body, little-endian fields). We only need the transport
/// fields here (node id + addrs + relay); the pinned fingerprints are consumed
/// by the app-layer handshake, not the transport.
fn parse_ticket(s: &str) -> Result<(iroh::EndpointId, Option<String>, Vec<std::net::SocketAddr>), String> {
    use data_encoding::BASE32_NOPAD;
    if !s.starts_with("nkct1") {
        return Err("bad ticket prefix".into());
    }
    let data = BASE32_NOPAD
        .decode(s.as_bytes()[5..].as_ref())
        .map_err(|e| format!("base32: {e}"))?;
    if data.len() < 1 + 32 + 2 + 2 + 1 + 32 + 32 + 4 {
        return Err("ticket too short".into());
    }
    let (body, checksum) = data.split_at(data.len() - 4);
    let crc = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    let expected = u32::from_le_bytes(checksum.try_into().unwrap());
    if crc.checksum(body) != expected {
        return Err("ticket checksum mismatch".into());
    }
    let mut off = 0usize;
    let take = |off: &mut usize, n: usize| -> Result<&[u8], String> {
        let end = off.checked_add(n).ok_or("overflow")?;
        if end > body.len() {
            return Err("truncated".into());
        }
        let r = &body[*off..end];
        *off = end;
        Ok(r)
    };
    let version = take(&mut off, 1)?[0];
    if version != 1 {
        return Err("unsupported ticket version".into());
    }
    let node_id: [u8; 32] = take(&mut off, 32)?.try_into().unwrap();
    let relay_len = u16::from_le_bytes(take(&mut off, 2)?.try_into().unwrap()) as usize;
    let relay_url = if relay_len > 0 {
        Some(String::from_utf8(take(&mut off, relay_len)?.to_vec()).map_err(|_| "relay utf8")?)
    } else {
        None
    };
    let n = u16::from_le_bytes(take(&mut off, 2)?.try_into().unwrap()) as usize;
    let mut addrs = Vec::with_capacity(n.min(16));
    for _ in 0..n {
        let family = take(&mut off, 1)?[0];
        match family {
            4 => {
                let ip: [u8; 4] = take(&mut off, 4)?.try_into().unwrap();
                let port = u16::from_le_bytes(take(&mut off, 2)?.try_into().unwrap());
                addrs.push(std::net::SocketAddr::new(std::net::IpAddr::V4(ip.into()), port));
            }
            6 => {
                let ip: [u8; 16] = take(&mut off, 16)?.try_into().unwrap();
                let port = u16::from_le_bytes(take(&mut off, 2)?.try_into().unwrap());
                addrs.push(std::net::SocketAddr::new(std::net::IpAddr::V6(ip.into()), port));
            }
            other => return Err(format!("bad ip family {other}")),
        }
    }
    let id = iroh::EndpointId::from_bytes(&node_id).map_err(|e| format!("node id: {e}"))?;
    Ok((id, relay_url, addrs))
}

/// The two pinned fingerprints trailing an NKCT1 ticket body (after the
/// variable relay/addr section): `pqc_fp_algo(1)` then `pqc_sign_fp(32)` then
/// `pqc_enc_fp(32)`. Re-decodes the ticket and skips the transport fields.
fn ticket_fps(s: &str) -> Result<([u8; 32], [u8; 32]), String> {
    use data_encoding::BASE32_NOPAD;
    if !s.starts_with("nkct1") {
        return Err("bad prefix".into());
    }
    let data = BASE32_NOPAD
        .decode(s.as_bytes()[5..].as_ref())
        .map_err(|e| format!("base32: {e}"))?;
    if data.len() < 4 + 32 + 32 {
        return Err("too short".into());
    }
    let body = &data[..data.len() - 4];
    // The two 32-byte fingerprints are the last 64 bytes of the body, preceded
    // by the 1-byte pqc_fp_algo — a fixed tail, so read from the end.
    let n = body.len();
    if n < 65 {
        return Err("no fingerprints".into());
    }
    let mut sign = [0u8; 32];
    let mut enc = [0u8; 32];
    sign.copy_from_slice(&body[n - 64..n - 32]);
    enc.copy_from_slice(&body[n - 32..n]);
    Ok((sign, enc))
}

/// Connect to a peer named by an NKCT1 ticket, over `alpn`. Relay is left at
/// the endpoint's mode (bound with relay disabled here ⇒ direct/LAN only).
///
/// # Safety
/// `ep` live; `ticket` a NUL-terminated NKCT1 string; `alpn` `alpn_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_connect(
    ep: *mut EndpointHandle,
    ticket: *const c_char,
    alpn: *const u8,
    alpn_len: usize,
) -> *mut ConnectionHandle {
    if ep.is_null() || ticket.is_null() || alpn.is_null() {
        return std::ptr::null_mut();
    }
    let ticket = match CStr::from_ptr(ticket).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let alpn = std::slice::from_raw_parts(alpn, alpn_len).to_vec();
    let ep = (*ep).0.clone();
    let res = RT.block_on(async move {
        let (id, relay, direct) = parse_ticket(ticket)?;
        let mut taddrs: Vec<iroh::TransportAddr> = Vec::new();
        if let Some(r) = relay {
            let url = iroh::RelayUrl::from_str(&r).map_err(|e| e.to_string())?;
            taddrs.push(iroh::TransportAddr::Relay(url));
        }
        for a in direct {
            taddrs.push(iroh::TransportAddr::Ip(a));
        }
        let addr = iroh::EndpointAddr::from_parts(id, taddrs);
        ep.connect(addr, &alpn).await.map_err(|e| e.to_string())
    });
    match res {
        Ok(c) => Box::into_raw(Box::new(ConnectionHandle(c))),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Extract the pinned PQC fingerprints from an NKCT1 ticket: `out_sign32` =
/// the responder's ML-DSA identity fingerprint (SHA3-256 of its raw pub), used
/// as the mutual-auth pin (#7 pre-commit and the #11 check); `out_enc32` = the
/// ML-KEM enc-key fingerprint. Either out pointer may be null to skip it.
///
/// # Safety
/// `ticket` a NUL-terminated NKCT1 string; out pointers null or 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_ticket_fingerprints(
    ticket: *const c_char,
    out_sign32: *mut u8,
    out_enc32: *mut u8,
) -> c_int {
    if ticket.is_null() {
        return NKCT_ERR;
    }
    let ticket = match CStr::from_ptr(ticket).to_str() {
        Ok(s) => s,
        Err(_) => return NKCT_ERR,
    };
    match ticket_fps(ticket) {
        Ok((sign, enc)) => {
            if !out_sign32.is_null() {
                std::ptr::copy_nonoverlapping(sign.as_ptr(), out_sign32, 32);
            }
            if !out_enc32.is_null() {
                std::ptr::copy_nonoverlapping(enc.as_ptr(), out_enc32, 32);
            }
            NKCT_OK
        }
        Err(_) => NKCT_ERR,
    }
}

/// This endpoint's own iroh NodeId (32 raw bytes) written to `out32`. These are
/// bound into the app-layer handshake transcript (#1/#2), so C++ needs them.
///
/// # Safety
/// `ep` live; `out32` points to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_endpoint_node_id(ep: *mut EndpointHandle, out32: *mut u8) -> c_int {
    if ep.is_null() || out32.is_null() {
        return NKCT_ERR;
    }
    let ep = &(*ep).0;
    let id = ep.id();
    let bytes = id.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out32, 32);
    NKCT_OK
}

/// The remote peer's iroh NodeId (32 raw bytes) for an established connection.
///
/// # Safety
/// `conn` live; `out32` points to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_conn_remote_node_id(conn: *mut ConnectionHandle, out32: *mut u8) -> c_int {
    if conn.is_null() || out32.is_null() {
        return NKCT_ERR;
    }
    let conn = &(*conn).0;
    let id = conn.remote_id();
    std::ptr::copy_nonoverlapping(id.as_bytes().as_ptr(), out32, 32);
    NKCT_OK
}
