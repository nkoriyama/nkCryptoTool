// Cross-platform pseudo-terminal for the C++ shell server, via portable-pty
// (openpty on unix, ConPTY on Windows) — the same crate the Rust binary's shell
// uses, so the C++ `--serve-shell` gets Windows support without hand-rolling
// ConPTY or pulling a GUI/PTY toolkit into C++. The C++ side owns the handshake,
// framing, and thread bridge; this module only spawns the shell under a PTY and
// exposes blocking read/write/resize/wait over the C ABI.
//
// Threading: the C++ server reads (its output thread) and writes (its input
// loop) concurrently through ONE handle pointer, so every mutable piece sits
// behind its own Mutex — the reader lock is only ever taken by the read thread,
// the writer/master/child locks by the other, so there is no real contention,
// only the aliasing discipline Rust requires across threads.

use std::ffi::{c_char, c_int, CStr};
use std::io::{Read, Write};
use std::sync::Mutex;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

pub struct PtyHandle {
    master: Mutex<Box<dyn MasterPty + Send>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        None
    } else {
        CStr::from_ptr(p).to_str().ok()
    }
}

/// Build the shell command: an interactive login shell when `cmd` is empty, else
/// `<shell> -c <cmd>` (unix) / `<comspec> /C <cmd>` (windows). The environment is
/// inherited from this process (CommandBuilder's default); we only pin TERM and
/// the working directory, mirroring the Rust binary's build_shell_command.
fn build_shell(cmd: &str) -> CommandBuilder {
    #[cfg(not(windows))]
    let mut b = {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut b = CommandBuilder::new(shell);
        if cmd.is_empty() {
            b.arg("-i");
        } else {
            b.arg("-c");
            b.arg(cmd);
        }
        b
    };
    #[cfg(windows)]
    let mut b = {
        let shell = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
        let mut b = CommandBuilder::new(shell);
        if !cmd.is_empty() {
            b.arg("/C");
            b.arg(cmd);
        }
        b
    };
    if std::env::var("TERM").is_err() {
        b.env("TERM", "xterm-256color");
    }
    if let Ok(cwd) = std::env::current_dir() {
        b.cwd(cwd);
    }
    b
}

/// Spawn a shell (or one command) under a PTY sized `cols`x`rows`. `cmd` empty ⇒
/// interactive shell. Returns an opaque handle or null on failure. Free with
/// nkct_pty_free.
///
/// # Safety: `cmd` NUL-terminated or null.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_spawn(cmd: *const c_char, cols: u16, rows: u16) -> *mut PtyHandle {
    let cmd_str = cstr(cmd).unwrap_or("").to_string();
    let r = (|| -> Result<PtyHandle, String> {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: if rows == 0 { 24 } else { rows },
                cols: if cols == 0 { 80 } else { cols },
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;
        let child = pair
            .slave
            .spawn_command(build_shell(&cmd_str))
            .map_err(|e| e.to_string())?;
        // Drop the parent's slave so the master reaches EOF when the shell exits.
        drop(pair.slave);
        let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        Ok(PtyHandle {
            master: Mutex::new(pair.master),
            child: Mutex::new(child),
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    })();
    match r {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Read child output into `buf` (up to `len`). Returns bytes read, 0 on EOF
/// (child gone / PTY closed), or -1 on error.
///
/// # Safety: `h` from nkct_pty_spawn; `buf` writable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_read(h: *mut PtyHandle, buf: *mut u8, len: usize) -> isize {
    if h.is_null() || buf.is_null() {
        return -1;
    }
    let h = &*h;
    let mut reader = match h.reader.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    let slice = std::slice::from_raw_parts_mut(buf, len);
    match reader.read(slice) {
        Ok(n) => n as isize,
        Err(_) => -1,
    }
}

/// Write `len` bytes of `buf` to the child's stdin. Returns `len` on success,
/// -1 on error.
///
/// # Safety: `h` from nkct_pty_spawn; `buf` readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_write(h: *mut PtyHandle, buf: *const u8, len: usize) -> isize {
    if h.is_null() || buf.is_null() {
        return -1;
    }
    let h = &*h;
    let mut writer = match h.writer.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    let slice = std::slice::from_raw_parts(buf, len);
    match writer.write_all(slice).and_then(|_| writer.flush()) {
        Ok(()) => len as isize,
        Err(_) => -1,
    }
}

/// Resize the PTY window.
///
/// # Safety: `h` from nkct_pty_spawn.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_resize(h: *mut PtyHandle, cols: u16, rows: u16) {
    if h.is_null() {
        return;
    }
    let h = &*h;
    if let Ok(master) = h.master.lock() {
        let _ = master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
    }
}

/// Block until the child exits; return its exit code (low bits meaningful), or
/// -1 on error.
///
/// # Safety: `h` from nkct_pty_spawn.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_wait(h: *mut PtyHandle) -> c_int {
    if h.is_null() {
        return -1;
    }
    let h = &*h;
    let mut child = match h.child.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    match child.wait() {
        Ok(status) => status.exit_code() as c_int,
        Err(_) => -1,
    }
}

/// Terminate the child (used when the client disconnects before it exits).
///
/// # Safety: `h` from nkct_pty_spawn.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_kill(h: *mut PtyHandle) {
    if h.is_null() {
        return;
    }
    let h = &*h;
    if let Ok(mut child) = h.child.lock() {
        let _ = child.kill();
    }
}

/// Free the handle (and close the PTY).
///
/// # Safety: `h` from nkct_pty_spawn, not used afterward.
#[no_mangle]
pub unsafe extern "C" fn nkct_pty_free(h: *mut PtyHandle) {
    if !h.is_null() {
        drop(Box::from_raw(h));
    }
}
