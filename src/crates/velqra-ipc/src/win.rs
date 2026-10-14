// SPDX-License-Identifier: GPL-3.0-only
//! Windows named pipes: current-user ACL, remote clients rejected, one core per user.
//!
//! Every `unsafe` block states why it is sound. Handles are owned by exactly one wrapper value and
//! closed exactly once, in `Drop`.

use std::collections::VecDeque;
use std::io;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_NO_DATA,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PeekNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, OpenProcessToken, CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW, DETACHED_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
};

const BUFFER: u32 = 64 * 1024;
const MAX_INSTANCES: u32 = 16;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide_ptr(p: *const u16) -> String {
    let mut len = 0;
    // SAFETY: `p` points to a NUL-terminated UTF-16 string returned by the OS and still allocated.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

fn os_err() -> io::Error {
    io::Error::last_os_error()
}

fn is_closed(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error().map(|c| c as u32),
        Some(ERROR_BROKEN_PIPE) | Some(ERROR_PIPE_NOT_CONNECTED) | Some(ERROR_NO_DATA)
    )
}

/// The current user's SID as a string such as `S-1-5-21-...`.
pub fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: GetCurrentProcess is a valid pseudo handle; `token` is a valid out pointer.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(os_err());
    }
    let result = (|| {
        let mut needed = 0u32;
        // SAFETY: first call with a null buffer only reports the size; `token` is valid.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(os_err());
        }
        // u64 elements keep the buffer aligned for TOKEN_USER
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` is at least `needed` bytes and suitably aligned; `token` is valid.
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(os_err());
        }
        // SAFETY: the call above filled `buf` with a TOKEN_USER whose Sid points inside `buf`.
        let sid = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };
        let mut s: *mut u16 = null_mut();
        // SAFETY: `sid` is a valid SID; `s` is a valid out pointer for the allocated string.
        if unsafe { ConvertSidToStringSidW(sid, &mut s) } == 0 {
            return Err(os_err());
        }
        let text = from_wide_ptr(s);
        // SAFETY: `s` was allocated by ConvertSidToStringSidW and is freed once.
        unsafe { LocalFree(s.cast()) };
        Ok(text)
    })();
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    result
}

/// `D:P(A;;GA;;;<current user>)(A;;GA;;;SY)`: protected, current user and SYSTEM only.
fn pipe_sddl() -> io::Result<Vec<u16>> {
    Ok(wide(&format!(
        "D:P(A;;GA;;;{})(A;;GA;;;SY)",
        current_user_sid()?
    )))
}

fn create_instance(name: &[u16], first: bool, sddl: &[u16]) -> io::Result<HANDLE> {
    let mut sd = null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    } == 0
    {
        return Err(os_err());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: `name` is NUL-terminated and `sa` (with its descriptor) outlives the call.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_INSTANCES,
            BUFFER,
            BUFFER,
            0,
            &sa,
        )
    };
    let err = os_err(); // read before LocalFree can change the last error
                        // SAFETY: `sd` was allocated by the conversion call above and is freed once.
    unsafe { LocalFree(sd) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(err);
    }
    Ok(handle)
}

/// One end of a connected pipe.
pub struct Connection {
    handle: HANDLE,
}

// SAFETY: a Connection exclusively owns its kernel handle; moving it between threads is fine.
unsafe impl Send for Connection {}

impl Drop for Connection {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed exactly once.
        unsafe { CloseHandle(self.handle) };
    }
}

impl Connection {
    /// `Ok(0)` means the peer closed; `TimedOut` means nothing arrived in time and the call can be repeated.
    pub fn read_timeout(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut avail = 0u32;
            // SAFETY: the handle is valid for the life of `self`; only `avail` is written.
            if unsafe {
                PeekNamedPipe(
                    self.handle,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut avail,
                    null_mut(),
                )
            } == 0
            {
                let e = os_err();
                return if is_closed(&e) { Ok(0) } else { Err(e) };
            }
            if avail > 0 {
                let want = buf.len().min(avail as usize) as u32;
                let mut read = 0u32;
                // SAFETY: `buf` has at least `want` writable bytes; data is already available so this does not block.
                if unsafe {
                    ReadFile(
                        self.handle,
                        buf.as_mut_ptr().cast(),
                        want,
                        &mut read,
                        null_mut(),
                    )
                } == 0
                {
                    let e = os_err();
                    return if is_closed(&e) { Ok(0) } else { Err(e) };
                }
                return Ok(read as usize);
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = data.len().min(1 << 20) as u32;
            let mut written = 0u32;
            // SAFETY: `data` has at least `n` readable bytes; the handle is valid.
            if unsafe {
                WriteFile(
                    self.handle,
                    data.as_ptr().cast(),
                    n,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                return Err(os_err());
            }
            data = &data[written as usize..];
        }
        Ok(())
    }
}

/// The listening side. A new instance is created as soon as a client is accepted, so the pipe name stays
/// visible; clients that arrive meanwhile get `ERROR_PIPE_BUSY` and `connect` waits for the next instance.
pub struct PipeServer {
    name: Vec<u16>,
    sddl: Vec<u16>,
    instances: VecDeque<HANDLE>,
}

// SAFETY: a PipeServer exclusively owns its kernel handles; moving it between threads is fine.
unsafe impl Send for PipeServer {}

impl Drop for PipeServer {
    fn drop(&mut self) {
        for h in self.instances.drain(..) {
            // SAFETY: each handle is owned by this value and closed exactly once.
            unsafe { CloseHandle(h) };
        }
    }
}

impl PipeServer {
    /// Fails if any server already owns this pipe name (one core per user).
    pub fn create_first(name: &str) -> io::Result<PipeServer> {
        let (name, sddl) = (wide(name), pipe_sddl()?);
        let h = create_instance(&name, true, &sddl)?;
        Ok(PipeServer {
            name,
            sddl,
            instances: VecDeque::from([h]),
        })
    }

    /// Waits for one client. When it returns, another instance is listening (best effort: running out of
    /// instances must not end the accept loop).
    pub fn accept(&mut self) -> io::Result<Connection> {
        if self.instances.is_empty() {
            self.instances
                .push_back(create_instance(&self.name, false, &self.sddl)?);
        }
        let h = self.instances.pop_front().expect("at least one instance");
        let own = Connection { handle: h }; // closed on every early return below
                                            // SAFETY: `h` is a valid pipe instance owned by `own`; a null OVERLAPPED means a blocking connect.
        if unsafe { ConnectNamedPipe(h, null_mut()) } == 0 {
            let code = os_err().raw_os_error().map(|c| c as u32);
            // CONNECTED: the client got there first. NO_DATA: it connected and already left; the first
            // read will report the closed peer. Both are normal.
            if code != Some(ERROR_PIPE_CONNECTED) && code != Some(ERROR_NO_DATA) {
                return Err(os_err());
            }
        }
        if self.instances.is_empty() {
            if let Ok(next) = create_instance(&self.name, false, &self.sddl) {
                self.instances.push_back(next);
            }
        }
        Ok(own)
    }

    /// SDDL of a listening instance's DACL (for tests and diagnostics).
    pub fn dacl_sddl(&self) -> io::Result<String> {
        let h = *self
            .instances
            .front()
            .ok_or_else(|| io::Error::other("no listening instance"))?;
        let mut sd = null_mut();
        // SAFETY: `h` is a valid handle; only the descriptor out pointer is requested.
        let rc = unsafe {
            GetSecurityInfo(
                h,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let mut text: *mut u16 = null_mut();
        // SAFETY: `sd` is a valid descriptor returned above; `text` receives an allocated string.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        };
        let err = os_err();
        // SAFETY: `sd` was allocated by GetSecurityInfo and is freed once.
        unsafe { LocalFree(sd) };
        if ok == 0 {
            return Err(err);
        }
        let s = from_wide_ptr(text);
        // SAFETY: `text` was allocated by the conversion call and is freed once.
        unsafe { LocalFree(text.cast()) };
        Ok(s)
    }
}

/// Connects to a pipe, waiting up to `timeout` while all instances are busy. A missing pipe fails
/// immediately with `NotFound` so callers can decide to start the core.
pub fn connect(name: &str, timeout: Duration) -> io::Result<Connection> {
    let wname = wide(name);
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `wname` is NUL-terminated. SECURITY_IDENTIFICATION stops a rogue server impersonating us.
        let h = unsafe {
            CreateFileW(
                wname.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return Ok(Connection { handle: h });
        }
        let e = os_err();
        match e.raw_os_error().map(|c| c as u32) {
            Some(ERROR_PIPE_BUSY) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                // SAFETY: `wname` is NUL-terminated; the wait is bounded.
                unsafe { WaitNamedPipeW(wname.as_ptr(), left.as_millis().min(250) as u32) };
            }
            Some(ERROR_FILE_NOT_FOUND) => return Err(io::ErrorKind::NotFound.into()),
            _ => return Err(e),
        }
    }
}

/// Starts a program that outlives the caller and shares nothing with it: no console, no window and,
/// above all, **no inherited handles**. A child that inherited the native-messaging host's stdio pipes
/// would keep them open after the host exits, and the browser would never see the port close.
pub fn spawn_detached(exe: &std::path::Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let application: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut command_line: Vec<u16> = format!("\"{}\"", exe.display())
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both structs are plain data for which all-zero is a valid initial value.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    // SAFETY: as above.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `application` and `command_line` are NUL-terminated and outlive the call (CreateProcessW may
    // modify `command_line`, which is why it is a mutable buffer); the structs are valid for the call.
    // bInheritHandles is FALSE (0) on purpose.
    let ok = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
            null(),
            null(),
            &startup,
            &mut info,
        )
    };
    if ok == 0 {
        return Err(os_err());
    }
    // SAFETY: both handles were just returned by CreateProcessW and are closed exactly once; the child
    // keeps running without them.
    unsafe {
        CloseHandle(info.hProcess);
        CloseHandle(info.hThread);
    }
    Ok(())
}
