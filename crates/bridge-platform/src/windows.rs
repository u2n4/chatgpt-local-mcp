use bridge_types::{AvailableState, BridgeError, CapabilityStatus, ErrorCode, OriginLayer};
use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_RENAME_INFORMATION, FILE_RENAME_POSIX_SEMANTICS, FILE_RENAME_REPLACE_IF_EXISTS,
    FileRenameInformationEx, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, RtlNtStatusToDosError,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, GetFinalPathNameByHandleW,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegEnumValueW,
    RegOpenKeyExW, RegQueryInfoKeyW,
};
use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW, UOI_NAME,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThreadId, GetProcessTimes, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
};

use crate::{ContainmentProbe, FileIdentity, HostResources, optional_gpu_probe, sha256_file};

pub const PINNED_CODEX_VERSION: &str = "0.171.0";
pub const PINNED_CODEX_SHA256: &str =
    "cefea4ffee1fff04983a99c0dda99944d8b380e891e740a28b32f4b815a6e0b7";

fn to_wide_null(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Inspect exact NTFS file/directory identity without following reparse points (junctions/symlinks).
pub fn file_identity_no_follow(path: &Path) -> Result<FileIdentity, BridgeError> {
    file_identity_no_follow_named(path, &path.display().to_string())
}

/// Inspect a project path while using only its relative name in diagnostics.
pub fn file_identity_no_follow_named(path: &Path, relative: &str) -> Result<FileIdentity, BridgeError> {
    let file = open_path_metadata_no_follow(path).map_err(|_| BridgeError::new(
        ErrorCode::FileNotFound,
        format!("Path does not exist or cannot be opened: {relative}"),
        OriginLayer::FileService,
    ))?;
    file_identity_from_handle(&file)
}

pub fn open_path_metadata_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
}

pub fn open_read_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Verify identity from an already-opened std::fs::File handle to prevent TOCTOU rename races.
pub fn file_identity_from_handle(file: &std::fs::File) -> Result<FileIdentity, BridgeError> {
    use std::os::windows::io::AsRawHandle;
    let raw = file.as_raw_handle() as HANDLE;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(raw, &mut info) };
    if ok == 0 {
        return Err(BridgeError::new(
            ErrorCode::InternalError,
            "GetFileInformationByHandle failed on open file handle.",
            OriginLayer::FileService,
        ));
    }
    let size = ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64);
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index_high: info.nFileIndexHigh,
        file_index_low: info.nFileIndexLow,
        is_reparse_point: (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
        is_directory: (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
        n_links: info.nNumberOfLinks,
        size_bytes: size,
    })
}

/// Resolve the path of the handle that will be read, rather than reopening a pathname.
pub fn file_path_from_handle(file: &std::fs::File) -> Result<PathBuf, BridgeError> {
    use std::os::windows::io::AsRawHandle;
    let handle = file.as_raw_handle() as HANDLE;
    let mut buffer = vec![0u16; 512];
    loop {
        // The handle stays open through the call and the buffer holds the advertised number of UTF-16 units.
        let length = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, FILE_NAME_NORMALIZED)
        } as usize;
        if length == 0 || length > 32_768 {
            return Err(BridgeError::new(ErrorCode::StalePrecondition,
                "Cannot verify the opened file path.", OriginLayer::FileService));
        }
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length + 1, 0);
    }
}

/// Allow concurrent readers but keep a file stable against writes and deletion while verifying it.
pub fn open_stable_read(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Pin a regular directory against renaming without following its final reparse point.
pub fn open_patch_directory(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        // Writing directory entries must stay possible; the guard excludes deletion of the directory itself.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
}

/// Deny competing in-place writes while permitting the planned atomic replacement.
pub fn open_patch_preimage(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(path)
}

pub fn create_patch_stage(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

/// Install the opened staged file at a single name relative to the pinned directory.
pub fn commit_patch_stage(stage: &std::fs::File, parent: &std::fs::File, name: &OsStr, replace: bool) -> Result<(), BridgeError> {
    use std::mem::{offset_of, size_of};
    use std::os::windows::io::AsRawHandle;
    let name: Vec<u16> = name.encode_wide().collect();
    if name.is_empty() || name.len() > 255 || name.iter().any(|&ch| matches!(ch, 0 | 47 | 58 | 92)) {
        return Err(BridgeError::new(ErrorCode::InvalidArgument, "Patch destination must be a single filename.", OriginLayer::FileService));
    }
    let name_bytes = name.len() * size_of::<u16>();
    let offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
    let bytes = (offset + name_bytes + size_of::<u16>()).max(size_of::<FILE_RENAME_INFORMATION>());
    let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let record = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut io = IO_STATUS_BLOCK::default();
    // The buffer is suitably aligned and includes space for all filename units.
    // Windows consumes it synchronously while both borrowed handles stay open.
    let status = unsafe {
        (*record).Anonymous.Flags = if replace { FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS } else { 0 };
        (*record).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*record).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), storage.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(), name.len());
        NtSetInformationFile(stage.as_raw_handle() as HANDLE, &mut io, record.cast(), bytes as u32, FileRenameInformationEx)
    };
    if status != 0 {
        let error = std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32);
        let code = if !replace && error.kind() == std::io::ErrorKind::AlreadyExists {
            ErrorCode::VersionConflict
        } else {
            ErrorCode::InternalError
        };
        return Err(BridgeError::new(code, format!("Commit of opened patch stage failed: {error}"), OriginLayer::FileService));
    }
    Ok(())
}

/// Atomically replace `dst` with `src` on NTFS without a delete-before-rename absence window
/// using `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
pub fn atomic_replace_file(src: &Path, dst: &Path, relative_target: &str) -> Result<(), BridgeError> {
    let w_src = to_wide_null(src.as_os_str());
    let w_dst = to_wide_null(dst.as_os_str());
    let ok = unsafe {
        MoveFileExW(
            w_src.as_ptr(),
            w_dst.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        let code = std::io::Error::last_os_error();
        return Err(BridgeError::new(
            ErrorCode::InternalError,
            format!("Atomic replacement of '{relative_target}' failed: {code}"),
            OriginLayer::FileService,
        ));
    }
    Ok(())
}

/// Query active `WinSta\Desktop` name (e.g. `WinSta0\Default` vs sandboxed desktop).
/// True when stdout is a pipe whose other end has been closed. The pipe state is
/// queried through the handle, so nothing is written to the stream.
pub fn stdout_peer_closed() -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::NtQueryInformationFile;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};

    /// `FILE_PIPE_LOCAL_INFORMATION` from the Windows driver kit.
    #[repr(C)]
    #[derive(Default)]
    struct PipeLocalInformation {
        named_pipe_type: u32,
        named_pipe_configuration: u32,
        maximum_instances: u32,
        current_instances: u32,
        inbound_quota: u32,
        read_data_available: u32,
        outbound_quota: u32,
        write_quota_available: u32,
        named_pipe_state: u32,
        named_pipe_end: u32,
    }
    const FILE_PIPE_LOCAL_INFORMATION_CLASS: i32 = 24;
    const FILE_PIPE_CLOSING_STATE: u32 = 4;

    let handle = std::io::stdout().as_raw_handle();
    if handle.is_null() || unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return false;
    }
    let mut info = PipeLocalInformation::default();
    let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let status = unsafe {
        NtQueryInformationFile(
            handle,
            &mut status_block,
            (&mut info as *mut PipeLocalInformation).cast(),
            std::mem::size_of::<PipeLocalInformation>() as u32,
            FILE_PIPE_LOCAL_INFORMATION_CLASS,
        )
    };
    status == 0 && info.named_pipe_state == FILE_PIPE_CLOSING_STATE
}

pub fn current_desktop_name() -> Option<String> {
    unsafe fn query_obj_name(handle: *mut core::ffi::c_void) -> Option<String> {
        if handle.is_null() {
            return None;
        }
        let mut buf = [0u16; 256];
        let mut needed: u32 = 0;
        let ok = unsafe {
            GetUserObjectInformationW(
                handle,
                UOI_NAME,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                (buf.len() * 2) as u32,
                &mut needed,
            )
        };
        if ok == 0 {
            return None;
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..len]))
    }

    let winsta = unsafe { GetProcessWindowStation() };
    let desk = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    let w = unsafe { query_obj_name(winsta) };
    let d = unsafe { query_obj_name(desk) };
    match (w, d) {
        (Some(ws), Some(dk)) => Some(format!("{ws}\\{dk}")),
        (Some(ws), None) => Some(ws),
        (None, Some(dk)) => Some(dk),
        (None, None) => None,
    }
}

pub fn current_process_working_set_bytes() -> Option<u64> {
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) };
    if ok != 0 {
        Some(pmc.WorkingSetSize as u64)
    } else {
        None
    }
}

pub fn host_resources() -> HostResources {
    host_resources_with_gpu(true)
}

pub fn host_resources_with_gpu(probe_gpu: bool) -> HostResources {
    let mut mem: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let ok = unsafe { GlobalMemoryStatusEx(&mut mem) };
    let (total_mb, avail_mb, used_pct) = if ok != 0 {
        (
            mem.ullTotalPhys / (1024 * 1024),
            mem.ullAvailPhys / (1024 * 1024),
            mem.dwMemoryLoad,
        )
    } else {
        (0, 0, 0)
    };
    let desktop = current_desktop_name();
    let mxc_default_desktop = desktop
        .as_deref()
        .map(|d| d.to_ascii_lowercase().ends_with("\\default"))
        .unwrap_or(false);
    HostResources {
        ram_total_mb: total_mb,
        ram_available_mb: avail_mb,
        ram_used_percent: used_pct,
        process_working_set_bytes: current_process_working_set_bytes(),
        gpu_probe: optional_gpu_probe(probe_gpu),
        desktop_name: desktop,
        mxc_default_desktop,
    }
}

pub fn codex_mxc_vendor_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    let p = PathBuf::from(appdata)
        .join("npm/node_modules/@openai/codex/node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe");
    if p.is_file() { Some(p) } else { None }
}

/// Report MXC prerequisites separately from containment in the Rust runner.
pub fn probe_mxc_backend() -> ContainmentProbe {
    let desktop = current_desktop_name();
    let default_desktop = desktop
        .as_deref()
        .map(|d| d.to_ascii_lowercase().ends_with("\\default"))
        .unwrap_or(false);
    let bin = codex_mxc_vendor_path();
    let (sha, hash_ok) = match &bin {
        Some(p) => match sha256_file(p) {
            Ok(h) => {
                let matched = h.eq_ignore_ascii_case(PINNED_CODEX_SHA256);
                (Some(h), matched)
            }
            Err(_) => (None, false),
        },
        None => (None, false),
    };
    let reason = if !hash_ok {
        "Pinned codex.exe MXC binary missing or SHA-256 mismatch. The Rust runner does not launch jobs through MXC."
            .to_string()
    } else if !default_desktop {
        format!(
            "Pinned codex.exe hash matched on desktop '{}'. The Rust runner does not launch jobs through MXC.",
            desktop.as_deref().unwrap_or("unknown")
        )
    } else {
        "Pinned codex.exe hash matched on WinSta0\\Default. The Rust runner does not launch jobs through MXC."
            .to_string()
    };
    ContainmentProbe {
        backend: "codex-sandbox-mxc".to_string(),
        pinned_version: PINNED_CODEX_VERSION.to_string(),
        binary_path: bin.map(|p| p.display().to_string()),
        binary_sha256: sha,
        binary_hash_verified: hash_ok,
        desktop_name: desktop,
        interactive_default_desktop: default_desktop,
        automatic_weaker_fallback: false,
        status: CapabilityStatus {
            implemented: false,
            authorized: false,
            available: AvailableState::False,
            verified: false,
            last_verified_at: None,
            reason,
        },
    }
}

/// Query exact Windows process creation timestamp (100ns FILETIME ticks) so PID reuse
/// cannot be mistaken for the original job process on reconnect.
pub fn process_creation_time_100ns(pid: u32) -> Option<u64> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut create = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let ok = unsafe { GetProcessTimes(handle, &mut create, &mut exit, &mut kernel, &mut user) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    Some(((create.dwHighDateTime as u64) << 32) | (create.dwLowDateTime as u64))
}

/// RAII Win32 Job Object supervising a process tree (children + grandchildren) with
/// kill-on-close, active process cap, memory cap, and explicit `TerminateJobObject`.
/// NOTE per Master Prompt §8 [S13]: Win32 Job Objects enforce process/resource supervision,
/// NOT complete filesystem/network containment (which requires MXC/AppContainer/VM).
pub struct WinJobObject {
    handle: HANDLE,
}

// SAFETY: Win32 Job Object kernel handles are thread-safe to pass/terminate across threads.
unsafe impl Send for WinJobObject {}
unsafe impl Sync for WinJobObject {}

impl WinJobObject {
    pub fn new(max_memory_mb: u64, max_processes: u32) -> Result<Self, BridgeError> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                "CreateJobObjectW failed.",
                OriginLayer::JobRunner,
            ));
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.BasicLimitInformation.ActiveProcessLimit = max_processes.max(1);
        info.JobMemoryLimit = (max_memory_mb.max(64) as usize).saturating_mul(1024 * 1024);

        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            unsafe { CloseHandle(handle) };
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                "SetInformationJobObject failed.",
                OriginLayer::JobRunner,
            ));
        }
        Ok(Self { handle })
    }

    /// A job that only ties process lifetime together: when its last handle closes,
    /// every process in it ends. It sets no process or memory limit.
    pub fn kill_on_close() -> Result<Self, BridgeError> {
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                "CreateJobObjectW failed.",
                OriginLayer::JobRunner,
            ));
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            unsafe { CloseHandle(handle) };
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                "SetInformationJobObject failed.",
                OriginLayer::JobRunner,
            ));
        }
        Ok(Self { handle })
    }

    pub fn assign_pid(&self, pid: u32) -> Result<(), BridgeError> {
        let proc = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if proc.is_null() {
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                format!("OpenProcess failed for pid {pid}"),
                OriginLayer::JobRunner,
            ));
        }
        let ok = unsafe { AssignProcessToJobObject(self.handle, proc) };
        unsafe { CloseHandle(proc) };
        if ok == 0 {
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                format!("AssignProcessToJobObject failed for pid {pid}"),
                OriginLayer::JobRunner,
            ));
        }
        Ok(())
    }

    pub fn terminate_tree(&self, exit_code: u32) -> Result<(), BridgeError> {
        let ok = unsafe { TerminateJobObject(self.handle, exit_code) };
        if ok == 0 {
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                "TerminateJobObject failed.",
                OriginLayer::JobRunner,
            ));
        }
        Ok(())
    }

    pub fn contains_pid(&self, pid: u32) -> Result<bool, BridgeError> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return Err(BridgeError::new(ErrorCode::IsolationNotVerified, "Cannot verify supervisor process identity.", OriginLayer::Containment));
        }
        let mut member = 0;
        let ok = unsafe { IsProcessInJob(handle, self.handle, &mut member) };
        unsafe { CloseHandle(handle) };
        if ok == 0 {
            return Err(BridgeError::new(ErrorCode::IsolationNotVerified, "Cannot verify supervisor Job Object membership.", OriginLayer::Containment));
        }
        Ok(member != 0)
    }

    pub fn active_processes(&self) -> Result<u32, BridgeError> {
        let mut counts: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe { QueryInformationJobObject(self.handle, JobObjectBasicAccountingInformation,
            (&mut counts as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            std::mem::size_of_val(&counts) as u32, std::ptr::null_mut()) };
        if ok == 0 {
            return Err(BridgeError::new(ErrorCode::IsolationNotVerified, "Cannot verify supervised process-tree exit.", OriginLayer::Containment));
        }
        Ok(counts.ActiveProcesses)
    }

    /// Enforce a hard CPU rate cap (`1..=100` percent) on every process in this Job Object.
    /// Fails closed if Windows refuses to apply `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`.
    pub fn set_cpu_hard_cap(&self, max_cpu_percent: u8) -> Result<(), BridgeError> {
        if !(1..=100).contains(&max_cpu_percent) {
            return Err(BridgeError::new(
                ErrorCode::InvalidArgument,
                "CPU hard cap percent must be between 1 and 100.",
                OriginLayer::JobRunner,
            ));
        }
        let info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                CpuRate: (max_cpu_percent as u32) * 100,
            },
        };
        let ok = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectCpuRateControlInformation,
                (&info as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                format!("SetInformationJobObject(JobObjectCpuRateControlInformation) failed: {err}"),
                OriginLayer::JobRunner,
            ));
        }
        Ok(())
    }

    /// Query the active CPU rate control flags and rate (in hundredths of a percent) on this Job Object.
    pub fn query_cpu_rate_control(&self) -> Result<(u32, u32), BridgeError> {
        let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectCpuRateControlInformation,
                (&mut info as *mut JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(BridgeError::new(
                ErrorCode::InternalError,
                "QueryInformationJobObject(JobObjectCpuRateControlInformation) failed.",
                OriginLayer::JobRunner,
            ));
        }
        let rate = unsafe { info.Anonymous.CpuRate };
        Ok((info.ControlFlags, rate))
    }
}

impl Drop for WinJobObject {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

/// The environment variables Windows keeps for the user and for the machine, as name and value.
///
/// A process started with a cleared environment does not receive them, but any process of this
/// user can still read them from the registry, a sandboxed one included. The value is `None`
/// when it is not text, is longer than 1 MiB or changed while it was read. A key that does not
/// exist has no entries. A `None` result means a key could not be read, or changed while it was
/// read, so the answer is unknown: both keys are read twice and the two readings must agree.
pub fn persistent_environment() -> Option<Vec<(String, Option<String>)>> {
    let first = scan_persistent_environment()?;
    (scan_persistent_environment()? == first).then_some(first)
}

fn scan_persistent_environment() -> Option<Vec<(String, Option<String>)>> {
    struct Key(HKEY);
    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by `RegOpenKeyExW` and is closed once.
            unsafe { RegCloseKey(self.0) };
        }
    }
    const SUCCESS: u32 = 0;
    const FILE_NOT_FOUND: u32 = 2;
    const NO_MORE_ITEMS: u32 = 259;
    const MAX_VALUE_BYTES: u32 = 1024 * 1024;
    let mut entries = Vec::new();
    for (root, key) in [
        (HKEY_CURRENT_USER, "Environment"),
        (HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ] {
        let path = to_wide_null(OsStr::new(key));
        let mut handle: HKEY = std::ptr::null_mut();
        // SAFETY: `path` is NUL-terminated and `handle` receives an owned key on success.
        match unsafe { RegOpenKeyExW(root, path.as_ptr(), 0, KEY_READ, &mut handle) } {
            SUCCESS => {}
            FILE_NOT_FOUND => continue,
            _ => return None,
        }
        let key = Key(handle);
        // The number of values and the time of the last change. A change during the enumeration
        // can move a value past the index already read, so the key must be the same afterwards.
        let stamp = || {
            let (mut values, mut written) = (0u32, FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 });
            // SAFETY: only the two out-pointers given are written; the others may be null.
            let status = unsafe {
                RegQueryInfoKeyW(key.0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut(),
                    std::ptr::null_mut(), std::ptr::null_mut(), &mut values, std::ptr::null_mut(), std::ptr::null_mut(),
                    std::ptr::null_mut(), &mut written)
            };
            (status == SUCCESS).then_some((values, written.dwLowDateTime, written.dwHighDateTime))
        };
        let before = stamp()?;
        let first = entries.len();
        // A value name has at most 16383 characters.
        let mut name = vec![0u16; 16384];
        for index in 0.. {
            let (mut name_len, mut first_kind, mut size) = (name.len() as u32, 0u32, 0u32);
            // SAFETY: the name buffer and the lengths are valid; no data is requested, so only
            // the size of the value is returned.
            let status = unsafe {
                RegEnumValueW(key.0, index, name.as_mut_ptr(), &mut name_len, std::ptr::null(), &mut first_kind,
                    std::ptr::null_mut(), &mut size)
            };
            match status {
                SUCCESS => {}
                NO_MORE_ITEMS => break,
                _ => return None,
            }
            let entry = String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]);
            let text = (first_kind == REG_SZ || first_kind == REG_EXPAND_SZ) && size <= MAX_VALUE_BYTES && size % 2 == 0;
            let value = text.then(|| {
                let mut data = vec![0u8; size as usize];
                let (mut name_len, mut kind, mut read) = (name.len() as u32, 0u32, size);
                // SAFETY: `data` holds `read` bytes and the other buffers are as above.
                let status = unsafe {
                    RegEnumValueW(key.0, index, name.as_mut_ptr(), &mut name_len, std::ptr::null(), &mut kind,
                        data.as_mut_ptr(), &mut read)
                };
                // The value may have been replaced between the two calls.
                let same = status == SUCCESS && kind == first_kind && read == size && String::from_utf16_lossy(&name[..(name_len as usize).min(name.len())]) == entry;
                same.then(|| {
                    let wide: Vec<u16> = data[..read as usize].chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
                    String::from_utf16_lossy(&wide).trim_end_matches(char::from(0)).to_owned()
                })
            }).flatten();
            entries.push((entry, value));
        }
        if stamp()? != before || entries.len() - first != before.0 as usize {
            return None;
        }
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_environment_lists_the_machine_variables() {
        let entries = persistent_environment().expect("environment keys are readable");
        assert!(entries.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Path") && value.as_deref().is_some_and(|value| !value.is_empty())
        }));
    }

    #[test]
    fn win32_identity_and_memory_probes_work() {
        let tmp = std::env::temp_dir();
        let id = file_identity_no_follow(&tmp).expect("temp dir identity");
        assert!(id.is_directory);
        assert!(id.canonical_id().starts_with("ntfs:"));
        let res = host_resources();
        assert!(res.ram_total_mb > 0);
        assert!(res.process_working_set_bytes.unwrap_or(0) > 0);
    }

    #[test]
    fn win32_job_object_terminates_spawned_child_tree() {
        let job = WinJobObject::new(256, 8).expect("create job object");
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/C", "ping -n 30 127.0.0.1 >NUL"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        assert!(process_creation_time_100ns(pid).is_some());
        job.assign_pid(pid).expect("assign child to job");
        job.terminate_tree(137).expect("terminate tree");
        let status = child.wait().expect("wait terminated child");
        assert_eq!(status.code(), Some(137));
    }

    #[test]
    fn win32_job_object_cpu_hard_cap_sets_and_rejects_invalid_percent() {
        let job = WinJobObject::new(256, 8).expect("create job object");
        job.set_cpu_hard_cap(50).expect("set 50% hard cap");
        let (flags, rate) = job.query_cpu_rate_control().expect("query cpu rate");
        assert_eq!(
            flags,
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        );
        assert_eq!(rate, 5000);

        job.set_cpu_hard_cap(25).expect("tighten to 25% hard cap");
        let (flags, rate) = job.query_cpu_rate_control().expect("query 25% cpu rate");
        assert_eq!(
            flags,
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        );
        assert_eq!(rate, 2500);

        assert_eq!(job.set_cpu_hard_cap(0).unwrap_err().code, ErrorCode::InvalidArgument);
        assert_eq!(job.set_cpu_hard_cap(101).unwrap_err().code, ErrorCode::InvalidArgument);
    }
}
