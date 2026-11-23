"""Handle-relative, local NTFS project files for Windows."""

from __future__ import annotations

import base64
import codecs
from collections import deque
import ctypes as ct
import hashlib
import json
import os
import re
from contextlib import ExitStack, contextmanager
from ctypes import wintypes as w
from pathlib import Path
from uuid import uuid4


class FileBoundaryError(ValueError):
    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


def _fail(code: str, message: str, details: dict | None = None):
    raise FileBoundaryError(code, message, details)


_MAX_FILE = 2 * 1024 * 1024
_MAX_READ_FILE = 32 * 1024 * 1024
_MAX_DIRECTORY = 4096
_MAX_SCAN = 2048
_MAX_SCAN_BYTES = 16 * 1024 * 1024
_MAX_HITS = 1000
_PRIVATE = ".edge-project-bridge"
_GENERATED_DIRS = frozenset({
    ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", "dist", "build",
    ".next", ".toolchain", ".nuxt", ".turbo", ".parcel-cache",
    ".tox", ".eggs", ".gradle", ".svelte-kit", "coverage", "htmlcov",
})
_BINARY_SEARCH_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff",
    ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".mp4", ".mov", ".mkv", ".avi", ".webm",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".whl",
    ".exe", ".dll", ".pyd", ".so", ".dylib", ".a", ".o", ".obj", ".lib", ".pdb",
    ".pyc", ".pyo", ".class", ".jar", ".wasm",
    ".ttf", ".otf", ".woff", ".woff2", ".pdf",
    ".blend", ".glb", ".gltf", ".stl", ".ply", ".fbx",
    ".sqlite", ".sqlite3", ".db", ".bin", ".dat",
    ".onnx", ".pth", ".pt", ".safetensors", ".ckpt",
})
_DENIED = frozenset({
    ".git", ".hg", ".svn", ".ssh", ".aws", ".azure", ".gnupg", ".kube",
    ".codex", ".claude", ".agents", ".npmrc", ".pypirc", ".netrc",
    ".git-credentials", ".terraform", ".htpasswd", ".pgpass", ".my.cnf",
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk",
    "kubeconfig", "credentials.json", "credentials.yaml", "credentials.yml",
    "credentials.toml", "credentials.ini", "credentials.xml",
    "secrets.json", "secrets.js", "secrets.ts", "secrets.yaml", "secrets.yml",
    "secrets.toml", "secrets.ini", "secrets.env",
    "auth.json", "auth.yaml", "auth.yml", "auth.toml",
    ".install-token", "api-token", "api-unit-token",
    "cookies", "cookies-journal", "login data", "login data-journal",
    "login data for account", "login data for account-journal",
    "trust tokens", "trust tokens-journal", "web data", "web data-journal",
    "account web data", "account web data-journal",
    _PRIVATE,
})
_DENIED_SUFFIXES = (
    ".pem", ".pfx", ".p12", ".key", ".token", ".kdbx", ".jks", ".keystore", ".ppk", ".ovpn",
)
_DEVICES = {
    "con", "prn", "aux", "nul", "conin$", "conout$",
    *(f"{kind}{digit}" for kind in ("com", "lpt") for digit in "0123456789¹²³"),
}
_BAD_CHAR = re.compile(r'[<>:"|?*\x00-\x1f]')
_HASH = re.compile(r"[0-9a-f]{64}")
_RECOVERY_ID = re.compile(r"[0-9a-f]{32}")
_FILE_ID = re.compile(r"ntfs:[0-9a-f]{8}:[0-9a-f]{16}")
_STAGE_NAME = re.compile(r"\.edge-bridge-tmp-[0-9a-f]{32}")


def _part(name: str) -> None:
    if (
        not name or name.endswith((" ", ".")) or _BAD_CHAR.search(name)
        or name.split(".", 1)[0].rstrip().casefold() in _DEVICES
        or len(name.encode("utf-16-le", errors="surrogatepass")) > 510
    ):
        _fail("UNSUPPORTED_PATH_TYPE", "Invalid or reserved Windows path component.")
    lowered = name.casefold()
    if (
        lowered in _DENIED or lowered == ".env" or lowered.startswith((".env.", ".edge-bridge-tmp-"))
        or lowered.endswith(_DENIED_SUFFIXES)
    ):
        _fail("PATH_OUTSIDE_ROOT", "The path is reserved or excluded by project policy.")


def _parts(path: str, *, directory: bool = False) -> list[str]:
    if not isinstance(path, str) or len(path) > 4096:
        _fail("UNSUPPORTED_PATH_TYPE", "Expected a bounded relative Windows path.")
    if path == "." and directory:
        return []
    if path.startswith(("/", "\\")) or re.match(r"^[a-zA-Z]:", path):
        _fail("PATH_OUTSIDE_ROOT", "Absolute paths and drive-relative paths are prohibited.")
    parts = path.replace("\\", "/").split("/")
    if any(part in (".", "..") for part in parts):
        _fail("PATH_OUTSIDE_ROOT", "Traversal and dot segments are prohibited.")
    if len(parts) > 64:
        _fail("RESOURCE_BUDGET_EXCEEDED", "The path is too deep.")
    for part in parts:
        _part(part)
    return parts


def _window(cursor: int, limit: int, maximum: int) -> None:
    if type(cursor) is not int or type(limit) is not int or cursor < 0 or not 1 <= limit <= maximum:
        _fail("INVALID_ARGUMENT", "Invalid cursor, offset, or page size.")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected(value: str | None) -> None:
    if value is not None and (not isinstance(value, str) or not _HASH.fullmatch(value)):
        _fail("INVALID_ARGUMENT", "Expected a lowercase SHA-256 digest.")


def _utf8(content: str) -> bytes:
    if not isinstance(content, str):
        _fail("INVALID_ARGUMENT", "Expected text content.")
    try:
        raw = content.encode("utf-8")
    except UnicodeError:
        _fail("INVALID_ARGUMENT", "Content is not valid Unicode.")
    if len(raw) > _MAX_FILE:
        _fail("RESOURCE_BUDGET_EXCEEDED", "Content exceeds the file size limit.")
    return raw


class _UnicodeString(ct.Structure):
    _fields_ = [("Length", w.USHORT), ("MaximumLength", w.USHORT), ("Buffer", ct.c_void_p)]


class _ObjectAttributes(ct.Structure):
    _fields_ = [
        ("Length", w.ULONG), ("RootDirectory", w.HANDLE),
        ("ObjectName", ct.POINTER(_UnicodeString)), ("Attributes", w.ULONG),
        ("SecurityDescriptor", ct.c_void_p), ("SecurityQualityOfService", ct.c_void_p),
    ]


class _IoStatus(ct.Structure):
    _fields_ = [("Status", ct.c_void_p), ("Information", ct.c_size_t)]


class _FileInformation(ct.Structure):
    _fields_ = [
        ("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
        ("written", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD),
        ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD),
        ("index_low", w.DWORD),
    ]

    @property
    def size(self) -> int:
        return self.size_high << 32 | self.size_low

    @property
    def identity(self) -> str:
        return f"ntfs:{self.volume:08x}:{self.index_high:08x}{self.index_low:08x}"


class _RenameInfo(ct.Structure):
    _fields_ = [
        ("Flags", w.ULONG), ("RootDirectory", w.HANDLE), ("FileNameLength", w.ULONG),
        ("FileName", w.WCHAR * 1),
    ]


_SYNC = 0x00100000
_READ_CONTROL = 0x00020000
_DELETE = 0x00010000
_READ_ATTR = 0x80
_READ_DATA = 0x01
_WRITE_DATA = 0x02
_DIR_ACCESS = _SYNC | _READ_ATTR | _READ_DATA | 0x20
_FILE_ACCESS = _SYNC | _READ_ATTR | _READ_DATA
_READ_SHARE = 0x01
_DIRECTORY_SHARE = 0x03
_DIRECTORY_OPTION = 0x01
_FILE_OPTION = 0x40
_REPARSE_ATTRIBUTE = 0x400
_DIRECTORY_ATTRIBUTE = 0x10
_ABSENT = {0xC0000034, 0xC000003A, 0xC000000F}
_COLLISIONS = {0xC0000035}
_NO_MORE_FILES = 0x80000006


def _status(status: int):
    code = status & 0xFFFFFFFF
    if status >= 0:
        return
    if code in _ABSENT:
        _fail("FILE_NOT_FOUND", "The requested object does not exist.")
    if code in _COLLISIONS:
        _fail("VERSION_CONFLICT", "The destination already exists.")
    if code == 0xC0000043:
        _fail("VERSION_CONFLICT", "The file is open in an incompatible mode.")
    if code in {0xC000050B, 0xC0000024, 0xC00000BA, 0xC0000103}:
        _fail("UNSUPPORTED_PATH_TYPE", "The path is a reparse point or unsupported object.")
    _fail("FILE_ACCESS_FAILED", f"Windows refused the operation (NTSTATUS 0x{code:08x}).")


def _wincheck(success, operation: str):
    if not success:
        _fail("FILE_ACCESS_FAILED", f"Windows refused {operation} (error {ct.get_last_error()}).")


if os.name == "nt":
    _k = ct.WinDLL("kernel32", use_last_error=True)
    _n = ct.WinDLL("ntdll")
    _a = ct.WinDLL("advapi32", use_last_error=True)
    _k.CreateFileW.argtypes = [
        w.LPCWSTR, w.DWORD, w.DWORD, ct.c_void_p, w.DWORD, w.DWORD, w.HANDLE,
    ]
    _k.CreateFileW.restype = w.HANDLE
    _k.CloseHandle.argtypes = [w.HANDLE]
    _k.CloseHandle.restype = w.BOOL
    _k.GetFileInformationByHandle.argtypes = [w.HANDLE, ct.POINTER(_FileInformation)]
    _k.GetFileInformationByHandle.restype = w.BOOL
    _k.GetFileInformationByHandleEx.argtypes = [w.HANDLE, ct.c_int, ct.c_void_p, w.DWORD]
    _k.GetFileInformationByHandleEx.restype = w.BOOL
    _k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
    _k.GetFinalPathNameByHandleW.restype = w.DWORD
    _k.GetDriveTypeW.argtypes = [w.LPCWSTR]
    _k.GetDriveTypeW.restype = w.UINT
    _k.GetVolumeInformationByHandleW.argtypes = [
        w.HANDLE, w.LPWSTR, w.DWORD, ct.POINTER(w.DWORD), ct.POINTER(w.DWORD),
        ct.POINTER(w.DWORD), w.LPWSTR, w.DWORD,
    ]
    _k.GetVolumeInformationByHandleW.restype = w.BOOL
    _k.ReadFile.argtypes = [w.HANDLE, ct.c_void_p, w.DWORD, ct.POINTER(w.DWORD), ct.c_void_p]
    _k.ReadFile.restype = w.BOOL
    _k.WriteFile.argtypes = _k.ReadFile.argtypes
    _k.WriteFile.restype = w.BOOL
    _k.FlushFileBuffers.argtypes = [w.HANDLE]
    _k.FlushFileBuffers.restype = w.BOOL
    _k.SetFileInformationByHandle.argtypes = [w.HANDLE, ct.c_int, ct.c_void_p, w.DWORD]
    _k.SetFileInformationByHandle.restype = w.BOOL
    _k.LocalFree.argtypes = [ct.c_void_p]
    _k.LocalFree.restype = ct.c_void_p
    _a.GetSecurityInfo.argtypes = [
        w.HANDLE, ct.c_int, w.DWORD, ct.c_void_p, ct.c_void_p, ct.c_void_p, ct.c_void_p,
        ct.POINTER(ct.c_void_p),
    ]
    _a.GetSecurityInfo.restype = w.DWORD
    _a.GetSecurityDescriptorLength.argtypes = [ct.c_void_p]
    _a.GetSecurityDescriptorLength.restype = w.DWORD
    _n.NtCreateFile.argtypes = [
        ct.POINTER(w.HANDLE), w.DWORD, ct.POINTER(_ObjectAttributes), ct.POINTER(_IoStatus),
        ct.c_void_p, w.ULONG, w.ULONG, w.ULONG, w.ULONG, ct.c_void_p, w.ULONG,
    ]
    _n.NtCreateFile.restype = ct.c_long
    _n.NtQueryDirectoryFile.argtypes = [
        w.HANDLE, w.HANDLE, ct.c_void_p, ct.c_void_p, ct.POINTER(_IoStatus),
        ct.c_void_p, w.ULONG, ct.c_int, ct.c_ubyte, ct.c_void_p, ct.c_ubyte,
    ]
    _n.NtQueryDirectoryFile.restype = ct.c_long
    _n.NtSetInformationFile.argtypes = [
        w.HANDLE, ct.POINTER(_IoStatus), ct.c_void_p, w.ULONG, ct.c_int,
    ]
    _n.NtSetInformationFile.restype = ct.c_long


def _info(handle, *, directory: bool) -> _FileInformation:
    info = _FileInformation()
    _wincheck(_k.GetFileInformationByHandle(handle, ct.byref(info)), "handle inspection")
    if info.attributes & _REPARSE_ATTRIBUTE:
        _fail("UNSUPPORTED_PATH_TYPE", "Reparse points are prohibited.")
    if bool(info.attributes & _DIRECTORY_ATTRIBUTE) != directory:
        _fail("UNSUPPORTED_PATH_TYPE", "The object has the wrong filesystem type.")
    if not directory and info.links != 1:
        _fail("UNSUPPORTED_PATH_TYPE", "Files with multiple hard links are prohibited.")
    return info


def _exact_long_name(handle, name: str) -> None:
    buffer = ct.create_unicode_buffer(512)
    length = _k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
    if len(buffer) <= length < 32768:
        buffer = ct.create_unicode_buffer(length + 1)
        length = _k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
    if not 0 < length < len(buffer):
        _fail("FILE_ACCESS_FAILED", "Could not verify the canonical handle path.")
    actual = buffer.value.rsplit("\\", 1)[-1]
    if actual.casefold() != name.casefold():
        _fail("UNSUPPORTED_PATH_TYPE", "Short-name aliases and redirected names are prohibited.")


@contextmanager
def _open(parent, name: str, *, directory=False, create=False, writable=False, movable=False):
    encoded = name.encode("utf-16-le", errors="surrogatepass")
    name_buffer = ct.create_string_buffer(encoded + b"\0\0")
    name_value = _UnicodeString(len(encoded), len(encoded) + 2, ct.addressof(name_buffer))
    attributes = _ObjectAttributes(
        ct.sizeof(_ObjectAttributes), parent, ct.pointer(name_value), 0x1040, None, None,
    )
    state = _IoStatus()
    handle = w.HANDLE()
    access = _DIR_ACCESS if directory else _FILE_ACCESS
    if writable:
        access |= _WRITE_DATA | _READ_CONTROL
    if movable:
        access |= _DELETE | _READ_CONTROL
    options = (_DIRECTORY_OPTION if directory else _FILE_OPTION) | 0x20 | 0x00200000
    share = _DIRECTORY_SHARE if directory else _READ_SHARE
    _status(_n.NtCreateFile(
        ct.byref(handle), access, ct.byref(attributes), ct.byref(state), None, 0,
        share, 2 if create else 1, options, None, 0,
    ))
    try:
        info = _info(handle, directory=directory)
        _exact_long_name(handle, name)
        yield handle, info
    finally:
        _k.CloseHandle(handle)


@contextmanager
def _drive(path: str):
    if os.name != "nt" or _k.GetDriveTypeW(path) != 3:
        _fail("UNSUPPORTED_PATH_TYPE", "A local, fixed NTFS drive on Windows is required.")
    handle = _k.CreateFileW(
        "\\\\?\\" + path, _DIR_ACCESS, _DIRECTORY_SHARE, None, 3, 0x02200000, None,
    )
    if handle == ct.c_void_p(-1).value:
        _fail("FILE_ACCESS_FAILED", "Could not pin the Windows volume root.")
    try:
        filesystem = ct.create_unicode_buffer(32)
        _wincheck(_k.GetVolumeInformationByHandleW(
            handle, None, 0, None, None, None, filesystem, len(filesystem),
        ), "volume inspection")
        if filesystem.value != "NTFS":
            _fail("UNSUPPORTED_PATH_TYPE", "Only a local NTFS volume is supported.")
        _info(handle, directory=True)
        yield handle
    finally:
        _k.CloseHandle(handle)


def _entries_with_attrs(handle) -> list[tuple[str, int]]:
    items: list[tuple[str, int]] = []
    state = _IoStatus()
    buffer = ct.create_string_buffer(65536)
    restart = True
    while True:
        # FileDirectoryInformation (class 1): fixed 64-byte header with FileAttributes at [56:60] and FileNameLength at [60:64]
        status = _n.NtQueryDirectoryFile(
            handle, None, None, None, ct.byref(state), buffer, len(buffer), 1, 0, None, restart,
        )
        if status & 0xFFFFFFFF == _NO_MORE_FILES:
            break
        _status(status)
        restart = False
        offset = 0
        data = buffer.raw
        while offset < state.Information:
            next_record = int.from_bytes(data[offset:offset + 4], "little")
            attrs = int.from_bytes(data[offset + 56:offset + 60], "little")
            size = int.from_bytes(data[offset + 60:offset + 64], "little")
            name = data[offset + 64:offset + 64 + size].decode("utf-16-le", "surrogatepass")
            if name not in (".", ".."):
                items.append((name, attrs))
                if len(items) > _MAX_DIRECTORY:
                    _fail("RESOURCE_BUDGET_EXCEEDED", "Directory enumeration limit exceeded.")
            if next_record == 0:
                break
            offset += next_record
    return sorted(items, key=lambda pair: (pair[0].casefold(), pair[0]))


def _entries(handle) -> list[str]:
    return [name for name, _attrs in _entries_with_attrs(handle)]


def _detect_binary_hint(sample: bytes) -> str:
    if sample.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32 BOM detected"
    if sample.startswith(b"\xff\xfe"):
        return "utf-16-le BOM detected"
    if sample.startswith(b"\xfe\xff"):
        return "utf-16-be BOM detected"
    if b"\x00" in sample:
        return "binary NUL bytes detected; retry with lossy_utf8=True or inspect metadata"
    return "non-UTF-8 byte sequence detected; retry with lossy_utf8=True for lossy preview"


def _read_exact(handle, size: int) -> bytes:
    if size == 0:
        return b""
    buffer = ct.create_string_buffer(size)
    actual = w.DWORD()
    _wincheck(_k.ReadFile(handle, buffer, size, ct.byref(actual), None), "file read")
    if actual.value != size:
        _fail("VERSION_CONFLICT", "The file changed while it was being read.")
    return buffer.raw


def _data(handle, info: _FileInformation) -> bytes:
    if info.size > _MAX_FILE:
        _fail("RESOURCE_BUDGET_EXCEEDED", "File exceeds the supported read limit.")
    raw = _read_exact(handle, info.size)
    after = _info(handle, directory=False)
    if after.size != info.size:
        _fail("VERSION_CONFLICT", "The file changed while it was being read.")
    return raw


def _read_window_and_hash(
    handle,
    info: _FileInformation,
    offset: int,
    limit: int,
    *,
    lossy_utf8: bool = False,
) -> dict:
    if info.size > _MAX_READ_FILE:
        _fail(
            "RESOURCE_BUDGET_EXCEEDED",
            "File exceeds the 32 MiB inspection limit.",
            {"size": info.size, "max_bytes": _MAX_READ_FILE},
        )
    hasher = hashlib.sha256()
    if info.size == 0:
        _info(handle, directory=False)
        return {
            "content": "",
            "hash": hasher.hexdigest(),
            "size": 0,
            "total_chars": 0,
            "encoding": "utf-8-lossy" if lossy_utf8 else "utf-8",
            "editable": not lossy_utf8,
        }
    decoder = codecs.getincrementaldecoder("utf-8")("replace" if lossy_utf8 else "strict")
    remaining = info.size
    chunk_size = 256 * 1024
    start = offset
    end = offset + limit
    total_chars = 0
    out_chunks: list[str] = []
    first_chunk = b""
    while remaining > 0:
        to_read = min(remaining, chunk_size)
        chunk = _read_exact(handle, to_read)
        if not first_chunk:
            first_chunk = chunk[:4096]
        if not lossy_utf8 and b"\x00" in chunk:
            hint = _detect_binary_hint(first_chunk)
            _fail(
                "UNSUPPORTED_FILE_ENCODING",
                f"Only UTF-8 text files can be read cleanly ({hint}).",
                {"hint": hint, "size": info.size},
            )
        hasher.update(chunk)
        remaining -= to_read
        try:
            piece = decoder.decode(chunk, final=(remaining == 0))
        except UnicodeError:
            hint = _detect_binary_hint(first_chunk)
            _fail(
                "UNSUPPORTED_FILE_ENCODING",
                f"Only UTF-8 text files can be read cleanly ({hint}).",
                {"hint": hint, "size": info.size},
            )
        pos = total_chars
        total_chars += len(piece)
        if total_chars > start and pos < end:
            lo = max(0, start - pos)
            hi = max(0, end - pos)
            out_chunks.append(piece[lo:hi])
    after = _info(handle, directory=False)
    if after.size != info.size:
        _fail("VERSION_CONFLICT", "The file changed while it was being read.")
    return {
        "content": "".join(out_chunks),
        "hash": hasher.hexdigest(),
        "size": info.size,
        "total_chars": total_chars,
        "encoding": "utf-8-lossy" if lossy_utf8 else "utf-8",
        "editable": not lossy_utf8,
    }


def _hash_and_header(handle, info: _FileInformation, *, header_bytes: int = 64) -> tuple[str | None, bytes]:
    if info.size > _MAX_READ_FILE:
        header = _read_exact(handle, min(info.size, header_bytes))
        _info(handle, directory=False)
        return None, header
    hasher = hashlib.sha256()
    remaining = info.size
    chunk_size = 256 * 1024
    header = b""
    while remaining > 0:
        to_read = min(remaining, chunk_size)
        chunk = _read_exact(handle, to_read)
        if len(header) < header_bytes:
            header += chunk[: header_bytes - len(header)]
        hasher.update(chunk)
        remaining -= to_read
    after = _info(handle, directory=False)
    if after.size != info.size:
        _fail("VERSION_CONFLICT", "The file changed while it was being read.")
    return hasher.hexdigest(), header


def _write_data(handle, data: bytes):
    actual = w.DWORD()
    _wincheck(_k.WriteFile(handle, data, len(data), ct.byref(actual), None), "file write")
    if actual.value != len(data):
        _fail("FILE_ACCESS_FAILED", "Incomplete file write.")
    _wincheck(_k.FlushFileBuffers(handle), "file flush")


def _remove_temporary(handle):
    disposition = w.BOOL(True)
    _wincheck(_k.SetFileInformationByHandle(
        handle, 4, ct.byref(disposition), ct.sizeof(disposition),
    ), "temporary file cleanup")


def _descriptor(handle) -> bytes:
    pointer = ct.c_void_p()
    error = _a.GetSecurityInfo(handle, 1, 7, None, None, None, None, ct.byref(pointer))
    if error:
        _fail("UNSUPPORTED_PATH_TYPE", "Could not verify the file owner and access control list.")
    try:
        return ct.string_at(pointer, _a.GetSecurityDescriptorLength(pointer))
    finally:
        _k.LocalFree(pointer)


def _check_replace_metadata(previous, staged):
    info = _info(previous, directory=False)
    # Restricted flags include read-only, system, sparse, compressed, offline and EFS.
    if info.attributes & (0x1 | 0x4 | 0x200 | 0x800 | 0x1000 | 0x4000):
        _fail("UNSUPPORTED_PATH_TYPE", "Replacing files with special NTFS attributes is unsupported.")
    streams = ct.create_string_buffer(65536)
    _wincheck(_k.GetFileInformationByHandleEx(previous, 7, streams, len(streams)), "stream inspection")
    next_entry = int.from_bytes(streams.raw[:4], "little")
    stream_size = int.from_bytes(streams.raw[4:8], "little")
    stream_name = streams.raw[24:24 + stream_size].decode("utf-16-le")
    if next_entry or stream_name != "::$DATA":
        _fail("UNSUPPORTED_PATH_TYPE", "Replacing files with alternate data streams is unsupported.")
    if _descriptor(previous) != _descriptor(staged):
        _fail("UNSUPPORTED_PATH_TYPE", "Replacing the file would change its owner or access control list.")


def _rename(handle, destination, name: str):
    encoded = name.encode("utf-16-le", errors="surrogatepass")
    size = ct.sizeof(_RenameInfo) + len(encoded)
    buffer = ct.create_string_buffer(size)
    rename = _RenameInfo.from_buffer(buffer)
    rename.Flags = 0
    rename.RootDirectory = destination.value if isinstance(destination, w.HANDLE) else destination
    rename.FileNameLength = len(encoded)
    ct.memmove(ct.addressof(buffer) + _RenameInfo.FileName.offset, encoded, len(encoded))
    _status(_n.NtSetInformationFile(handle, ct.byref(_IoStatus()), buffer, size, 65))


class ProjectFiles:
    """All authority is anchored to the registered directory identity."""

    def __init__(self, root: str | Path, root_identity: str | None = None):
        spelling = str(root).replace("/", "\\")
        if not re.match(r"^[a-zA-Z]:\\[^\\]", spelling):
            _fail("UNSUPPORTED_PATH_TYPE", "Select a fully qualified local project directory.")
        self.root = Path(spelling)
        self._drive = spelling[:3]
        self._root_parts = spelling[3:].rstrip("\\").split("\\")
        for part in self._root_parts:
            _part(part)
        self.root_identity = root_identity
        if root_identity is None:
            with self._root() as (_, info):
                self.root_identity = info.identity

    @classmethod
    def identity(cls, root: str | Path) -> str:
        return cls(root).root_identity

    @contextmanager
    def _root(self):
        with ExitStack() as stack:
            handle = stack.enter_context(_drive(self._drive))
            for part in self._root_parts:
                handle, info = stack.enter_context(_open(handle, part, directory=True))
            if self.root_identity is not None and self.root_identity != info.identity:
                _fail("PROJECT_ROOT_CHANGED", "The directory identity differs from the approved grant.")
            yield handle, info

    @contextmanager
    def _directory(self, parts: list[str]):
        with ExitStack() as stack:
            handle, _ = stack.enter_context(self._root())
            for part in parts:
                handle, _ = stack.enter_context(_open(handle, part, directory=True))
            yield handle

    def ensure_directory(self, path: str) -> str:
        """Create a safe relative directory path using handle-relative NTFS checks."""
        parts = _parts(path, directory=True)
        with ExitStack() as stack:
            handle, _ = stack.enter_context(self._root())
            for part in parts:
                try:
                    handle, _ = stack.enter_context(_open(handle, part, directory=True, create=True))
                except FileBoundaryError as exc:
                    if exc.code != "VERSION_CONFLICT":
                        raise
                    handle, _ = stack.enter_context(_open(handle, part, directory=True))
        return "/".join(parts)

    @staticmethod
    def _children(handle):
        for name, attrs in _entries_with_attrs(handle):
            if attrs & _REPARSE_ATTRIBUTE:
                continue
            try:
                _part(name)
            except FileBoundaryError:
                continue
            is_dir = bool(attrs & _DIRECTORY_ATTRIBUTE)
            try:
                with _open(handle, name, directory=is_dir) as (_, info):
                    if is_dir:
                        yield {"name": name, "type": "directory"}
                    else:
                        yield {"name": name, "type": "file", "size": info.size}
            except FileBoundaryError:
                continue

    def list(
        self,
        path: str = ".",
        cursor: int = 0,
        limit: int = 50,
        *,
        recursive: bool = False,
        max_depth: int = 3,
        exclude_generated: bool = True,
    ) -> dict:
        _window(cursor, limit, 200)
        if not isinstance(recursive, bool) or not isinstance(exclude_generated, bool):
            _fail("INVALID_ARGUMENT", "Boolean flag expected.")
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 8:
            _fail("INVALID_ARGUMENT", "max_depth must be between 1 and 8.")
        prefix = _parts(path, directory=True)
        if not recursive:
            with self._directory(prefix) as handle:
                entries = list(self._children(handle))
            return {
                "entries": entries[cursor:cursor + limit],
                "next_cursor": cursor + limit if cursor + limit < len(entries) else None,
            }
        entries: list[dict] = []
        queue: deque[tuple[list[str], int]] = deque([(prefix, 1)])
        capped = False
        while queue and not capped:
            current, depth = queue.popleft()
            with self._directory(current) as handle:
                children = sorted(self._children(handle), key=lambda item: item["name"].casefold())
            for item in children:
                if exclude_generated and item["type"] == "directory" and item["name"].casefold() in _GENERATED_DIRS:
                    continue
                target = current + [item["name"]]
                entries.append({
                    **item,
                    "name": "/".join(target[len(prefix):]),
                    "path": "/".join(target),
                    "depth": depth,
                })
                if len(entries) >= _MAX_DIRECTORY:
                    capped = True
                    break
                if item["type"] == "directory" and depth < max_depth and len(target) < 64:
                    queue.append((target, depth + 1))
        next_cursor = cursor + limit
        return {
            "entries": entries[cursor:next_cursor],
            "next_cursor": next_cursor if next_cursor < len(entries) else None,
            "recursive": True,
            "scan_truncated": capped,
        }

    def read(self, path: str, offset: int = 0, limit: int = 32768, *, lossy_utf8: bool = False) -> dict:
        _window(offset, limit, 65536)
        if not isinstance(lossy_utf8, bool):
            _fail("INVALID_ARGUMENT", "lossy_utf8 must be a boolean.")
        parts = _parts(path)
        with self._directory(parts[:-1]) as handle, _open(handle, parts[-1]) as (child, info):
            result = _read_window_and_hash(child, info, offset, limit, lossy_utf8=lossy_utf8)
        end = offset + limit
        total_chars = result["total_chars"]
        return {
            "path": "/".join(parts), "content": result["content"], "hash": result["hash"],
            "encoding": result["encoding"], "editable": result["editable"],
            "size": result["size"], "offset": offset,
            "next_offset": end if end < total_chars else None, "truncated": end < total_chars,
        }

    def read_snapshot_file(self, path: str, *, max_bytes: int = 65_536) -> dict:
        """Read one whole UTF-8 snapshot file through a single verified handle, capped at 256 KiB."""
        if type(max_bytes) is not int or not 1 <= max_bytes <= 256 * 1024:
            _fail("INVALID_ARGUMENT", "Snapshot file size limit must be between 1 and 262144 bytes.")
        parts = _parts(path)
        rel_path = "/".join(parts)
        with self._directory(parts[:-1]) as handle, _open(handle, parts[-1]) as (child, info):
            if info.size > max_bytes:
                _fail(
                    "RESOURCE_BUDGET_EXCEEDED",
                    f"snapshot file '{rel_path}' size {info.size} bytes exceeds {max_bytes} bytes.",
                    {"path": rel_path, "size": info.size, "max_bytes": max_bytes},
                )
            result = _read_window_and_hash(child, info, 0, max_bytes, lossy_utf8=False)
        return {
            "path": rel_path, "content": result["content"], "hash": result["hash"],
            "encoding": result["encoding"], "editable": result["editable"],
            "size": result["size"], "offset": 0, "next_offset": None, "truncated": False,
        }

    def make_snapshot_directory(self, path: str) -> None:
        """Create one relative directory in a broker-owned snapshot."""
        parts = _parts(path)
        with self._directory(parts[:-1]) as parent, _open(parent, parts[-1], directory=True, create=True):
            pass

    def search(
        self,
        query: str,
        path: str = ".",
        cursor: int = 0,
        limit: int = 40,
        *,
        exclude_generated: bool = True,
        case_sensitive: bool = False,
    ) -> dict:
        _window(cursor, limit, 200)
        if not isinstance(query, str) or not 1 <= len(query) <= 200:
            _fail("INVALID_ARGUMENT", "Expected between one and 200 characters.")
        if not isinstance(exclude_generated, bool) or not isinstance(case_sensitive, bool):
            _fail("INVALID_ARGUMENT", "Boolean flag expected.")
        prefix = _parts(path, directory=True)
        pending = [prefix]
        matches = []
        scanned = 0
        files_scanned = 0
        scanned_bytes = 0
        needle = query if case_sensitive else query.casefold()
        capped = False
        while pending and not capped:
            relative = pending.pop()
            with self._directory(relative) as handle:
                for item in self._children(handle):
                    scanned += 1
                    if scanned > _MAX_SCAN or len(matches) >= _MAX_HITS:
                        capped = True
                        break
                    name = item["name"]
                    target = relative + [name]
                    if item["type"] == "directory":
                        if exclude_generated and name.casefold() in _GENERATED_DIRS:
                            continue
                        if len(target) < 64:
                            pending.append(target)
                        continue
                    if item["size"] > _MAX_FILE or Path(name).suffix.casefold() in _BINARY_SEARCH_EXTS:
                        continue
                    try:
                        with _open(handle, name) as (child, info):
                            if info.size > _MAX_FILE:
                                continue
                            if scanned_bytes + info.size > _MAX_SCAN_BYTES:
                                capped = True
                                break
                            raw = _data(child, info)
                            if b"\x00" in raw:
                                continue
                            files_scanned += 1
                            scanned_bytes += info.size
                            content = raw.decode("utf-8")
                    except (FileBoundaryError, UnicodeError):
                        continue
                    for line_number, line in enumerate(content.splitlines(), 1):
                        haystack = line if case_sensitive else line.casefold()
                        if needle in haystack:
                            matches.append({
                                "path": "/".join(target), "line": line_number, "text": line[:400],
                            })
                            if len(matches) >= _MAX_HITS:
                                capped = True
                                break
        next_cursor = cursor + limit
        return {
            "matches": matches[cursor:next_cursor],
            "scan_truncated": capped,
            "files_scanned": files_scanned,
            "bytes_scanned": scanned_bytes,
            "next_cursor": next_cursor if next_cursor < len(matches) else None,
        }

    def view(self, path: str) -> dict:
        parts = _parts(path)
        extension = Path(parts[-1]).suffix.casefold()
        if extension not in {".png", ".jpg", ".jpeg"}:
            try:
                return self.read(path, limit=8192)
            except FileBoundaryError as exc:
                if exc.code != "UNSUPPORTED_FILE_ENCODING":
                    raise
                with self._directory(parts[:-1]) as handle, _open(handle, parts[-1]) as (child, info):
                    file_hash, header = _hash_and_header(child, info)
                return {
                    "path": "/".join(parts),
                    "kind": "binary",
                    "size": info.size,
                    "hash": file_hash,
                    "encoding": "binary",
                    "previewable": False,
                    "editable": False,
                    "header_hex": header.hex(),
                    "hint": exc.details.get("hint", "Binary or non-UTF-8 file."),
                }
        with self._directory(parts[:-1]) as handle, _open(handle, parts[-1]) as (child, info):
            if info.size > 256 * 1024:
                _fail("RESOURCE_BUDGET_EXCEEDED", "Image preview exceeds 256 KiB.")
            raw = _data(child, info)
        png = extension == ".png"
        if not raw.startswith(b"\x89PNG\r\n\x1a\n" if png else b"\xff\xd8\xff"):
            _fail("UNSUPPORTED_FILE_ENCODING", "The file does not match the expected image format.")
        return {
            "path": "/".join(parts), "hash": _sha(raw), "size": len(raw),
            "content_type": "image/png" if png else "image/jpeg",
            "encoding": "base64", "content": base64.b64encode(raw).decode("ascii"),
        }

    def binary_evidence(self, path: str) -> dict:
        """Return bounded binary evidence to the trusted job supervisor."""
        parts = _parts(path)
        with self._directory(parts[:-1]) as parent, _open(parent, parts[-1]) as (handle, info):
            raw = _data(handle, info)
        return {"path": "/".join(parts), "sha256": _sha(raw), "size": len(raw), "header": raw[:12]}

    @staticmethod
    def _guard(parent, name: str, expected_hash: str):
        @contextmanager
        def guard():
            with ExitStack() as stack:
                try:
                    handle, info = stack.enter_context(_open(parent, name, movable=True))
                except FileBoundaryError as exc:
                    if exc.code == "FILE_NOT_FOUND":
                        _fail("VERSION_CONFLICT", "The file no longer exists.")
                    raise
                if _sha(_data(handle, info)) != expected_hash:
                    _fail("VERSION_CONFLICT", "The expected hash differs from the file on disk.")
                yield handle
        return guard()

    @staticmethod
    @contextmanager
    def _stage(parent, raw: bytes):
        temp_name = ".edge-bridge-tmp-" + uuid4().hex
        with _open(parent, temp_name, create=True, writable=True, movable=True) as (handle, _):
            state = {"installed": False, "name": temp_name}
            try:
                _write_data(handle, raw)
                yield handle, state
            finally:
                if not state["installed"]:
                    _remove_temporary(handle)

    def write(self, path: str, content: str, expected_hash: str | None) -> dict:
        parts = _parts(path)
        _expected(expected_hash)
        raw = _utf8(content)
        if expected_hash is not None:
            result = self.patch([{"path": path, "content": content, "expected_hash": expected_hash}])
            return {
                "path": "/".join(parts), "hash": _sha(raw), "size": len(raw),
                "recovery_id": result["patch_id"],
            }
        with ExitStack() as stack:
            parent = stack.enter_context(self._directory(parts[:-1]))
            staged, state = stack.enter_context(self._stage(parent, raw))
            _rename(staged, parent, parts[-1])
            state["installed"] = True
        return {"path": "/".join(parts), "hash": _sha(raw), "size": len(raw)}

    @contextmanager
    def _private(self, *, create: bool = True):
        with self._root() as (root, _):
            with ExitStack() as stack:
                try:
                    directory, _ = stack.enter_context(_open(root, _PRIVATE, directory=True, create=create))
                except FileBoundaryError as exc:
                    if not create or exc.code != "VERSION_CONFLICT":
                        raise
                    directory, _ = stack.enter_context(_open(root, _PRIVATE, directory=True))
                yield directory

    @staticmethod
    def _journal(parent, name: str, payload: dict):
        with _open(parent, name, writable=True, create=True) as (handle, _):
            _write_data(handle, json.dumps(payload, ensure_ascii=True).encode("ascii"))

    @staticmethod
    def _require_absent(parent, name: str):
        try:
            with _open(parent, name):
                _fail("VERSION_CONFLICT", "The destination already exists.")
        except FileBoundaryError as exc:
            if exc.code != "FILE_NOT_FOUND":
                raise

    def patch(self, edits: list[dict]) -> dict:
        if not isinstance(edits, list) or not 1 <= len(edits) <= 20:
            _fail("INVALID_ARGUMENT", "A patch requires one to 20 complete-text replacements.")
        prepared = []
        for edit in edits:
            if not isinstance(edit, dict) or edit.keys() != {"path", "content", "expected_hash"}:
                _fail("INVALID_ARGUMENT", "Each patch edit needs path, content, and expected_hash.")
            parts = _parts(edit["path"])
            raw = _utf8(edit["content"])
            _expected(edit["expected_hash"])
            prepared.append((parts, raw, edit["expected_hash"]))
        names = ["/".join(parts).casefold() for parts, _, _ in prepared]
        if len(set(names)) != len(names) or sum(len(raw) for _, raw, _ in prepared) > _MAX_FILE:
            _fail("INVALID_ARGUMENT", "Patch paths must be unique and the total size bounded.")
        with ExitStack() as stack:
            staged_edits = []
            for parts, raw, expected_hash in prepared:
                parent = stack.enter_context(self._directory(parts[:-1]))
                previous = None
                if expected_hash is not None:
                    previous = stack.enter_context(self._guard(parent, parts[-1], expected_hash))
                else:
                    self._require_absent(parent, parts[-1])
                staged, state = stack.enter_context(self._stage(parent, raw))
                if previous is not None:
                    _check_replace_metadata(previous, staged)
                staged_edits.append((parent, parts[-1], staged, state, previous))
            private = stack.enter_context(self._private())
            receipt = uuid4().hex
            plan = [
                {
                    "path": "/".join(parts), "before": expected_hash, "after": _sha(raw),
                    "backup": f"{receipt}.{index}.previous" if expected_hash is not None else None,
                    "before_id": _info(previous, directory=False).identity if previous is not None else None,
                    "staged": state["name"],
                    "after_id": _info(staged, directory=False).identity,
                }
                for index, ((parts, raw, expected_hash), (_, _, staged, state, previous))
                in enumerate(zip(prepared, staged_edits, strict=True))
            ]
            self._journal(private, f"{receipt}.plan.json", {
                "schema": 2, "root_identity": self.root_identity, "patch": plan,
            })
            applied = []
            try:
                for (parent, name, staged, state, previous), entry in zip(staged_edits, plan):
                    # NTFS refuses one-step replacement while an existing destination is
                    # pinned against DELETE sharing. Preserve the pinned original and
                    # publish without replace, so a concurrent creator always wins.
                    if previous is not None:
                        _rename(previous, private, entry["backup"])
                    try:
                        _rename(staged, parent, name)
                    except FileBoundaryError:
                        if previous is not None:
                            try:
                                _rename(previous, parent, name)
                            except FileBoundaryError:
                                pass  # The original remains linked in the recovery directory.
                        raise
                    state["installed"] = True
                    applied.append({key: entry[key] for key in ("path", "before", "after", "backup")})
            except FileBoundaryError as exc:
                self._journal(private, f"{receipt}.result.json", {"status": "needs_review", "applied": applied})
                _fail(exc.code, f"{exc} Review patch recovery journal {receipt}.")
            self._journal(private, f"{receipt}.result.json", {"status": "applied", "applied": applied})
        return {"patch_id": receipt, "applied": applied}

    @staticmethod
    def _read_journal(parent, name: str) -> dict:
        with _open(parent, name) as (handle, info):
            data = _data(handle, info)
        try:
            value = json.loads(data)
        except (UnicodeError, ValueError):
            _fail("RECOVERY_JOURNAL_INVALID", "The recovery journal is incomplete or invalid.")
        if not isinstance(value, dict):
            _fail("RECOVERY_JOURNAL_INVALID", "Expected a recovery journal object.")
        return value

    def _recovery_plan(self, journal: dict, receipt_id: str) -> list[dict]:
        if journal.get("schema") != 2 or journal.get("root_identity") != self.root_identity:
            _fail("RECOVERY_JOURNAL_INVALID", "Select a version 2 plan for this exact project root.")
        edits = journal.get("patch")
        if not isinstance(edits, list) or not 1 <= len(edits) <= 20:
            _fail("RECOVERY_JOURNAL_INVALID", "The recovery plan has an invalid edit count.")
        paths = set()
        for index, edit in enumerate(edits):
            if not isinstance(edit, dict) or set(edit) != {
                "path", "before", "after", "backup", "before_id", "staged", "after_id",
            }:
                _fail("RECOVERY_JOURNAL_INVALID", "The recovery plan has an invalid entry.")
            path = "/".join(_parts(edit["path"]))
            if path != edit["path"] or path.casefold() in paths:
                _fail("RECOVERY_JOURNAL_INVALID", "The recovery plan must use unique canonical paths.")
            paths.add(path.casefold())
            before = edit["before"]
            if before is None:
                if edit["backup"] is not None or edit["before_id"] is not None:
                    _fail("RECOVERY_JOURNAL_INVALID", "A create entry cannot have an original backup.")
            elif (
                not isinstance(before, str) or not _HASH.fullmatch(before)
                or edit["backup"] != f"{receipt_id}.{index}.previous"
                or not isinstance(edit["before_id"], str) or not _FILE_ID.fullmatch(edit["before_id"])
            ):
                _fail("RECOVERY_JOURNAL_INVALID", "The original backup metadata is invalid.")
            if any(not isinstance(edit[key], str) or not pattern.fullmatch(edit[key])
                   for key, pattern in (("after", _HASH), ("after_id", _FILE_ID), ("staged", _STAGE_NAME))):
                _fail("RECOVERY_JOURNAL_INVALID", "The staged file metadata is invalid.")
        return edits

    @staticmethod
    @contextmanager
    def _recovery_object(parent, name: str | None, *, movable: bool = False):
        if name is None:
            yield None, "not_applicable"
            return
        with ExitStack() as stack:
            try:
                handle, info = stack.enter_context(_open(parent, name, movable=movable))
                observed = (info.identity, _sha(_data(handle, info)))
            except FileBoundaryError as exc:
                yield None, "missing" if exc.code == "FILE_NOT_FOUND" else "unverified"
                return
            yield handle, observed

    def _recover_patch_entry(self, private, edit: dict, *, restore: bool, confirmed: bool) -> dict:
        parts = _parts(edit["path"])
        before = (edit["before_id"], edit["before"])
        after = (edit["after_id"], edit["after"])
        with (
            self._directory(parts[:-1]) as parent,
            self._recovery_object(parent, parts[-1]) as (_, current),
            self._recovery_object(parent, edit["staged"]) as (_, staged),
            self._recovery_object(private, edit["backup"], movable=restore) as (backup_handle, backup),
        ):
            result = {
                "path": edit["path"],
                "backup": "verified" if backup == before else ("mismatch" if isinstance(backup, tuple) else backup),
                "staged": "verified" if staged == after else ("mismatch" if isinstance(staged, tuple) else staged),
            }
            if current == before:
                status = "original_intact"
            elif current == after:
                status = "published"
            elif isinstance(current, tuple):
                status = "destination_preserved"
            elif current != "missing":
                status = "destination_unverified"
            elif confirmed:
                status = "completed_destination_missing"
            elif edit["before"] is None:
                status = "not_published"
            elif backup != before or staged != after:
                status = "restore_unverified"
            elif not restore:
                status = "restore_available"
            else:
                try:
                    _rename(backup_handle, parent, parts[-1])
                except FileBoundaryError as exc:
                    status = "destination_preserved" if exc.code == "VERSION_CONFLICT" else "restore_blocked"
                    result["error"] = exc.code
                else:
                    status = "restored"
                    result["backup"] = "moved_to_original"
            return {**result, "status": status}

    def patch_recovery(self, receipt_id: str, *, restore: bool = False) -> dict:
        """Inspect a patch or explicitly restore a verified displaced original to an empty name."""
        if not isinstance(receipt_id, str) or not _RECOVERY_ID.fullmatch(receipt_id) or type(restore) is not bool:
            _fail("INVALID_ARGUMENT", "Expected a lowercase patch receipt ID and a boolean restore flag.")
        with self._private(create=False) as private:
            journal = self._read_journal(private, f"{receipt_id}.plan.json")
            edits = self._recovery_plan(journal, receipt_id)
            try:
                result = self._read_journal(private, f"{receipt_id}.result.json")
            except FileBoundaryError as exc:
                if exc.code != "FILE_NOT_FOUND":
                    raise
                status, completed = "result_missing", set()
            else:
                status = result.get("status")
                applied = result.get("applied")
                if status not in ("applied", "needs_review") or not isinstance(applied, list) or any(
                    not isinstance(entry, dict) or not isinstance(entry.get("path"), str) for entry in applied
                ):
                    _fail("RECOVERY_JOURNAL_INVALID", "The result journal cannot be verified.")
                completed = {entry["path"] for entry in applied}
            entries = [
                self._recover_patch_entry(private, edit, restore=restore,
                                          confirmed=status == "applied" or edit["path"] in completed)
                for edit in edits
            ]
        return {"patch_id": receipt_id, "journal_status": status, "entries": entries}

    def move(self, source: str, destination: str, expected_hash: str) -> dict:
        first, last = _parts(source), _parts(destination)
        _expected(expected_hash)
        if expected_hash is None:
            _fail("INVALID_ARGUMENT", "A source hash is required.")
        with self._directory(first[:-1]) as parent, _open(parent, first[-1], movable=True) as (
            source_handle, info,
        ), self._directory(last[:-1]) as target:
            if _sha(_data(source_handle, info)) != expected_hash:
                _fail("VERSION_CONFLICT", "The source file changed.")
            _rename(source_handle, target, last[-1])
        return {"source": "/".join(first), "destination": "/".join(last), "hash": expected_hash}

    def delete(self, path: str, expected_hash: str) -> dict:
        parts = _parts(path)
        _expected(expected_hash)
        if expected_hash is None:
            _fail("INVALID_ARGUMENT", "A source hash is required.")
        receipt = uuid4().hex
        with self._directory(parts[:-1]) as parent, _open(parent, parts[-1], movable=True) as (
            handle, info,
        ):
            if _sha(_data(handle, info)) != expected_hash:
                _fail("VERSION_CONFLICT", "The source file changed.")
            with self._private() as private:
                self._journal(private, f"{receipt}.trash.json", {
                    "original": "/".join(parts), "hash": expected_hash, "stored_file": f"{receipt}.trash",
                })
                _rename(handle, private, f"{receipt}.trash")
        return {"path": "/".join(parts), "hash": expected_hash, "trash_id": receipt, "reversible": True}
