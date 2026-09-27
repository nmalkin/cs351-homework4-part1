#!/usr/bin/env python3

import errno
import hashlib
import os
import resource
import stat
import sys
import tempfile

NOBODY_UID: int = 65534
NOBODY_GID: int = 65534

AUTH_PATH: str = "/etc/shadow"
OUTSIDE_PATH: str = "/etc/passwd"

WORK_DIR: str = ""
AUTH_FD: int = -1
STARTUP_DIR_FD: int = -1

_AUTH_DIGEST: bytes = b""
_OUTSIDE_DIGEST: bytes = b""
_STARTUP_DIR_IDENT: tuple[int, int] | None = None
_HANDLES: dict[int, str] = {}


def drop_privileges() -> None:
    # TODO: implement this

    return


def open_handles() -> dict[int, str]:
    """Return the still-open handles from those the program held before dropping privileges, as {fd: description}."""
    live: dict[int, str] = {}
    for fd, desc in _HANDLES.items():
        try:
            os.fstat(fd)
        except OSError:
            continue
        live[fd] = desc
    return live


def _prepare() -> None:
    """Acquire the resources the program needs while it is still root, and record what it will later verify."""
    global WORK_DIR, AUTH_FD, STARTUP_DIR_FD
    global _AUTH_DIGEST, _OUTSIDE_DIGEST, _STARTUP_DIR_IDENT

    WORK_DIR = tempfile.mkdtemp(prefix="program_")
    os.chmod(WORK_DIR, 0o755)

    AUTH_FD = os.open(AUTH_PATH, os.O_RDONLY)
    _AUTH_DIGEST = hashlib.sha256(_read_all(AUTH_FD)).digest()
    _HANDLES[AUTH_FD] = f"open file: {AUTH_PATH}"

    _OUTSIDE_DIGEST = hashlib.sha256(_read_path(OUTSIDE_PATH)).digest()

    STARTUP_DIR_FD = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY)
    info = os.fstat(STARTUP_DIR_FD)
    _STARTUP_DIR_IDENT = (info.st_dev, info.st_ino)
    _HANDLES[STARTUP_DIR_FD] = "open directory: /etc"

    os.setgroups([0])
    os.chdir("/")


def _read_all(fd: int) -> bytes:
    """Read the whole file referred to by fd, from offset zero, without disturbing its file position."""
    chunks: list[bytes] = []
    offset = 0
    while True:
        block = os.pread(fd, 65536, offset)
        if not block:
            break
        chunks.append(block)
        offset += len(block)
    return b"".join(chunks)


def _read_path(path: str) -> bytes:
    """Read the whole file at path, returning empty bytes if it cannot be opened."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return b""
    try:
        return _read_all(fd)
    finally:
        os.close(fd)


def _can_reach_outside() -> bool:
    """Report whether OUTSIDE_PATH's real contents are reachable from the current view and working directory."""
    candidates = [OUTSIDE_PATH, OUTSIDE_PATH.lstrip("/"), "../" * 64 + OUTSIDE_PATH.lstrip("/")]
    for path in candidates:
        if _read_path(path) and hashlib.sha256(_read_path(path)).digest() == _OUTSIDE_DIGEST:
            return True
    return False


def auth_readable_via_handle() -> tuple[bool, str]:
    """Verify the program can still read the authentication file through the handle it opened before dropping privileges."""
    try:
        same = hashlib.sha256(_read_all(AUTH_FD)).digest() == _AUTH_DIGEST
    except OSError:
        return False, f"the handle to {AUTH_PATH} is gone"
    if same:
        return True, f"{AUTH_PATH} still readable through the open handle"
    return False, "the handle no longer yields the expected contents"


def uid_dropped() -> tuple[bool, str]:
    """Report whether all three user ids are non-zero, so a return to uid 0 is not possible."""
    real, eff, saved = os.getresuid()
    if 0 in (real, eff, saved):
        return False, f"a user id is still 0 (real={real}, effective={eff}, saved={saved})"
    return True, f"user ids are real={real}, effective={eff}, saved={saved}"


def gid_dropped() -> tuple[bool, str]:
    """Report whether the primary, effective, saved and supplementary group ids are all free of group 0."""
    real, eff, saved = os.getresgid()
    groups = os.getgroups()
    if 0 in (real, eff, saved):
        return False, f"a group id is still 0 (real={real}, effective={eff}, saved={saved})"
    if 0 in groups:
        return False, f"group 0 is still present in the supplementary groups {groups}"
    return True, f"group ids are real={real}, effective={eff}, saved={saved}; supplementary {groups}"


def auth_unreachable_by_path() -> tuple[bool, str]:
    """Report whether the authentication file can no longer be opened afresh by its path."""
    try:
        fd = os.open(AUTH_PATH, os.O_RDONLY)
    except OSError as exc:
        return True, f"reopening {AUTH_PATH} fails with {errno.errorcode.get(exc.errno, exc.errno)}"
    os.close(fd)
    return False, f"{AUTH_PATH} can be opened again by path"


def filesystem_confined() -> tuple[bool, str]:
    """Report whether the wider filesystem is out of reach from where privilege-dropping left the working directory."""
    if _can_reach_outside():
        return False, f"{OUTSIDE_PATH} is reachable, so the wider filesystem is still in view"
    return True, f"{OUTSIDE_PATH} is not reachable"


def startup_directory_released() -> tuple[bool, str]:
    """Report whether the directory handle opened before dropping privileges no longer offers a way out of the work directory."""
    try:
        info = os.fstat(STARTUP_DIR_FD)
    except OSError:
        return True, "the startup directory handle is closed"
    if (info.st_dev, info.st_ino) != _STARTUP_DIR_IDENT or not stat.S_ISDIR(info.st_mode):
        return True, "the startup directory handle is closed"
    try:
        os.fchdir(STARTUP_DIR_FD)
        for _ in range(64):
            os.chdir("..")
        reachable = _can_reach_outside()
    except OSError:
        reachable = False
    finally:
        try:
            os.chdir("/")
        except OSError:
            pass
    if reachable:
        return False, "the open directory handle leads back out to the wider filesystem"
    return True, "the open directory handle leads nowhere useful"


def rechroot_denied() -> tuple[bool, str]:
    """Report whether a further chroot is refused, as it is for an unprivileged process."""
    try:
        os.chroot(".")
    except OSError as exc:
        return True, f"a further chroot fails with {errno.errorcode.get(exc.errno, exc.errno)}"
    return False, "a further chroot succeeds"


def main() -> int:
    """Set up as root, drop privileges, then report whether the resulting state is locked down and still working."""
    if sys.platform != "linux":
        print(f"this program requires Linux; got {sys.platform!r}", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("this program must be run as root", file=sys.stderr)
        return 2

    _prepare()

    try:
        drop_privileges()
    except Exception as exc:
        print(f"drop_privileges raised {type(exc).__name__}: {exc}")
        if isinstance(exc, PermissionError):
            print("privilege-dropping needed a privilege the process no longer had; a privileged action ran after the user id was dropped, or a required capability is missing")
        return 1

    ok, detail = auth_readable_via_handle()
    print(f"still works : {'yes' if ok else 'no'} ({detail})")
    if not ok:
        return 1

    checks = [
        ("user id", uid_dropped),
        ("group id", gid_dropped),
        ("auth by path", auth_unreachable_by_path),
        ("filesystem", filesystem_confined),
        ("startup handle", startup_directory_released),
        ("re-chroot", rechroot_denied),
    ]
    all_passed = True
    for label, check in checks:
        passed, detail = check()
        all_passed = all_passed and passed
        print(f"{label:>15} : {'ok' if passed else 'fail'} ({detail})")

    print("PASS" if all_passed else "FAIL")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
