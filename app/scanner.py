"""Antivirus scanning with pluggable backends.

The scanner is optional. When disabled, uploads are marked ``skipped`` and the
service behaves exactly as before. This keeps the feature from becoming a hard
dependency for deployments that do not need it -- and, importantly, keeps the
test suite runnable on a machine without ClamAV installed.

Two backends are provided:

``ClamdScanner``
    Talks the INSTREAM protocol to ``clamd`` over TCP or a unix socket.
    Preferred in production: the signature database is loaded once by the
    daemon rather than per scan.

``ClamscanScanner``
    Shells out to the ``clamscan`` binary. Simpler to set up, but loads
    signatures on every invocation (seconds of latency, high memory), so it is
    intended for low-volume or one-shot use.

There is also ``StubScanner`` for tests and for dry runs.
"""

from __future__ import annotations

import logging
import shutil
import socket
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

log = logging.getLogger("host.scanner")

# clamd INSTREAM chunk size. The daemon caps a single chunk at 2 GiB; 64 KiB
# keeps memory flat and matches common client implementations.
_CHUNK = 64 * 1024


class ScanError(Exception):
    """The scanner could not produce a verdict (as opposed to finding malware).

    Callers must distinguish this from an ``infected`` result: a broken scanner
    should not silently mark files clean.
    """


@dataclass
class ScanResult:
    status: str  # clean | infected | error
    detail: str | None = None

    @property
    def is_clean(self) -> bool:
        return self.status == "clean"


class Scanner(Protocol):
    name: str

    def scan(self, path: Path) -> ScanResult: ...

    def available(self) -> bool: ...


class StubScanner:
    """Deterministic scanner for tests and dry runs.

    Matching is by *content* substring rather than filename. This matters:
    blobs are stored content-addressed, so the path handed to the scanner is
    the SHA-256 hash and never contains the original name. A filename-based
    stub would silently never match anything in the real storage layout.

    ``verdicts`` maps a byte-substring to a verdict; ``default`` is returned
    when nothing matches.
    """

    name = "stub"
    # Only read this much per file when probing for markers.
    _PROBE = 1 << 16

    def __init__(self, verdicts: dict[str, str] | None = None, default: str = "clean"):
        self.verdicts = verdicts or {}
        self.default = default
        self.calls: list[Path] = []

    def available(self) -> bool:
        return True

    def scan(self, path: Path) -> ScanResult:
        self.calls.append(path)
        try:
            with path.open("rb") as fp:
                head = fp.read(self._PROBE)
        except OSError as exc:
            raise ScanError(f"stub cannot read {path}: {exc}") from exc

        for needle, verdict in self.verdicts.items():
            if needle.encode() in head:
                return ScanResult(verdict, f"stub matched {needle!r}")
        return ScanResult(self.default, None)


class ClamdScanner:
    """Send the file to a running clamd over INSTREAM.

    Protocol: send ``zINSTREAM\\0``, then length-prefixed chunks, then a
    zero-length chunk to signal EOF. clamd replies with a single line such as
    ``stream: OK`` or ``stream: Eicar-Signature FOUND``.

    A soft timeout is essential: a wedged daemon must not hang the upload path.
    """

    name = "clamd"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
        unix_socket: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.unix_socket = unix_socket
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        if self.unix_socket:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.unix_socket)
            return s
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    def available(self) -> bool:
        try:
            with self._connect() as s:
                s.sendall(b"zPING\0")
                return s.recv(64).strip().upper() == b"PONG"
        except (OSError, socket.timeout):
            return False

    def scan(self, path: Path) -> ScanResult:
        try:
            with self._connect() as s:
                s.sendall(b"zINSTREAM\0")
                with path.open("rb") as fp:
                    while True:
                        chunk = fp.read(_CHUNK)
                        if not chunk:
                            break
                        # Length prefix is a big-endian uint32 per chunk.
                        s.sendall(struct.pack("!I", len(chunk)) + chunk)
                    s.sendall(struct.pack("!I", 0))

                reply = b""
                while not reply.endswith(b"\0") and b"\n" not in reply:
                    part = s.recv(4096)
                    if not part:
                        break
                    reply += part
        except (OSError, socket.timeout) as exc:
            raise ScanError(f"clamd unreachable: {exc}") from exc

        text = reply.decode("utf-8", "replace").strip().strip("\0").strip()
        if not text:
            raise ScanError("clamd returned an empty response")

        # Expected forms: "stream: OK", "stream: <Signature> FOUND",
        # or an error such as "INSTREAM size limit exceeded. ERROR".
        body = text.split(":", 1)[1].strip() if ":" in text else text

        if body.upper().endswith("OK"):
            return ScanResult("clean", None)
        if body.upper().endswith("FOUND"):
            signature = body[: -len("FOUND")].strip()
            return ScanResult("infected", signature or "unknown")
        raise ScanError(f"unexpected clamd response: {text!r}")


class ClamscanScanner:
    """Invoke the ``clamscan`` binary once per file.

    Exit codes: 0 = clean, 1 = infected, 2 = error. Signature loading makes
    each call cost seconds and hundreds of MB, so this backend suits only
    low-volume deployments.
    """

    name = "clamscan"

    def __init__(self, binary: str = "clamscan", timeout: float = 120.0) -> None:
        self.binary = binary
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def scan(self, path: Path) -> ScanResult:
        try:
            proc = subprocess.run(
                [self.binary, "--no-summary", "--infected", str(path)],
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ScanError(f"{self.binary} not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise ScanError(f"scan timed out after {self.timeout}s") from exc

        if proc.returncode == 0:
            return ScanResult("clean", None)
        if proc.returncode == 1:
            text = proc.stdout.decode("utf-8", "replace").strip()
            # Output form: /path/to/file: SignatureName FOUND
            signature = text.rsplit(":", 1)[-1].replace("FOUND", "").strip()
            return ScanResult("infected", signature or "unknown")
        raise ScanError(
            f"clamscan exit {proc.returncode}: "
            f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}"
        )


def build_scanner() -> Scanner | None:
    """Construct the scanner named in settings, or None when disabled.

    Falls back to None (rather than raising) when the configured backend is
    not installed, so a misconfigured deployment degrades to "scanning off"
    instead of failing to boot. The condition is logged loudly.
    """
    from .config import settings

    backend = (settings.av_backend or "none").lower()
    if backend in ("none", "off", "disabled", ""):
        return None

    if backend == "clamd":
        scanner: Scanner = ClamdScanner(
            host=settings.clamd_host,
            port=settings.clamd_port,
            unix_socket=settings.clamd_socket or None,
            timeout=settings.av_timeout,
        )
    elif backend == "clamscan":
        scanner = ClamscanScanner(
            binary=settings.clamscan_path, timeout=settings.av_timeout
        )
    elif backend == "stub":
        # Explicitly opt-in only; never selected implicitly, so a stub can
        # never be mistaken for real protection in production.
        #
        # The stub is useless without markers to match: built with an empty
        # verdict map it returns `default` for every file, which makes
        # AV_BACKEND=stub behave identically to AV_BACKEND=none while
        # reporting itself as active. Seed it from settings so an operator can
        # exercise the whole gate end to end.
        markers = [m.strip() for m in (settings.av_stub_markers or "").split(",")]
        verdicts = {m: "infected" for m in markers if m}
        scanner = StubScanner(verdicts)
        if verdicts:
            log.warning(
                "AV_BACKEND=stub is a TEST double, not malware protection; "
                "flagging content containing: %s",
                ", ".join(sorted(verdicts)),
            )
        else:
            log.warning(
                "AV_BACKEND=stub with no AV_STUB_MARKERS configured; "
                "every file will be reported clean. This is not protection."
            )
    else:
        log.error("unknown AV_BACKEND %r; scanning disabled", backend)
        return None

    if not scanner.available():
        log.error(
            "AV_BACKEND=%s but the backend is not reachable; "
            "uploads will NOT be scanned",
            backend,
        )
        return None

    log.info("antivirus scanner active: %s", scanner.name)
    return scanner
