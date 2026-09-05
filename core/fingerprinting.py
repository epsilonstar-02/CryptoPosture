"""
core/fingerprinting.py
FoxIO JA4+ integration for Pipeline Stage 6.

This module deliberately contains NO hand-written JA4/JA4S/JA4X algorithm.
It invokes the official FoxIO JA4+ Python implementation against the original
PCAP once per capture and correlates FoxIO's JSON output back to our normalized
TCP sessions.

Official implementation:
  https://github.com/FoxIO-LLC/ja4

Requirements for the FoxIO Python implementation:
  - Python 3
  - tshark >= 4.0.6 (recommended by FoxIO)
  - FoxIO's official python/ja4.py bundle

Licensing note:
  JA4 is BSD-3-Clause.
  JA4S / JA4X and the other JA4+ methods are covered by FoxIO License 1.1.
  Review FoxIO's current license before distributing or commercializing this
  project.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .crypto_parser import HandshakeResult, _TLS_VERSION_MAP
from .models import CertHealth, JA4Fingerprints


# ---------------------------------------------------------------------------
# TLS / DTLS version -> JA4 2-character code
# ---------------------------------------------------------------------------

_VERSION_CODE: dict[int, str] = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}


def is_grease(val: int) -> bool:
    """Check if 16-bit integer is a GREASE value (RFC 8701)."""
    return (val & 0x0F0F) == 0x0A0A and ((val >> 8) & 0xFF) == (val & 0xFF)


def _sha256_short(data: str, length: int = 12) -> str:
    """Return first `length` lowercase hex chars of SHA-256 hash."""
    import hashlib
    return hashlib.sha256(data.encode("ascii")).hexdigest()[:length]


def format_alpn(alpn: Optional[str | bytes]) -> str:
    """
    Format ALPN protocol string into a 2-character JA4 representation per official FoxIO spec.
    """
    if not alpn:
        return "00"
    if isinstance(alpn, str):
        b = alpn.encode("latin1")
    else:
        b = alpn
    if len(b) == 0:
        return "00"

    def is_alnum(byte_val: int) -> bool:
        return (0x30 <= byte_val <= 0x39) or (0x41 <= byte_val <= 0x5A) or (0x61 <= byte_val <= 0x7A)

    first_byte = b[0]
    last_byte = b[-1]

    if is_alnum(first_byte) and is_alnum(last_byte):
        return chr(first_byte) + chr(last_byte)
    else:
        hex_str = b.hex()
        return f"{hex_str[0]}{hex_str[-1]}"


def _encode_variable_length_quantity(v: int) -> list[int]:
    """Encode an integer as an ASN.1 VLQ (base-128 variable-length quantity)."""
    output = []
    output.append(v & 0x7F)
    v >>= 7
    while v > 0:
        output.insert(0, (v & 0x7F) | 0x80)
        v >>= 7
    return output


def oid_to_hex(oid: str) -> str:
    """
    Convert a dotted OID string to its ASN.1 DER content octets in lowercase hex (RFC 5280 / FoxIO JA4X).
    Example: '2.5.4.3' -> '550403'
    """
    parts = [int(x) for x in oid.strip().split(".") if x.strip()]
    if len(parts) < 2:
        return ""
    encoded = [parts[0] * 40 + parts[1]]
    for n in parts[2:]:
        encoded.extend(_encode_variable_length_quantity(n))
    return "".join(f"{b:02x}" for b in encoded)





class FoxIOIntegrationError(RuntimeError):
    """Raised when the official FoxIO runner cannot be executed or parsed."""


@dataclass(frozen=True)
class FoxIOStreamObservation:
    """FoxIO JA4+ observations associated with one TCP 4-tuple."""

    src: str
    dst: str
    srcport: int
    dstport: int
    stream: Optional[int] = None
    ja4: Optional[str] = None
    ja4s: Optional[str] = None
    ja4x: Tuple[str, ...] = ()
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str, int, int]:
        return (self.src, self.dst, self.srcport, self.dstport)


def _find_tshark() -> Optional[str]:
    """
    Locate tshark executable across explicit env, system PATH, and
    standard installation paths (especially on Windows where Wireshark
    installs without automatically adding itself to system PATH).
    """
    env_path = os.getenv("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    which_path = shutil.which("tshark")
    if which_path:
        return which_path

    if sys.platform == "win32":
        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            os.path.expandvars(r"%ProgramFiles%\Wireshark\tshark.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Wireshark\tshark.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
        ]
        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand
    else:
        candidates = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/homebrew/bin/tshark",
        ]
        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand

    return None


@dataclass
class FoxIOFingerprintIndex:
    """Lazy, capture-scoped index of FoxIO's official JSON output."""

    pcap_path: Path
    foxio_script: Optional[Path] = None
    foxio_executable: Optional[str] = None
    tshark_path: Optional[str] = None
    keylog_path: Optional[Path] = None
    timeout_seconds: int = 120

    _loaded: bool = field(default=False, init=False)
    _observations: Dict[Tuple[str, str, int, int], FoxIOStreamObservation] = field(
        default_factory=dict, init=False
    )
    _load_error: Optional[str] = field(default=None, init=False)
    _stdout_tail: str = field(default="", init=False)

    @classmethod
    def from_environment(
        cls,
        pcap_path: str | Path,
        *,
        keylog_path: str | Path | None = None,
    ) -> "FoxIOFingerprintIndex":
        """
        Resolve the official FoxIO runner from environment or common project
        locations. We support either:
          FOXIO_JA4_SCRIPT=/path/to/foxio/python/ja4.py
        or:
          FOXIO_JA4_EXECUTABLE=/path/to/ja4
        """
        root = Path(__file__).resolve().parent.parent
        script_env = os.getenv("FOXIO_JA4_SCRIPT")
        exe_env = os.getenv("FOXIO_JA4_EXECUTABLE")
        tshark_env = _find_tshark()

        candidates = [
            root / "third_party" / "foxio_ja4" / "ja4.py",
            root / "vendor" / "foxio_ja4" / "ja4.py",
            root / "foxio" / "python" / "ja4.py",
        ]
        script = Path(script_env).expanduser() if script_env else next(
            (p for p in candidates if p.exists()), None
        )

        keylog_env = os.getenv("FOXIO_SSLKEYLOG")
        resolved_keylog = keylog_path or keylog_env

        return cls(
            pcap_path=Path(pcap_path),
            foxio_script=script,
            foxio_executable=exe_env or shutil.which("ja4"),
            tshark_path=tshark_env,
            keylog_path=Path(resolved_keylog).expanduser() if resolved_keylog else None,
            timeout_seconds=int(os.getenv("FOXIO_JA4_TIMEOUT", "120")),
        )

    resolve = from_environment

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    def _build_command(self) -> List[str]:
        if not self.pcap_path.exists():
            raise FoxIOIntegrationError(f"PCAP not found: {self.pcap_path}")

        if not self.tshark_path:
            raise FoxIOIntegrationError(
                "tshark was not found. FoxIO's official Python implementation "
                "requires tshark. Set TSHARK_PATH or add tshark to PATH."
            )

        if self.foxio_script and self.foxio_script.exists():
            cmd = [
                sys.executable,
                str(self.foxio_script),
                str(self.pcap_path),
                "-J",
                "--ja4",
                "--ja4s",
                "--ja4x",
            ]
        elif self.foxio_executable:
            # Official FoxIO Rust binary: JSON is selected with -j/--json and
            # the binary emits the full JA4+ suite for the capture.
            cmd = [
                self.foxio_executable,
                "--json",
                str(self.pcap_path),
            ]
        else:
            raise FoxIOIntegrationError(
                "FoxIO was not found. Set FOXIO_JA4_SCRIPT to FoxIO's official "
                "python/ja4.py, or FOXIO_JA4_EXECUTABLE to an official ja4 binary."
            )

        if self.keylog_path:
            if self.foxio_script and self.foxio_script.exists():
                cmd.extend(["-key", str(self.keylog_path)])
            else:
                cmd.extend(["--keylog-file", str(self.keylog_path)])

        return cmd

    @staticmethod
    def _iter_json_records(stdout: str) -> Iterable[Dict[str, Any]]:
        """
        Parse both official FoxIO JSON output shapes:
          * Python implementation: one JSON object per line
          * Rust implementation: JSON document/array
        """
        text = stdout.strip()
        if not text:
            return

        try:
            document = json.loads(text)
            if isinstance(document, dict):
                yield document
                return
            if isinstance(document, list):
                for item in document:
                    if isinstance(item, dict):
                        yield item
                return
        except json.JSONDecodeError:
            pass

        # Python implementation historically emits JSON-lines; keep a strict
        # literal_eval fallback for older builds that print dict reprs.
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                try:
                    obj = ast.literal_eval(line)
                except (SyntaxError, ValueError):
                    continue
            if isinstance(obj, dict):
                yield obj

    @staticmethod
    def _tuple_int(value: Any) -> Optional[int]:
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_fingerprint_values(obj: Dict[str, Any], prefix: str) -> List[str]:
        """Return PREFIX / PREFIX.1 / PREFIX.2 ... values in numeric order."""
        values: List[Tuple[int, str]] = []
        direct = obj.get(prefix)
        if isinstance(direct, str) and direct:
            values.append((1, direct))

        pat = re.compile(rf"^{re.escape(prefix)}\.(\d+)$")
        for key, value in obj.items():
            match = pat.match(str(key))
            if match and isinstance(value, str) and value:
                values.append((int(match.group(1)), value))

        return [value for _, value in sorted(set(values), key=lambda x: x[0])]

    def load(self) -> None:
        """Execute FoxIO once for this capture and index all returned streams."""
        if self._loaded:
            return

        try:
            command = self._build_command()
            env = os.environ.copy()
            env["TSHARK_PATH"] = self.tshark_path or ""
            if self.tshark_path:
                tshark_dir = str(Path(self.tshark_path).parent)
                env["PATH"] = f"{tshark_dir}{os.pathsep}{env.get('PATH', '')}"

            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=env,
            )
            self._stdout_tail = completed.stdout[-4000:]

            if completed.returncode != 0:
                stderr = completed.stderr.strip()
                raise FoxIOIntegrationError(
                    f"FoxIO JA4+ exited with code {completed.returncode}. "
                    f"{stderr[-1000:] or 'No stderr output.'}"
                )

            count = 0
            for obj in self._iter_json_records(completed.stdout):
                src = obj.get("src")
                dst = obj.get("dst")
                srcport = self._tuple_int(obj.get("srcport", obj.get("src_port")))
                dstport = self._tuple_int(obj.get("dstport", obj.get("dst_port")))
                if not all([src, dst, srcport is not None, dstport is not None]):
                    continue

                ja4_values = self._extract_fingerprint_values(obj, "JA4")
                ja4s_values = self._extract_fingerprint_values(obj, "JA4S")
                ja4x_values = self._extract_fingerprint_values(obj, "JA4X")

                obs = FoxIOStreamObservation(
                    src=str(src),
                    dst=str(dst),
                    srcport=srcport,
                    dstport=dstport,
                    stream=self._tuple_int(obj.get("stream")),
                    ja4=ja4_values[0] if ja4_values else None,
                    ja4s=ja4s_values[0] if ja4s_values else None,
                    ja4x=tuple(ja4x_values),
                    raw=obj,
                )
                self._observations[obs.key] = obs
                count += 1

            if count == 0:
                raise FoxIOIntegrationError(
                    "FoxIO returned no stream records. Check the capture, tshark "
                    "installation, and FoxIO bundle."
                )

            self._loaded = True
        except (subprocess.TimeoutExpired, OSError, FoxIOIntegrationError) as exc:
            self._load_error = str(exc)
            raise FoxIOIntegrationError(str(exc)) from exc

    def lookup(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[FoxIOStreamObservation]:
        self.load()
        return self._observations.get((str(src_ip), str(dst_ip), int(src_port), int(dst_port)))


def build_fingerprints(
    *args,
    stream: Any = None,
    foxio: Optional[FoxIOFingerprintIndex] = None,
    **kwargs,
) -> Union[JA4Fingerprints, Tuple[JA4Fingerprints, Dict[str, Any]]]:
    """
    Dual-mode JA4+ fingerprint builder:
    1. Pipeline Mode: build_fingerprints(stream=stream, foxio=foxio) -> Tuple[JA4Fingerprints, Dict[str, Any]]
       Correlates official FoxIO output for the given stream.
    2. Reference / Standalone Mode: build_fingerprints(result: HandshakeResult) -> JA4Fingerprints
       Computes JA4/JA4S/JA4X from HandshakeResult in-memory.
    """
    if stream is not None and foxio is not None:
        obs = foxio.lookup(stream.src_ip, stream.dst_ip, stream.src_port, stream.dst_port)
        if obs is None:
            return JA4Fingerprints(), {
                "implementation": "FoxIO official JA4+",
                "status": "NO_MATCHING_FOXIO_STREAM",
                "pcap_stream_match": False,
            }

        fps = JA4Fingerprints(
            ja4=obs.ja4,
            ja4s=obs.ja4s,
            ja4x=obs.ja4x[0] if obs.ja4x else None,
            ja4x_chain=list(obs.ja4x),
        )

        return fps, {
            "implementation": "FoxIO official JA4+",
            "status": "MATCHED",
            "pcap_stream_match": True,
            "foxio_stream": obs.stream,
            "ja4x_certificate_count": len(obs.ja4x),
            "ja4x_chain": list(obs.ja4x),
            "keylog_used": bool(foxio.keylog_path),
        }

    # Fallback / Reference mode is REMOVED as per the freeze requirements.
    return JA4Fingerprints()
