#!/usr/bin/env python3
"""
rdp_weak_scan.py - tiny RDP weak configuration scanner

Checks (unauthenticated):
  - NLA mode (none / optional / required) via RDP_NEG_REQ/RSP
  - CredSSP support
  - TLS protocol versions (1.0/1.1/1.2/1.3) via TLS handshake probes
  - TLS certificate SHA-1 thumbprints (per successful version)
  - Clipboard / bitmap caching (network-only commentary)

Checks with --auth (using Impacket Remote Registry):
  - fDenyTSConnections (global RDP on/off)
  - fAllowToGetHelp (Remote Assistance / shadow)
  - SecurityLayer / UserAuthentication (true NLA/TLS posture)
  - fDisableClip / fDisableCdm (listener + policy)
  - DisableClipboardRedirection / DisableDriveRedirection
  - PortNumber (configured listener port) + mismatch warning vs scanned port

Supports IPv6 targets via [addr]:port or bare addr syntax.
Compatible with Python 3.8+.

SECURITY NOTE: 
  - --auth credentials are held in memory.
  - Using --auth on CLI exposes creds to process listing. 
  - Prefer --auth-file or --auth-env.

EXIT CODES:
  0: Scan completed successfully.
  1: Argument/Input error.
  2: Strict TLS check failed (if --strict-tls used).
"""

import argparse
import json
import socket
import ssl
import struct
import sys
import traceback
import hashlib
import time
import os
from typing import Optional, Tuple, List, Dict, Any

SCANNER_VERSION = "0.7.0"

# Constants
DEFAULT_RDP_PORT = 3389
TPKT_VERSION = 3
# X.224 TPDU codes
X224_TPDU_CONNECTION_REQUEST = 0xE0
X224_TPDU_CONNECTION_CONFIRM = 0xD0

# Heuristic: if IPv6 address part length < 6 (e.g. "3389"), assume it's a port.
IPV6_PORT_HEURISTIC_LEN = 6

# Optional Impacket support for --auth mode
try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.dcerpc.v5 import rrp, transport

    IMPACKET_AVAILABLE = True
except ImportError:  # pragma: no cover - handled gracefully at runtime
    IMPACKET_AVAILABLE = False
    SMBConnection = None
    SessionError = None
    rrp = None
    transport = None

# RDP security protocol bit flags (MS-RDPBCGR)
PROTOCOL_RDP = 0x0
PROTOCOL_SSL = 0x1
PROTOCOL_HYBRID = 0x2
PROTOCOL_RDSTLS = 0x4
PROTOCOL_HYBRID_EX = 0x8


def build_rdp_neg_req(requested_protocols: int) -> bytes:
    """
    Build an X.224 + RDP_NEG_REQ packet:

    TPKT (4 bytes)
    X.224 CR (7 bytes)
    RDP_NEG_REQ (8 bytes) = type(1) flags(1) length(2) requestedProtocols(4 LE)
    """
    # RDP_NEG_REQ
    nego = struct.pack("<BBHI", 0x01, 0x00, 8, requested_protocols)
    # X.224 header
    x224 = bytes([0x0E, X224_TPDU_CONNECTION_REQUEST, 0x00, 0x00, 0x00, 0x00, 0x00])
    # TPKT header
    length = 4 + len(x224) + len(nego)
    tpkt = struct.pack("!BBH", TPKT_VERSION, 0, length)
    return tpkt + x224 + nego


def parse_rdp_neg_resp(data: bytes) -> Dict[str, Any]:
    """
    Parse TPKT + X.224 + optional RDP_NEG_RSP / RDP_NEG_FAILURE.
    Returns a small dict describing what we saw.
    """
    if len(data) < 11:
        return {"has_neg_data": False, "error": "short_header", "raw": data.hex()}

    tpkt_v, tpkt_r, length = struct.unpack("!BBH", data[:4])
    if tpkt_v != TPKT_VERSION:
        return {"has_neg_data": False, "error": "bad_tpkt_version", "raw": data.hex()}

    # X.224 header
    # Byte 4 is length indicator (LI), ignored here.
    code = data[5]
    if code not in (X224_TPDU_CONNECTION_CONFIRM, X224_TPDU_CONNECTION_REQUEST):
        return {
            "has_neg_data": False,
            "error": f"unexpected_x224_type_{code:#x}",
            "raw": data.hex(),
        }

    # If there's no room for RDP_NEG_* after X.224, it's a legacy (no negotiation) server
    if len(data) < 11 + 8:
        return {"has_neg_data": False, "legacy": True, "raw": data.hex()}

    nego_type, flags, length_field = struct.unpack("<BBH", data[11:15])

    if nego_type == 0x02:  # RDP_NEG_RSP
        selected_protocol = struct.unpack("<I", data[15:19])[0]
        return {
            "has_neg_data": True,
            "type": "rsp",
            "selected_protocol": selected_protocol,
            "raw": data.hex(),
        }
    elif nego_type == 0x03:  # RDP_NEG_FAILURE
        failure_code = struct.unpack("<I", data[15:19])[0]
        return {
            "has_neg_data": True,
            "type": "failure",
            "failure_code": failure_code,
            "raw": data.hex(),
        }
    else:
        return {
            "has_neg_data": True,
            "type": f"unknown_{nego_type:#x}",
            "raw": data.hex(),
        }


def recv_exact(sock: socket.socket, n: int, timeout: float) -> bytes:
    """
    Receive exactly n bytes.
    Uses an absolute deadline to prevent timeouts from resetting on partial reads.
    """
    deadline = time.time() + timeout
    sock.settimeout(timeout)
    buf = b""

    while len(buf) < n:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise socket.timeout(f"Timed out waiting for {n} bytes, got {len(buf)}")

        # Strictly respect the deadline.
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise socket.timeout(f"Timed out waiting for {n} bytes, got {len(buf)}")

        if not chunk:
            raise IOError(
                f"Connection closed while expecting {n} bytes, got {len(buf)}"
            )
        buf += chunk
    return buf


def recv_rdp_packet(sock: socket.socket, timeout: float) -> bytes:
    """
    Reads a TPKT-encapsulated packet.
    Reads header (4 bytes), extracts length, reads rest.
    """
    header = recv_exact(sock, 4, timeout)
    v, r, length = struct.unpack("!BBH", header)
    # Note: We don't validate version here to allow parse_rdp_neg_resp
    # to handle/report "bad_tpkt_version" with context if preferred.
    rest = recv_exact(sock, length - 4, timeout)
    return header + rest


def rdp_negotiate(
    host: str, port: int, requested_protocols: int, timeout: float = 3.0
) -> Dict[str, Any]:
    pkt = build_rdp_neg_req(requested_protocols)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(pkt)
        data = recv_rdp_packet(sock, timeout)
        return parse_rdp_neg_resp(data)


def interpret_selected_protocol(selected_protocol: int) -> Dict[str, Any]:
    """
    Convert selectedProtocol into booleans (NLA in use, TLS in use, etc.).
    """
    nla = selected_protocol in (PROTOCOL_HYBRID, PROTOCOL_HYBRID_EX)
    tls = selected_protocol in (
        PROTOCOL_SSL,
        PROTOCOL_HYBRID,
        PROTOCOL_HYBRID_EX,
        PROTOCOL_RDSTLS,
    )
    classic_rdp = selected_protocol == PROTOCOL_RDP
    return {
        "selected_protocol_value": selected_protocol,
        "nla_in_use": nla,
        "tls_in_use": tls,
        "classic_rdp_in_use": classic_rdp,
    }


def scan_nla_and_credssp(
    host: str, port: int, timeout: float = 3.0
) -> Dict[str, Any]:
    """
    Determine whether the server supports TLS / CredSSP,
    and whether NLA is required or optional.
    """
    result = {
        "supports_tls": False,
        "supports_credssp": False,
        "nla_required": None,
        "negotiation_raw": {},
    }

    requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
    try:
        resp = rdp_negotiate(host, port, requested, timeout)
    except socket.timeout:
        result["error"] = "negotiation_timeout: Server did not respond"
        return result
    except ConnectionRefusedError:
        result["error"] = "connection_refused: Port appears closed"
        return result
    except Exception as e:
        result["error"] = f"negotiation_failed: {type(e).__name__}: {e}"
        return result

    result["negotiation_raw"]["ssl_hybrid"] = resp

    if resp.get("legacy"):
        # No RDP_NEG_RSP attached => legacy RDP, no TLS/NLA negotiation
        result.update(
            {
                "supports_tls": False,
                "supports_credssp": False,
                "nla_required": False,
                "mode": "legacy_rdp",
            }
        )
        return result

    if resp.get("type") == "failure":
        result["error"] = f"negotiation_failure_code_{resp.get('failure_code')}"
        return result

    if resp.get("type") != "rsp":
        result["error"] = f"unexpected_negotiation_type_{resp.get('type')}"
        return result

    selected = resp.get("selected_protocol", 0)
    interp = interpret_selected_protocol(selected)
    result["supports_tls"] = interp["tls_in_use"]
    result["supports_credssp"] = interp["nla_in_use"]

    # If CredSSP not in use, NLA is clearly not required
    if not interp["nla_in_use"]:
        result["nla_required"] = False
        result["mode"] = "no_nla"
        return result

    # CredSSP is in use. Check if TLS-only (no NLA) is still allowed.
    try:
        resp_ssl_only = rdp_negotiate(host, port, PROTOCOL_SSL, timeout)
    except Exception as e:
        result["negotiation_raw"]["ssl_only_error"] = str(e)
        result["nla_required"] = True
        result["mode"] = "nla_required"
        return result

    result["negotiation_raw"]["ssl_only"] = resp_ssl_only

    if (
        resp_ssl_only.get("type") == "rsp"
        and resp_ssl_only.get("selected_protocol") == PROTOCOL_SSL
    ):
        result["nla_required"] = False
        result["mode"] = "nla_optional"
    else:
        result["nla_required"] = True
        result["mode"] = "nla_required"

    return result


def scan_tls_versions(
    host: str, port: int, timeout: float = 3.0, verbose: bool = False
) -> Dict[str, Any]:
    """
    Probe which TLS protocol versions the RDP server will accept,
    and compute certificate thumbprints for successful handshakes.
    """
    versions_supported = {}
    thumbprints = {}

    try:
        tls_version_enum = ssl.TLSVersion
    except AttributeError:
        # Python too old for TLSVersion API
        return {"error": "python_ssl_too_old"}

    version_candidates = [
        ("TLS1.0", getattr(tls_version_enum, "TLSv1", None)),
        ("TLS1.1", getattr(tls_version_enum, "TLSv1_1", None)),
        ("TLS1.2", getattr(tls_version_enum, "TLSv1_2", None)),
        ("TLS1.3", getattr(tls_version_enum, "TLSv1_3", None)),
    ]

    for name, ver in version_candidates:
        if ver is None:
            continue

        try:
            # Create a fresh context per iteration to avoid state pollution
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver

            requested = PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
            pkt = build_rdp_neg_req(requested)

            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.sendall(pkt)

                # Use helper for TPKT reading
                data = recv_rdp_packet(sock, timeout)
                parsed = parse_rdp_neg_resp(data)

                if parsed.get("legacy") or parsed.get("type") == "failure":
                    versions_supported[name] = False
                    thumbprints[name] = None
                    continue

                if (
                    parsed.get("type") != "rsp"
                    or parsed.get("selected_protocol") == PROTOCOL_RDP
                ):
                    versions_supported[name] = False
                    thumbprints[name] = None
                    continue

                # At this point server expects a TLS handshake
                try:
                    tls_sock = ctx.wrap_socket(sock, server_hostname=host)
                    tls_sock.do_handshake()
                    versions_supported[name] = True

                    try:
                        der_cert = tls_sock.getpeercert(binary_form=True)
                        if der_cert:
                            # SHA-1 is used here only for fingerprinting (not security).
                            thumbprints[name] = hashlib.sha1(der_cert).hexdigest()
                        else:
                            thumbprints[name] = None
                    except Exception:
                        thumbprints[name] = None

                    tls_sock.close()
                except ssl.SSLError as e:
                    versions_supported[name] = False
                    thumbprints[name] = None
                    if verbose:
                        print(f"[-] {name} handshake error: {e}", file=sys.stderr)

        except Exception as e:
            # Any weird network / parsing failure -> mark as unsupported
            versions_supported[name] = False
            thumbprints[name] = None
            if verbose:
                print(f"[-] {name} probe error: {e}", file=sys.stderr)

    weak = [
        name
        for name, ok in versions_supported.items()
        if ok and name in ("TLS1.0", "TLS1.1")
    ]
    strong = [
        name
        for name, ok in versions_supported.items()
        if ok and name in ("TLS1.2", "TLS1.3")
    ]

    unique_thumbprints = sorted({fp for fp in thumbprints.values() if fp})

    return {
        "versions": versions_supported,
        "weak": weak,
        "strong": strong,
        "thumbprints": thumbprints,
        "unique_thumbprints": unique_thumbprints,
    }


def default_clipboard_status() -> Dict[str, str]:
    """
    Placeholder for clipboard redirection check without credentials.
    """
    return {
        "status": "unknown",
        "detail": (
            "Clipboard redirection is controlled by server policy "
            "(fDisableClip / DisableClipboardRedirection) and typically requires "
            "credentials or an on-host agent to inspect."
        ),
    }


def default_bitmap_caching_status() -> Dict[str, str]:
    """
    Placeholder for bitmap caching commentary.

    This is primarily a client-side option and not directly enforceable
    by the server in a way we can infer anonymously.
    """
    return {
        "status": "client_side",
        "detail": (
            "Bitmap caching is primarily a client-side option; "
            "the server cannot universally disable it in a way "
            "that is externally detectable."
        ),
    }


def format_target_display(host: str, port: int) -> str:
    """Helper to format IPv6 targets with brackets if needed."""
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{display_host}:{port}"


# ---------------------------------------------------------------------------
#  Impacket / Remote Registry helpers (used in --auth mode)
# ---------------------------------------------------------------------------


def parse_auth_string(auth_str: str) -> Tuple[str, str, str]:
    """
    Parse 'DOMAIN\\user:pass' or 'user:pass' into (domain, user, password).
    Domain may be '' for local accounts.
    """
    if ":" not in auth_str:
        raise ValueError(
            "Auth string must be in the form 'DOMAIN\\\\user:pass' or 'user:pass'"
        )
    user_part, password = auth_str.split(":", 1)
    if "\\" in user_part:
        domain, username = user_part.split("\\", 1)
    else:
        domain, username = "", user_part

    # Input sanitization
    forbidden = "\n\r\0"
    if any(c in username for c in forbidden):
        raise ValueError("Invalid characters in username")
    if any(c in domain for c in forbidden):
        raise ValueError("Invalid characters in domain")
    # Printable characters check for password (basic sanity)
    if not all(c.isprintable() or c.isspace() for c in password):
        raise ValueError("Non-printable characters in password")

    return domain, username, password


def open_remote_registry(
    host: str, domain: str, username: str, password: str, timeout: float = 5.0
):
    """
    Open a Remote Registry session using Impacket over SMB.
    Returns (smb, dce).
    Ensures SMB connection is closed if DCE bind fails.
    """
    if not IMPACKET_AVAILABLE:
        raise RuntimeError("Impacket is not installed; --auth mode is unavailable")

    smb = None
    try:
        smb = SMBConnection(host, host, sess_port=445)
        smb.setTimeout(timeout)

        try:
            smb.login(username, password, domain)
        except SessionError as e:
            msg = str(e)
            if "STATUS_LOGON_FAILURE" in msg:
                raise RuntimeError("Auth failed: Invalid credentials")
            elif "STATUS_ACCOUNT_LOCKED_OUT" in msg:
                raise RuntimeError("Auth failed: Account locked out")
            else:
                raise
        except Exception as e:
            raise RuntimeError(f"SMB login failed: {e}")

        string_binding = r"ncacn_np:445[\pipe\winreg]"
        rpc = transport.DCERPCTransportFactory(string_binding)
        rpc.set_smb_connection(smb)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)
        return smb, dce

    except Exception as e:
        # If anything failed, clean up the SMB connection before re-raising
        if smb is not None:
            try:
                smb.close()
            except Exception:
                pass
        # Preserve original exception context if wrapping, or just raise string
        if isinstance(e, RuntimeError):
            raise e
        raise RuntimeError(f"Remote Registry connection failed: {e}")


def close_remote_registry(smb, dce):
    """
    Best-effort cleanup for Remote Registry session.
    """
    try:
        if dce is not None:
            dce.disconnect()
    except Exception:
        pass
    try:
        if smb is not None:
            smb.close()
    except Exception:
        pass


def query_reg_value(dce, key_path: str, value_name: str) -> Any:
    """
    Query a registry value via MS-RRP.
    """
    if rrp is None:
        return None

    if not key_path or not value_name:
        return None

    try:
        root, subkey = key_path.split("\\", 1)
    except ValueError:
        raise ValueError(f"Invalid registry path: {key_path}")

    root_upper = root.upper()
    if root_upper not in ("HKLM", "HKEY_LOCAL_MACHINE"):
        raise ValueError(f"Unsupported root hive '{root}' (only HKLM is used here)")

    try:
        ans = rrp.hOpenLocalMachine(dce)
        h_root = ans["phKey"]
    except Exception:
        return None

    h_key = None
    try:
        ans2 = rrp.hBaseRegOpenKey(
            dce,
            h_root,
            subkey,
            samDesired=rrp.MAXIMUM_ALLOWED,
        )
        h_key = ans2["phkResult"]
        data_type, data = rrp.hBaseRegQueryValue(dce, h_key, value_name)
        return data
    except Exception:
        return None
    finally:
        # Robust cleanup
        if h_key is not None:
            try:
                rrp.hBaseRegCloseKey(dce, h_key)
            except Exception:
                pass
        try:
            rrp.hBaseRegCloseKey(dce, h_root)
        except Exception:
            pass


def query_reg_dword(dce, key_path: str, value_name: str) -> Optional[int]:
    """
    Convenience wrapper for REG_DWORD values.
    Returns int or None.
    """
    val = query_reg_value(dce, key_path, value_name)
    if val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, (bytes, bytearray)):
        if len(val) >= 4:
            return struct.unpack("<I", val[:4])[0]
    return None


def interpret_security_layer(val: Optional[int]) -> str:
    """
    Decode SecurityLayer DWORD into a human-friendly string.
    0 = RDP, 1 = Negotiate, 2 = TLS.
    """
    if val is None:
        return "unknown"
    if val == 0:
        return "RDP_security_only (no TLS)"
    if val == 1:
        return "Negotiate (RDP or TLS)"
    if val == 2:
        return "TLS_only"
    return f"unknown({val})"


def any_flag_enabled(flags: List[Optional[int]]) -> bool:
    """Helper to check if any flag in a list is 1 (True)."""
    # Explicitly check for 1 to avoid confusion with non-None types
    return any(v == 1 for v in flags if v is not None)


def rdp_registry_enum(
    host: str,
    domain: str,
    username: str,
    password: str,
    scanned_port: Optional[int] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Enumerate RDP-related registry settings using Remote Registry.
    """
    if not IMPACKET_AVAILABLE:
        return {"error": "impacket_not_installed"}

    smb = None
    dce = None
    try:
        smb, dce = open_remote_registry(host, domain, username, password, timeout)

        global_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
        winst_key = (
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        )
        policy_key = (
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        )

        global_info = {
            "fDenyTSConnections": query_reg_dword(
                dce, global_key, "fDenyTSConnections"
            ),
            "fAllowToGetHelp": query_reg_dword(dce, global_key, "fAllowToGetHelp"),
        }

        winst_info = {
            "SecurityLayer": query_reg_dword(dce, winst_key, "SecurityLayer"),
            "UserAuthentication": query_reg_dword(
                dce, winst_key, "UserAuthentication"
            ),
            "fDisableClip": query_reg_dword(dce, winst_key, "fDisableClip"),
            "fDisableCdm": query_reg_dword(dce, winst_key, "fDisableCdm"),
            "PortNumber": query_reg_dword(dce, winst_key, "PortNumber"),
        }

        policy_info = {
            "fDisableClip": query_reg_dword(dce, policy_key, "fDisableClip"),
            "fDisableCdm": query_reg_dword(dce, policy_key, "fDisableCdm"),
            "DisableClipboardRedirection": query_reg_dword(
                dce, policy_key, "DisableClipboardRedirection"
            ),
            "DisableDriveRedirection": query_reg_dword(
                dce, policy_key, "DisableDriveRedirection"
            ),
        }

        clip_flags = [
            winst_info.get("fDisableClip"),
            policy_info.get("fDisableClip"),
            policy_info.get("DisableClipboardRedirection"),
        ]
        drive_flags = [
            winst_info.get("fDisableCdm"),
            policy_info.get("fDisableCdm"),
            policy_info.get("DisableDriveRedirection"),
        ]

        clip_disabled = any_flag_enabled(clip_flags)
        drive_disabled = any_flag_enabled(drive_flags)

        f_deny = global_info.get("fDenyTSConnections")
        # fDenyTSConnections = 1 -> RDP disabled, anything else -> assume enabled
        rdp_enabled = False if f_deny == 1 else True

        security_layer_val = winst_info.get("SecurityLayer")
        user_auth_val = winst_info.get("UserAuthentication")
        allow_help_val = global_info.get("fAllowToGetHelp")

        effective = {
            "rdp_enabled": rdp_enabled,
            "clipboard_allowed": not clip_disabled,
            "drive_redirection_allowed": not drive_disabled,
            "security_layer_raw": security_layer_val,
            "security_layer": interpret_security_layer(security_layer_val),
            "user_auth_raw": user_auth_val,
            "nla_enforced": True if user_auth_val == 1 else False,
            "remote_assistance_enabled": True if allow_help_val == 1 else False,
            "configured_port": winst_info.get("PortNumber"),
            "scanned_port": scanned_port,
        }

        # Check port mismatch
        effective["port_mismatch"] = False
        if (
            scanned_port is not None
            and effective["configured_port"]
            and effective["configured_port"] != scanned_port
        ):
            effective["port_mismatch"] = True

        result = {
            "host": host,
            "global": global_info,
            "winstations": winst_info,
            "policies": policy_info,
            "effective": effective,
        }
        return result

    except Exception as e:
        err_str = str(e)
        if "Port 445 likely closed" in err_str:
            return {"error": "smb_unavailable", "detail": err_str}
        return {"error": "auth_failed", "detail": err_str}
    finally:
        close_remote_registry(smb, dce)


# ---------------------------------------------------------------------------
#  Combined scanner
# ---------------------------------------------------------------------------


def scan_target(
    host: str,
    port: int,
    timeout: float = 3.0,
    auth: Optional[Tuple[str, str, str]] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Core scan routine for a single host:port.
    auth: optional (domain, user, password) tuple to enable registry-based checks.
    """
    result = {
        "target": format_target_display(host, port),
        "scanner_version": SCANNER_VERSION,
        "scan_time": time.time(),
    }

    nla_info = scan_nla_and_credssp(host, port, timeout)
    result["nla"] = nla_info

    if nla_info.get("error"):
        result["tls"] = {"error": "skipped_due_to_negotiation_error"}
    else:
        result["tls"] = scan_tls_versions(host, port, timeout, verbose=verbose)

    result["clipboard"] = default_clipboard_status()
    result["bitmap_caching"] = default_bitmap_caching_status()

    if auth is not None:
        domain, username, password = auth
        if not IMPACKET_AVAILABLE:
            result["rdp_registry"] = {"error": "impacket_not_installed"}
        else:
            result["rdp_registry"] = rdp_registry_enum(
                host,
                domain,
                username,
                password,
                scanned_port=port,
                timeout=timeout,
            )

    return result


def parse_target(s: str) -> Tuple[str, int]:
    """
    Parse target strings into (host, port).
    Supports IPv4, DNS, and IPv6 ([addr]:port).
    """
    s = s.strip()
    if not s:
        raise ValueError("Empty target")

    # Bracketed IPv6 forms: [addr] or [addr]:port
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise ValueError(f"Invalid IPv6 target (missing ']'): '{s}'")
        host = s[1:end]
        rest = s[end + 1 :]

        if rest == "":
            port = DEFAULT_RDP_PORT
        elif rest.startswith(":"):
            port_str = rest[1:]
            if not port_str:
                raise ValueError(f"Invalid port in target '{s}'")
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid port in target '{s}'")
        else:
            raise ValueError(f"Unexpected characters after IPv6 literal in '{s}'")
    else:
        # Non-bracketed forms
        colon_count = s.count(":")

        if colon_count == 0:
            # 'host'
            host, port = s, DEFAULT_RDP_PORT
        elif colon_count == 1:
            # 'host:port' or 'ipv4:port'
            host, port_str = s.rsplit(":", 1)
            if not host or not port_str:
                raise ValueError(f"Invalid target '{s}'")
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"Invalid port in target '{s}'")
        else:
            # Multiple colons. Check ambiguity.
            # Heuristic: if last part is small digits, likely user meant port but forgot brackets
            last_part = s.split(":")[-1]
            if last_part.isdigit() and len(last_part) < IPV6_PORT_HEURISTIC_LEN:
                raise ValueError(
                    f"Ambiguous target '{s}'. If this is [ipv6]:port, use brackets."
                )
            # Treat as bare IPv6 with default port
            host, port = s, DEFAULT_RDP_PORT

    if not (1 <= port <= 65535):
        raise ValueError(f"Port out of range (1-65535): {port}")

    return host, port


def load_targets_from_file(filepath: str) -> List[str]:
    """Read targets from a file, skipping empty lines and comments."""
    targets = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except Exception as e:
        print(f"[!] Could not read targets file: {e}", file=sys.stderr)
        sys.exit(1)
    return targets


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Minimal RDP weak configuration scanner "
            "(NLA, TLS versions, CredSSP, certificate thumbprints, clipboard, "
            "bitmap caching, and optional registry-based checks with --auth)."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    # Target specification: allow both positional CLI args and a file
    parser.add_argument(
        "targets",
        nargs="*",
        help="Targets as host or host:port",
    )
    parser.add_argument(
        "--targets-file",
        metavar="FILE",
        help="File containing targets (one per line)",
    )

    parser.add_argument(
        "--timeout", type=float, default=3.0, help="Per-connection timeout (seconds)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between targets (rate limiting)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output JSON instead of text"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose debug output"
    )

    # Auth Groups
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--auth",
        metavar="DOMAIN\\user:pass",
        help=(
            "Credentials for Impacket+Registry checks. "
            "WARNING: Visible in process list. Prefer --auth-file or --auth-env."
        ),
    )
    group.add_argument(
        "--auth-file",
        metavar="FILE",
        help="Read credentials from file (first line). Format: 'DOMAIN\\\\user:pass'.",
    )
    group.add_argument(
        "--auth-env",
        action="store_true",
        help="Read credentials from RDP_SCAN_AUTH environment variable.",
    )

    parser.add_argument(
        "--expected-thumbprint",
        metavar="SHA1",
        help="Expected SHA-1 thumbprint of the RDP certificate. "
        "Warns if the server presents something else.",
    )
    parser.add_argument(
        "--strict-tls",
        action="store_true",
        help="Return exit code 2 if any target supports TLS1.0 or TLS1.1.",
    )

    args = parser.parse_args(argv)

    # Input Validation
    if args.timeout <= 0:
        print("[!] Timeout must be positive.", file=sys.stderr)
        return 1
    if args.delay < 0:
        print("[!] Delay must be non-negative.", file=sys.stderr)
        return 1

    # Target Gathering
    target_list = args.targets[:]
    if args.targets_file:
        target_list.extend(load_targets_from_file(args.targets_file))

    if not target_list:
        parser.print_help()
        return 1

    # Credential Loading
    auth_str = None
    if args.auth:
        auth_str = args.auth
    elif args.auth_file:
        try:
            with open(args.auth_file, "r") as f:
                auth_str = f.readline().strip()
        except Exception as e:
            print(f"[!] Could not read auth file: {e}", file=sys.stderr)
            return 1
    elif args.auth_env:
        auth_str = os.getenv("RDP_SCAN_AUTH")
        if not auth_str:
            print("[!] RDP_SCAN_AUTH environment variable not set.", file=sys.stderr)
            return 1

    auth_tuple = None
    if auth_str:
        try:
            auth_tuple = parse_auth_string(auth_str)
        except ValueError as e:
            print(f"[!] Invalid auth value: {e}", file=sys.stderr)
            return 1

    expected_fp = (
        (args.expected_thumbprint or "").lower().replace(":", "").strip()
    )

    all_results = []
    total_targets = len(target_list)

    try:
        for i, t in enumerate(target_list):
            # Progress (if not JSON)
            if not args.json:
                print(
                    f"[*] Scanning {i + 1}/{total_targets}: {t}...",
                    file=sys.stderr,
                    end="\r",
                )

            # Rate limiting
            if i > 0 and args.delay > 0:
                time.sleep(args.delay)

            try:
                host, port = parse_target(t)
            except ValueError as e:
                print(f"[!] Skipping target '{t}': {e}", file=sys.stderr)
                continue

            try:
                res = scan_target(
                    host,
                    port,
                    timeout=args.timeout,
                    auth=auth_tuple,
                    verbose=args.verbose,
                )
            except Exception as e:
                if args.verbose:
                    traceback.print_exc()
                # Consistent IPv6 display even on crash
                display_host = (
                    f"[{host}]"
                    if ":" in host and not host.startswith("[")
                    else host
                )
                res = {
                    "target": f"{display_host}:{port}",
                    "scanner_version": SCANNER_VERSION,
                    "scan_time": time.time(),
                    "error": f"scan_failed: {e}",
                }

            all_results.append(res)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)
        # Fall through to print whatever results we have collected so far

    # Clear progress line
    if not args.json:
        print(" " * 60, file=sys.stderr, end="\r")

    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        for res in all_results:
            print(f"== {res.get('target')} ==")
            if "error" in res:
                print(f"  ERROR: {res['error']}")
                print()
                continue

            nla = res["nla"]
            mode = nla.get("mode", "unknown")
            print(f"  NLA mode (from negotiation): {mode}")
            print(f"    supports TLS: {nla.get('supports_tls')}")
            print(f"    supports CredSSP: {nla.get('supports_credssp')}")
            print(f"    NLA required (network inference): {nla.get('nla_required')}")

            tls = res.get("tls", {})
            if "error" in tls:
                msg = tls["error"]
                if msg == "python_ssl_too_old":
                    print("  TLS: Python/OpenSSL too old for TLSVersion probing.")
                else:
                    print(f"  TLS: {msg}")
            else:
                print("  TLS versions (via handshake probes):")
                for name, ok in sorted(tls["versions"].items()):
                    flag = "yes" if ok else "no"
                    print(f"    {name}: {flag}")
                if tls["weak"]:
                    print(f"    Weak TLS enabled: {', '.join(tls['weak'])}")
                if tls["strong"]:
                    print(f"    Strong TLS enabled: {', '.join(tls['strong'])}")

                thumbs = tls.get("thumbprints", {})
                unique_thumbs = tls.get("unique_thumbprints") or []

                if unique_thumbs:
                    print("  TLS certificate thumbprints:")
                    if len(unique_thumbs) == 1:
                        print(f"    (Same cert for all versions): {unique_thumbs[0]}")
                    else:
                        print("    (Certificates differ between versions!)")
                        for name, fp in sorted(thumbs.items()):
                            if fp:
                                print(f"      {name}: {fp}")

                # Check expected thumbprint if provided
                if expected_fp and thumbs:
                    found_fps = {
                        fp.lower().replace(":", "") for fp in thumbs.values() if fp
                    }
                    if found_fps and expected_fp not in found_fps:
                        print(
                            "  WARNING: Presented certificate thumbprints do not match "
                            "the expected thumbprint specified via --expected-thumbprint."
                        )

            clip = res["clipboard"]
            print(
                f"  Clipboard redirection (unauth view): "
                f"{clip['status']} ({clip['detail']})"
            )

            bmp = res["bitmap_caching"]
            print(
                f"  Bitmap caching (commentary): "
                f"{bmp['status']} ({bmp['detail']})"
            )

            rdp_reg = res.get("rdp_registry")
            if rdp_reg:
                if "error" in rdp_reg:
                    err_msg = rdp_reg.get('error')
                    detail = rdp_reg.get('detail', '')
                    print(f"  RDP registry (auth-based): {err_msg} - {detail}")
                else:
                    eff = rdp_reg.get("effective", {})
                    print("  RDP registry (auth-based posture):")
                    print(
                        f"    RDP enabled (fDenyTSConnections): "
                        f"{eff.get('rdp_enabled')}"
                    )
                    print(
                        f"    NLA enforced (UserAuthentication=1): "
                        f"{eff.get('nla_enforced')}"
                    )
                    print(
                        f"    SecurityLayer: {eff.get('security_layer')} "
                        f"(raw={eff.get('security_layer_raw')})"
                    )
                    print(
                        "    Clipboard allowed: "
                        f"{eff.get('clipboard_allowed')} "
                        "(from fDisableClip / DisableClipboardRedirection)"
                    )
                    print(
                        "    Drive redirection allowed: "
                        f"{eff.get('drive_redirection_allowed')} "
                        "(from fDisableCdm / DisableDriveRedirection)"
                    )
                    print(
                        "    Remote Assistance enabled (fAllowToGetHelp): "
                        f"{eff.get('remote_assistance_enabled')}"
                    )
                    conf_port = eff.get("configured_port")
                    sp = eff.get("scanned_port")
                    print(f"    Registry PortNumber: {conf_port}")
                    if eff.get("port_mismatch"):
                        print(
                            f"    WARNING: Scanned port is {sp}, but registry "
                            f"PortNumber is {conf_port} "
                            "(possible port forward / non-standard listener)."
                        )

            print()

    # --strict-tls check
    exit_code = 0
    if args.strict_tls:
        for res in all_results:
            tls = res.get("tls", {})
            if isinstance(tls, dict) and tls.get("weak"):
                exit_code = 2
                break

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
