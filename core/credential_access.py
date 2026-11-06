"""Explicit, transient retrieval of the active user's current Wi-Fi password."""
from __future__ import annotations

import re
import subprocess


class CredentialAccessError(RuntimeError):
    """Sanitized credential-access failure safe to show in the UI."""


def _current_ssid(wifi_info):
    if not isinstance(wifi_info, dict) or wifi_info.get("connected") is not True:
        raise CredentialAccessError("No currently connected Wi-Fi network was confirmed by the operating system.")
    ssid = wifi_info.get("ssid")
    if not isinstance(ssid, str) or not ssid.strip():
        raise CredentialAccessError("The connected SSID is unavailable; WiFiSentinel will not search other saved profiles.")
    return ssid


def _run(args, runner):
    try:
        result = runner(args, capture_output=True, text=True, timeout=10, shell=False, check=False)
    except subprocess.TimeoutExpired:
        raise CredentialAccessError("The operating-system credential request timed out or was cancelled.") from None
    except (OSError, PermissionError):
        raise CredentialAccessError("The operating-system credential utility is unavailable or access was denied.") from None
    return result


def _windows_is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def retrieve_current_wifi_credential(os_type, wifi_info, run_command=subprocess.run, is_admin=None):
    """Return a password only for the currently connected SSID after explicit UI action.

    macOS delegates to Keychain's `security` utility, which honors Keychain ACLs
    and any OS prompt. Windows calls `netsh` only from an elevated process,
    allowing Windows profile permissions to gate plaintext access. Command
    execution is argv-based, bounded, and never logs or persists stdout.
    """
    ssid = _current_ssid(wifi_info)
    if os_type == "Darwin":
        args = ["security", "find-generic-password", "-D", "AirPort network password", "-a", ssid, "-w"]
        result = _run(args, run_command)
        if getattr(result, "returncode", 1) != 0:
            raise CredentialAccessError("macOS Keychain did not grant access or no saved credential exists for the current network. Check Keychain Access or allow its access prompt.")
        password = (getattr(result, "stdout", "") or "").rstrip("\r\n")
        if not password:
            raise CredentialAccessError("macOS returned no saved password for the current network. Check Keychain Access or the router settings.")
        return password

    if os_type == "Windows":
        if is_admin is None:
            is_admin = _windows_is_admin()
        if not is_admin:
            raise CredentialAccessError("Windows requires WiFiSentinel to be launched with an authorized administrator account to read a plaintext saved Wi-Fi key. You can inspect it in the current network's Wi-Fi properties instead.")
        args = ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"]
        result = _run(args, run_command)
        if getattr(result, "returncode", 1) != 0:
            raise CredentialAccessError("Windows did not grant access or no saved credential exists for the current network. Inspect the current network's Wi-Fi properties.")
        output = getattr(result, "stdout", "") or ""
        for line in output.splitlines():
            match = re.match(r"^\s*Key Content\s*:\s?(.*)$", line, re.IGNORECASE)
            if match:
                password = match.group(1).rstrip("\r")
                if password:
                    return password
                break
        raise CredentialAccessError("Windows returned no readable saved key for the current profile. The profile may use enterprise authentication or a localized output format; inspect Wi-Fi properties.")

    raise CredentialAccessError(f"Saved Wi-Fi credential retrieval is not supported on {os_type or 'this platform'}.")
