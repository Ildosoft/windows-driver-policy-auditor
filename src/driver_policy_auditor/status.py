from __future__ import annotations
import hashlib, json, platform, subprocess
from pathlib import Path

def _reg(path: str, name: str):
    if platform.system() != "Windows": return None
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key: return winreg.QueryValueEx(key, name)[0]
    except OSError: return None

def system_status() -> dict:
    return {"platform": platform.platform(),
        "hvci_enabled": _reg(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled"),
        "vbs_enabled": _reg(r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity"),
        "vulnerable_driver_blocklist": _reg(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable"),
        "smart_app_control": _reg(r"SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState"), "read_only": True}

def audit_driver(path: Path) -> dict:
    resolved = path.expanduser().resolve(strict=True)
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    signature = {"status": "unavailable", "signer": None}
    if platform.system() == "Windows":
        escaped = str(resolved).replace("'", "''")
        script = f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped}';[pscustomobject]@{{status=[string]$s.Status;signer=$s.SignerCertificate.Subject}}|ConvertTo-Json -Compress"
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if completed.returncode == 0 and completed.stdout.strip(): signature = json.loads(completed.stdout)
    return {"path": str(resolved), "size": resolved.stat().st_size, "sha256": digest, "authenticode": signature}
