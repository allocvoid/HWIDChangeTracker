#!/usr/bin/env python3
"""
HWID Monitor & Logger
Reads all hardware identifiers Windows exposes, logs them with timestamps,
and compares readings to detect exactly what changes between runs.
Zero pip dependencies — stdlib only.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import winreg

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
DEFAULT_LOG_PATH = os.path.join(SCRIPT_DIR, "hwid_log.json")
TASK_NAME = "HWID Monitor"

# Hide console windows spawned by subprocess calls
CREATE_NO_WINDOW = 0x08000000

PS_BATCH_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @{}

# CPU
$cpu = Get-CimInstance Win32_Processor | Select-Object ProcessorId, Name
$r['cpu_id'] = if ($cpu.ProcessorId) { $cpu.ProcessorId.Trim() } else { $null }
$r['cpu_name'] = if ($cpu.Name) { $cpu.Name.Trim() } else { $null }

# Motherboard
$mb = Get-CimInstance Win32_BaseBoard
$r['motherboard_serial'] = if ($mb.SerialNumber) { $mb.SerialNumber.Trim() } else { $null }
$r['motherboard_manufacturer'] = if ($mb.Manufacturer) { $mb.Manufacturer.Trim() } else { $null }
$r['motherboard_product'] = if ($mb.Product) { $mb.Product.Trim() } else { $null }

# BIOS
$bios = Get-CimInstance Win32_BIOS
$r['bios_serial'] = if ($bios.SerialNumber) { $bios.SerialNumber.Trim() } else { $null }
$r['bios_version'] = if ($bios.SMBIOSBIOSVersion) { $bios.SMBIOSBIOSVersion.Trim() } else { $null }

# System UUID (SMBIOS UUID)
$csp = Get-CimInstance Win32_ComputerSystemProduct
$r['system_uuid'] = if ($csp.UUID) { $csp.UUID.Trim() } else { $null }

# Disk Drives
$disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
    @{
        model     = if ($_.Model) { $_.Model.Trim() } else { '' }
        serial    = if ($_.SerialNumber) { $_.SerialNumber.Trim() } else { '' }
        interface = if ($_.InterfaceType) { $_.InterfaceType } else { '' }
        media     = if ($_.MediaType) { $_.MediaType } else { '' }
        size_gb   = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 0 }
    }
})
$r['disk_drives'] = $disks

# Network Adapters (physical only, with MAC)
$nets = @(Get-CimInstance Win32_NetworkAdapter |
    Where-Object { $_.MACAddress -ne $null -and $_.PhysicalAdapter -eq $true } |
    ForEach-Object {
        @{
            name = if ($_.Name) { $_.Name.Trim() } else { '' }
            mac  = $_.MACAddress
            pnp  = if ($_.PNPDeviceID) { $_.PNPDeviceID } else { '' }
            type = if ($_.AdapterType) { $_.AdapterType } else { '' }
        }
    })
$r['network_adapters'] = $nets

# GPU
$gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object {
    @{
        name   = if ($_.Name) { $_.Name.Trim() } else { '' }
        pnp    = if ($_.PNPDeviceID) { $_.PNPDeviceID } else { '' }
        driver = if ($_.DriverVersion) { $_.DriverVersion } else { '' }
    }
})
$r['gpus'] = $gpus

# RAM
$rams = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
    @{
        bank        = if ($_.BankLabel) { $_.BankLabel.Trim() } else { '' }
        serial      = if ($_.SerialNumber) { $_.SerialNumber.Trim() } else { '' }
        capacity_gb = if ($_.Capacity) { [math]::Round($_.Capacity / 1GB, 1) } else { 0 }
        manufacturer = if ($_.Manufacturer) { $_.Manufacturer.Trim() } else { '' }
    }
})
$r['ram_modules'] = $rams

# Volume Serial Numbers (fixed disks only, DriveType 3)
$vols = @(Get-CimInstance Win32_LogicalDisk |
    Where-Object { $_.DriveType -eq 3 } |
    ForEach-Object {
        @{
            drive  = $_.DeviceID
            serial = if ($_.VolumeSerialNumber) { $_.VolumeSerialNumber } else { '' }
            name   = if ($_.VolumeName) { $_.VolumeName.Trim() } else { '' }
        }
    })
$r['volumes'] = $vols

# TPM
$tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm
if ($tpm) {
    $r['tpm_manufacturer'] = if ($tpm.ManufacturerIdTxt) { $tpm.ManufacturerIdTxt } else { $null }
    $r['tpm_version'] = if ($tpm.SpecVersion) { $tpm.SpecVersion } else { $null }
} else {
    $r['tpm_manufacturer'] = $null
    $r['tpm_version'] = $null
}

$r | ConvertTo-Json -Depth 4 -Compress
"""

# ─────────────────────────────────────────────────────────────────────────────
# ANSI Colors (with fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _enable_ansi():
    """Enable ANSI escape codes on Windows 10+."""
    try:
        os.system("")  # triggers VT processing
        # Test if it actually works
        return True
    except Exception:
        return False

USE_COLOR = _enable_ansi()

def c(text, code):
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def green(t):  return c(t, "92")
def red(t):    return c(t, "91")
def yellow(t): return c(t, "93")
def cyan(t):   return c(t, "96")
def bold(t):   return c(t, "1")
def dim(t):    return c(t, "90")

# ─────────────────────────────────────────────────────────────────────────────
# Registry Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_registry(hive, path, name):
    """Read a single registry value. Returns None on failure."""
    try:
        key = winreg.OpenKey(hive, path)
        value, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return value
    except (OSError, FileNotFoundError, PermissionError):
        return None


def _get_registry_values():
    """Read all HWID-relevant registry values."""
    data = {}

    # Machine GUID
    data["machine_guid"] = _read_registry(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid"
    )

    # Windows info
    nt_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    data["windows_product_id"] = _read_registry(
        winreg.HKEY_LOCAL_MACHINE, nt_path, "ProductId"
    )
    data["windows_edition"] = _read_registry(
        winreg.HKEY_LOCAL_MACHINE, nt_path, "ProductName"
    )
    data["windows_build"] = _read_registry(
        winreg.HKEY_LOCAL_MACHINE, nt_path, "CurrentBuild"
    )

    install_epoch = _read_registry(
        winreg.HKEY_LOCAL_MACHINE, nt_path, "InstallDate"
    )
    if install_epoch and isinstance(install_epoch, int):
        try:
            data["windows_install_date"] = datetime.datetime.utcfromtimestamp(
                install_epoch
            ).isoformat()
        except (OSError, ValueError):
            data["windows_install_date"] = str(install_epoch)
    else:
        data["windows_install_date"] = None

    return data

# ─────────────────────────────────────────────────────────────────────────────
# PowerShell / WMI Collection
# ─────────────────────────────────────────────────────────────────────────────

def _run_powershell_batch():
    """Run the batched PowerShell CIM script. Returns parsed dict or None."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
             PS_BATCH_SCRIPT],
            capture_output=True, text=True, timeout=45,
            creationflags=CREATE_NO_WINDOW
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(yellow(f"  [WARN] PowerShell batch failed: {e}"))
        print(yellow("         Falling back to individual WMIC calls..."))
    return None


def _wmic_query(wmic_class, fields):
    """Fallback: individual WMIC query. Returns list of dicts."""
    try:
        cmd = f'wmic {wmic_class} get {",".join(fields)} /format:csv'
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=15, shell=True,
                                creationflags=CREATE_NO_WINDOW)
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        if len(lines) < 2:
            return []
        headers = [h.strip().lower() for h in lines[0].split(",")]
        rows = []
        for line in lines[1:]:
            vals = line.split(",")
            if len(vals) >= len(headers):
                row = {}
                for i, h in enumerate(headers):
                    if h and h != "node":
                        row[h] = vals[i].strip() if i < len(vals) else ""
                rows.append(row)
        return rows
    except Exception:
        return []


def _fallback_wmi_collect():
    """Collect WMI data via individual WMIC calls (slower fallback)."""
    data = {}

    # CPU
    cpus = _wmic_query("cpu", ["ProcessorId", "Name"])
    if cpus:
        data["cpu_id"] = cpus[0].get("processorid", "")
        data["cpu_name"] = cpus[0].get("name", "")
    else:
        data["cpu_id"] = None
        data["cpu_name"] = None

    # Motherboard
    mbs = _wmic_query("baseboard", ["SerialNumber", "Manufacturer", "Product"])
    if mbs:
        data["motherboard_serial"] = mbs[0].get("serialnumber", "")
        data["motherboard_manufacturer"] = mbs[0].get("manufacturer", "")
        data["motherboard_product"] = mbs[0].get("product", "")
    else:
        data["motherboard_serial"] = None
        data["motherboard_manufacturer"] = None
        data["motherboard_product"] = None

    # BIOS
    bios = _wmic_query("bios", ["SerialNumber", "SMBIOSBIOSVersion"])
    if bios:
        data["bios_serial"] = bios[0].get("serialnumber", "")
        data["bios_version"] = bios[0].get("smbiosbiosversion", "")
    else:
        data["bios_serial"] = None
        data["bios_version"] = None

    # System UUID
    csp = _wmic_query("csproduct", ["UUID"])
    data["system_uuid"] = csp[0].get("uuid", "") if csp else None

    # Disks
    disks = _wmic_query("diskdrive", ["Model", "SerialNumber", "InterfaceType", "MediaType", "Size"])
    data["disk_drives"] = []
    for d in disks:
        size = 0
        try:
            size = round(int(d.get("size", 0)) / (1024**3), 1)
        except (ValueError, TypeError):
            pass
        data["disk_drives"].append({
            "model": d.get("model", ""),
            "serial": d.get("serialnumber", "").strip(),
            "interface": d.get("interfacetype", ""),
            "media": d.get("mediatype", ""),
            "size_gb": size
        })

    # Network (physical with MAC)
    data["network_adapters"] = []
    try:
        cmd = 'wmic nic where "MACAddress is not null AND PhysicalAdapter=TRUE" get Name,MACAddress,PNPDeviceID,AdapterType /format:csv'
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, shell=True,
                                creationflags=CREATE_NO_WINDOW)
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        if len(lines) >= 2:
            headers = [h.strip().lower() for h in lines[0].split(",")]
            for line in lines[1:]:
                vals = line.split(",")
                if len(vals) >= len(headers):
                    entry = {}
                    for i, h in enumerate(headers):
                        if h and h != "node":
                            entry[h] = vals[i].strip() if i < len(vals) else ""
                    data["network_adapters"].append({
                        "name": entry.get("name", ""),
                        "mac": entry.get("macaddress", ""),
                        "pnp": entry.get("pnpdeviceid", ""),
                        "type": entry.get("adaptertype", "")
                    })
    except Exception:
        pass

    # GPU
    gpus = _wmic_query("path win32_videocontroller", ["Name", "PNPDeviceID", "DriverVersion"])
    data["gpus"] = [{"name": g.get("name", ""), "pnp": g.get("pnpdeviceid", ""),
                      "driver": g.get("driverversion", "")} for g in gpus]

    # RAM
    rams = _wmic_query("memorychip", ["BankLabel", "SerialNumber", "Capacity", "Manufacturer"])
    data["ram_modules"] = []
    for r in rams:
        cap = 0
        try:
            cap = round(int(r.get("capacity", 0)) / (1024**3), 1)
        except (ValueError, TypeError):
            pass
        data["ram_modules"].append({
            "bank": r.get("banklabel", ""),
            "serial": r.get("serialnumber", "").strip(),
            "capacity_gb": cap,
            "manufacturer": r.get("manufacturer", "")
        })

    # Volumes (fixed disks)
    vols = _wmic_query("logicaldisk where drivetype=3", ["DeviceID", "VolumeSerialNumber", "VolumeName"])
    data["volumes"] = [{"drive": v.get("deviceid", ""), "serial": v.get("volumeserialnumber", ""),
                         "name": v.get("volumename", "")} for v in vols]

    # TPM
    data["tpm_manufacturer"] = None
    data["tpm_version"] = None

    return data


def _get_machine_sid():
    """Get the machine SID prefix from a local user account."""
    try:
        result = subprocess.run(
            ["wmic", "useraccount", "where", "LocalAccount=True", "get", "SID", "/value"],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW
        )
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line.startswith("SID=S-"):
                sid = line.split("=", 1)[1].strip()
                # Remove the last -RID part to get the machine SID
                parts = sid.rsplit("-", 1)
                if len(parts) == 2:
                    return parts[0]
                return sid
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Classification Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize(val):
    """Normalize a value: strip whitespace, replace blanks/OEM placeholders with (empty)."""
    if val is None:
        return "(empty)"
    if isinstance(val, str):
        val = val.strip()
        if not val or val.lower() in ("to be filled by o.e.m.", "default string",
                                       "not available", "none", "n/a", "system serial number",
                                       "system manufacturer", "to be filled by o.e.m"):
            return "(empty)"
    return val


def _classify_adapters(adapters):
    """Split network adapters by PNP prefix into physical/usb/virtual."""
    physical, usb, virtual = [], [], []
    for a in (adapters or []):
        pnp = (a.get("pnp") or "").upper()
        entry = {
            "name": a.get("name", ""),
            "mac": a.get("mac", ""),
            "pnp": a.get("pnp", ""),
            "type": a.get("type", "")
        }
        if pnp.startswith("PCI"):
            physical.append(entry)
        elif pnp.startswith("USB"):
            usb.append(entry)
        else:
            virtual.append(entry)
    return physical, usb, virtual


def _classify_disks(disks):
    """Split disks into internal and removable."""
    internal, removable = [], []
    for d in (disks or []):
        iface = (d.get("interface") or "").upper()
        media = (d.get("media") or "").lower()
        entry = {
            "model": d.get("model", ""),
            "serial": d.get("serial", "").strip(),
            "interface": d.get("interface", ""),
            "size_gb": d.get("size_gb", 0)
        }
        if iface == "USB" or "removable" in media:
            removable.append(entry)
        else:
            internal.append(entry)
    return internal, removable


def _is_mac_randomized(mac):
    """Check if a MAC address has the locally-administered bit set."""
    if not mac:
        return False
    first_octet = mac.split(":")[0] if ":" in mac else mac.split("-")[0]
    try:
        val = int(first_octet, 16)
        return bool(val & 0x02)  # bit 1 = locally administered
    except ValueError:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Snapshot Collection
# ─────────────────────────────────────────────────────────────────────────────

def collect_hwid_snapshot():
    """Collect all HWID components into a snapshot dict."""
    print(dim("  Collecting HWID components..."))

    components = {}

    # 1. Registry reads
    print(dim("    Reading registry..."))
    reg = _get_registry_values()
    components["machine_guid"] = _normalize(reg.get("machine_guid"))
    components["windows_product_id"] = _normalize(reg.get("windows_product_id"))
    components["windows_edition"] = reg.get("windows_edition", "")
    components["windows_build"] = reg.get("windows_build", "")
    components["windows_install_date"] = reg.get("windows_install_date", "")

    # 2. PowerShell batch (or fallback)
    print(dim("    Querying WMI (this may take a few seconds)..."))
    wmi = _run_powershell_batch()
    if wmi is None:
        wmi = _fallback_wmi_collect()

    # Scalars
    components["cpu_id"] = _normalize(wmi.get("cpu_id"))
    components["cpu_name"] = _normalize(wmi.get("cpu_name"))
    components["motherboard_serial"] = _normalize(wmi.get("motherboard_serial"))
    components["motherboard_manufacturer"] = _normalize(wmi.get("motherboard_manufacturer"))
    components["motherboard_product"] = _normalize(wmi.get("motherboard_product"))
    components["bios_serial"] = _normalize(wmi.get("bios_serial"))
    components["bios_version"] = _normalize(wmi.get("bios_version"))
    components["system_uuid"] = _normalize(wmi.get("system_uuid"))
    components["tpm_manufacturer"] = _normalize(wmi.get("tpm_manufacturer"))
    components["tpm_version"] = _normalize(wmi.get("tpm_version"))

    # Classify disks
    internal_disks, removable_disks = _classify_disks(wmi.get("disk_drives", []))
    components["disk_drives_internal"] = sorted(internal_disks, key=lambda d: d.get("serial", ""))
    components["disk_drives_removable"] = sorted(removable_disks, key=lambda d: d.get("serial", ""))

    # Classify network adapters
    phys_nics, usb_nics, virt_nics = _classify_adapters(wmi.get("network_adapters", []))
    components["network_adapters_physical"] = sorted(phys_nics, key=lambda n: n.get("mac", ""))
    components["network_adapters_usb"] = sorted(usb_nics, key=lambda n: n.get("mac", ""))
    components["network_adapters_virtual"] = sorted(virt_nics, key=lambda n: n.get("mac", ""))

    # GPUs
    components["gpu_devices"] = sorted(wmi.get("gpus", []), key=lambda g: g.get("name", ""))

    # RAM
    components["ram_modules"] = sorted(wmi.get("ram_modules", []), key=lambda r: r.get("bank", ""))

    # Volumes
    components["volume_serials"] = sorted(wmi.get("volumes", []), key=lambda v: v.get("drive", ""))

    # 3. Python-native
    print(dim("    Reading system info..."))
    components["computer_name"] = socket.gethostname()
    components["machine_sid"] = _get_machine_sid() or "(unavailable)"

    # Build fingerprint
    fp_str = json.dumps(components, sort_keys=True, default=str)
    fingerprint = hashlib.sha256(fp_str.encode()).hexdigest()[:16]

    snapshot = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "fingerprint": fingerprint,
        "components": components
    }

    print(dim("  Done.\n"))
    return snapshot

# ─────────────────────────────────────────────────────────────────────────────
# Log File I/O
# ─────────────────────────────────────────────────────────────────────────────

def load_log(path):
    """Load the log file. Returns a list of snapshots."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except (json.JSONDecodeError, IOError) as e:
        # Backup corrupt log
        backup = path + ".bak"
        print(yellow(f"  [WARN] Log file corrupt ({e}). Backed up to {backup}"))
        try:
            os.replace(path, backup)
        except OSError:
            pass
    return []


def save_log(path, entries):
    """Save the log file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entries, f, indent=2, default=str)
    except IOError as e:
        print(red(f"  [ERROR] Could not save log: {e}"))

# ─────────────────────────────────────────────────────────────────────────────
# Diff Engine
# ─────────────────────────────────────────────────────────────────────────────

LIST_MERGE_KEYS = {
    "disk_drives_internal": "serial",
    "disk_drives_removable": "serial",
    "network_adapters_physical": "mac",
    "network_adapters_usb": "mac",
    "network_adapters_virtual": "mac",
    "gpu_devices": "name",
    "ram_modules": "bank",
    "volume_serials": "drive",
}


def _diff_lists(old_list, new_list, field_name):
    """Diff two lists of dicts using a merge key."""
    merge_key = LIST_MERGE_KEYS.get(field_name, None)
    details = {"added": [], "removed": [], "changed": []}

    if merge_key is None:
        # Simple equality
        if old_list != new_list:
            details["changed"] = [{"old": old_list, "new": new_list}]
        return details

    old_map = {item.get(merge_key, f"_idx_{i}"): item for i, item in enumerate(old_list)}
    new_map = {item.get(merge_key, f"_idx_{i}"): item for i, item in enumerate(new_list)}

    all_keys = set(old_map.keys()) | set(new_map.keys())
    for k in sorted(all_keys):
        if k in old_map and k not in new_map:
            details["removed"].append(old_map[k])
        elif k not in old_map and k in new_map:
            details["added"].append(new_map[k])
        elif old_map[k] != new_map[k]:
            details["changed"].append({"key": k, "old": old_map[k], "new": new_map[k]})

    return details


def diff_snapshots(old_components, new_components):
    """Compare two component dicts. Returns list of changes."""
    changes = []
    all_keys = sorted(set(old_components.keys()) | set(new_components.keys()))

    for key in all_keys:
        old_val = old_components.get(key)
        new_val = new_components.get(key)

        if old_val == new_val:
            continue

        if isinstance(old_val, list) and isinstance(new_val, list):
            details = _diff_lists(old_val, new_val, key)
            if details["added"] or details["removed"] or details["changed"]:
                changes.append({
                    "field": key,
                    "type": "list_change",
                    "details": details
                })
        else:
            changes.append({
                "field": key,
                "type": "value_change",
                "old": old_val,
                "new": new_val
            })

    return changes

# ─────────────────────────────────────────────────────────────────────────────
# Report Formatting
# ─────────────────────────────────────────────────────────────────────────────

SEPARATOR = "=" * 80
THIN_SEP = "-" * 80


def _pad_label(label, width=28):
    dots = "." * max(2, width - len(label))
    return f"  {label} {dots}"


def _format_item_summary(item, kind):
    """One-line summary of a list item."""
    if kind.startswith("disk_drives"):
        return f"{item.get('model', '?')} | Serial: {item.get('serial', '?')} | {item.get('interface', '?')} | {item.get('size_gb', 0)} GB"
    elif kind.startswith("network_adapters"):
        return f"{item.get('name', '?')} | MAC: {item.get('mac', '?')}"
    elif kind == "gpu_devices":
        return f"{item.get('name', '?')} (driver {item.get('driver', '?')})"
    elif kind == "ram_modules":
        return f"{item.get('bank', '?')} | Serial: {item.get('serial', '?')} | {item.get('capacity_gb', 0)} GB | {item.get('manufacturer', '')}"
    elif kind == "volume_serials":
        return f"{item.get('drive', '?')} = {item.get('serial', '?')} ({item.get('name', '')})"
    return str(item)


def format_report(snapshot, changes, prev_timestamp, is_first_run):
    """Format the full console report."""
    comp = snapshot["components"]
    lines = []

    lines.append("")
    lines.append(bold(SEPARATOR))
    lines.append(bold(f"{'HWID MONITOR - Snapshot Report':^80}"))
    lines.append(bold(f"{snapshot['timestamp']:^80}"))
    lines.append(bold(SEPARATOR))
    lines.append("")

    # ── System Identifiers ──
    lines.append(bold(cyan("  SYSTEM IDENTIFIERS (should never change)")))
    lines.append(f"  {THIN_SEP[2:]}")
    lines.append(f"{_pad_label('CPU ID')} {comp.get('cpu_id', '?')}")
    lines.append(f"{_pad_label('CPU Name')} {comp.get('cpu_name', '?')}")
    lines.append(f"{_pad_label('Motherboard')} {comp.get('motherboard_manufacturer', '')} {comp.get('motherboard_product', '')}")
    lines.append(f"{_pad_label('Motherboard Serial')} {comp.get('motherboard_serial', '?')}")
    lines.append(f"{_pad_label('BIOS Serial')} {comp.get('bios_serial', '?')}")
    lines.append(f"{_pad_label('BIOS Version')} {comp.get('bios_version', '?')}")
    lines.append(f"{_pad_label('System UUID')} {comp.get('system_uuid', '?')}")
    lines.append(f"{_pad_label('Machine GUID')} {comp.get('machine_guid', '?')}")
    lines.append(f"{_pad_label('Windows Product ID')} {comp.get('windows_product_id', '?')}")
    lines.append(f"{_pad_label('Windows Edition')} {comp.get('windows_edition', '?')}")
    lines.append(f"{_pad_label('Windows Build')} {comp.get('windows_build', '?')}")
    lines.append(f"{_pad_label('Windows Install Date')} {comp.get('windows_install_date', '?')}")
    lines.append(f"{_pad_label('Machine SID')} {comp.get('machine_sid', '?')}")
    lines.append(f"{_pad_label('Computer Name')} {comp.get('computer_name', '?')}")
    tpm = comp.get("tpm_manufacturer")
    if tpm and tpm != "(empty)":
        lines.append(f"{_pad_label('TPM')} {tpm} (spec {comp.get('tpm_version', '?')})")
    else:
        lines.append(f"{_pad_label('TPM')} Not detected")
    lines.append("")

    # ── Hardware ──
    lines.append(bold(cyan("  HARDWARE")))
    lines.append(f"  {THIN_SEP[2:]}")
    for i, ram in enumerate(comp.get("ram_modules", []), 1):
        lines.append(f"{_pad_label(f'RAM Module {i}')} {ram.get('bank', '?')} | {ram.get('serial', '?')} | {ram.get('capacity_gb', 0)} GB | {ram.get('manufacturer', '')}")
    for i, gpu in enumerate(comp.get("gpu_devices", []), 1):
        lines.append(f"{_pad_label(f'GPU {i}')} {gpu.get('name', '?')} (driver {gpu.get('driver', '?')})")
    lines.append("")

    # ── Storage Internal ──
    lines.append(bold(cyan("  STORAGE - Internal")))
    lines.append(f"  {THIN_SEP[2:]}")
    for i, disk in enumerate(comp.get("disk_drives_internal", []), 1):
        lines.append(f"{_pad_label(f'Disk {i}')} {disk.get('model', '?')} | Serial: {disk.get('serial', '?')} | {disk.get('interface', '?')} | {disk.get('size_gb', 0)} GB")
    for vol in comp.get("volume_serials", []):
        drive_letter = vol.get('drive', '?')
        lines.append(f"{_pad_label(f'Volume {drive_letter}')} {vol.get('serial', '?')} ({vol.get('name', '')})")
    lines.append("")

    # ── Storage Removable ──
    removable = comp.get("disk_drives_removable", [])
    if removable:
        lines.append(bold(yellow("  STORAGE - Removable (may vary)")))
        lines.append(f"  {THIN_SEP[2:]}")
        for i, disk in enumerate(removable, 1):
            lines.append(f"{_pad_label(f'Disk {i}')} {disk.get('model', '?')} | Serial: {disk.get('serial', '?')} | {disk.get('interface', '?')}")
        lines.append("")

    # ── Network Physical ──
    phys = comp.get("network_adapters_physical", [])
    if phys:
        lines.append(bold(cyan("  NETWORK - Physical Hardware (PCI bus)")))
        lines.append(f"  {THIN_SEP[2:]}")
        for i, nic in enumerate(phys, 1):
            line = f"{_pad_label(f'NIC {i}')} {nic.get('name', '?')} | MAC: {nic.get('mac', '?')}"
            lines.append(line)
            if _is_mac_randomized(nic.get("mac", "")):
                lines.append(yellow(f"{'':>32}[!] MAC has locally-administered bit set (possibly randomized)"))
        lines.append("")

    # ── Network USB ──
    usb_nics = comp.get("network_adapters_usb", [])
    if usb_nics:
        lines.append(bold(cyan("  NETWORK - USB Adapters")))
        lines.append(f"  {THIN_SEP[2:]}")
        for i, nic in enumerate(usb_nics, 1):
            lines.append(f"{_pad_label(f'NIC {i}')} {nic.get('name', '?')} | MAC: {nic.get('mac', '?')}")
        lines.append("")

    # ── Network Virtual ──
    virt = comp.get("network_adapters_virtual", [])
    if virt:
        lines.append(bold(yellow(f"  NETWORK - Virtual Adapters ({len(virt)} adapters)")))
        lines.append(f"  {THIN_SEP[2:]}")
        for i, nic in enumerate(virt, 1):
            lines.append(dim(f"{_pad_label(f'vNIC {i}')} {nic.get('name', '?')} | MAC: {nic.get('mac', '?')}"))
        lines.append("")

    # ── Comparison ──
    lines.append(bold(SEPARATOR))
    if is_first_run:
        lines.append(bold(green(f"{'FIRST RUN - Baseline Recorded':^80}")))
        lines.append(bold(green(f"{'Run again to compare against this baseline.':^80}")))
    elif not changes:
        header = f"COMPARISON WITH PREVIOUS RUN ({prev_timestamp})"
        lines.append(bold(green(f"{header:^80}")))
        lines.append("")
        lines.append(green(f"  Overall Fingerprint .. UNCHANGED ({snapshot['fingerprint']})"))
        lines.append("")
        lines.append(green("  [OK] No changes detected. All HWID components are identical."))
    else:
        lines.append(bold(red(f"  COMPARISON WITH PREVIOUS RUN ({prev_timestamp})")))
        lines.append(bold(SEPARATOR))
        lines.append("")
        lines.append(red(f"  Overall Fingerprint .. CHANGED"))
        lines.append("")

        unchanged_fields = []
        for ch in changes:
            field = ch["field"]
            if ch["type"] == "value_change":
                lines.append(red(f"  [!!] CHANGE: {field}"))
                lines.append(f"       Old: {ch['old']}")
                lines.append(f"       New: {ch['new']}")
                lines.append("")
            elif ch["type"] == "list_change":
                det = ch["details"]
                lines.append(red(f"  [!!] CHANGE: {field}"))
                for item in det.get("added", []):
                    lines.append(yellow(f"       + ADDED: {_format_item_summary(item, field)}"))
                for item in det.get("removed", []):
                    lines.append(yellow(f"       - REMOVED: {_format_item_summary(item, field)}"))
                for item in det.get("changed", []):
                    lines.append(yellow(f"       ~ MODIFIED (key={item.get('key', '?')}):"))
                    lines.append(f"         Old: {item.get('old', '?')}")
                    lines.append(f"         New: {item.get('new', '?')}")
                lines.append("")

        # List unchanged
        changed_fields = {ch["field"] for ch in changes}
        all_fields = sorted(comp.keys())
        unchanged_fields = [f for f in all_fields if f not in changed_fields]
        if unchanged_fields:
            lines.append(green(f"  [OK] No changes in: {', '.join(unchanged_fields)}"))
            lines.append("")

        # ── Stability Assessment ──
        lines.append(bold(SEPARATOR))
        lines.append(bold(f"{'STABILITY ASSESSMENT':^80}"))
        lines.append(bold(SEPARATOR))
        lines.append("")

        core_fields = {"cpu_id", "motherboard_serial", "bios_serial", "system_uuid",
                        "machine_guid", "windows_product_id", "machine_sid", "computer_name"}
        storage_fields = {"disk_drives_internal", "volume_serials"}
        net_fields = {"network_adapters_physical", "network_adapters_usb", "network_adapters_virtual"}
        hw_fields = {"ram_modules", "gpu_devices"}

        core_stable = not (changed_fields & core_fields)
        storage_stable = not (changed_fields & storage_fields)
        net_stable = not (changed_fields & net_fields)
        hw_stable = not (changed_fields & hw_fields)

        lines.append(f"  Core IDs (CPU/MB/BIOS/UUID/GUID) ....... {green('STABLE') if core_stable else red('UNSTABLE')}")
        lines.append(f"  Hardware (RAM/GPU) ..................... {green('STABLE') if hw_stable else red('UNSTABLE')}")
        lines.append(f"  Storage (internal disks/volumes) ....... {green('STABLE') if storage_stable else red('UNSTABLE')}")
        lines.append(f"  Network (all adapters) ................. {green('STABLE') if net_stable else red('UNSTABLE')}")
        lines.append("")

        # Likely cause hints
        if not net_stable and core_stable and storage_stable:
            only_virtual = changed_fields & net_fields == {"network_adapters_virtual"}
            if only_virtual:
                lines.append(yellow("  LIKELY CAUSE: Virtual network adapter changes (Hyper-V/VMware/VPN)."))
                lines.append(yellow("  These change with VM activity and VPN connections."))
            else:
                lines.append(yellow("  LIKELY CAUSE: Network adapter changes."))
            lines.append(yellow("  If the software fingerprints MAC addresses, this is likely the trigger."))
            lines.append("")

        if "disk_drives_removable" in changed_fields and storage_stable:
            lines.append(yellow("  NOTE: Only removable/USB drives changed. Core storage is stable."))
            lines.append("")

        if "gpu_devices" in changed_fields:
            lines.append(yellow("  NOTE: GPU list changed. Virtual display adapters may appear/disappear."))
            lines.append("")

    lines.append(bold(SEPARATOR))
    lines.append(f"  Fingerprint: {snapshot['fingerprint']}  |  Logged to: {os.path.basename(DEFAULT_LOG_PATH)}")
    lines.append(bold(SEPARATOR))
    lines.append("")

    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# Export (for support tickets)
# ─────────────────────────────────────────────────────────────────────────────

def export_report(snapshot, changes, prev_timestamp, export_path):
    """Export a JSON report suitable for sending to support."""
    report = {
        "tool": "HWID Monitor & Logger",
        "generated": snapshot["timestamp"],
        "fingerprint": snapshot["fingerprint"],
        "components": snapshot["components"],
        "comparison": {
            "compared_to": prev_timestamp if prev_timestamp else "N/A (first run)",
            "changes_detected": len(changes),
            "changes": []
        }
    }
    for ch in changes:
        entry = {"field": ch["field"], "type": ch["type"]}
        if ch["type"] == "value_change":
            entry["old_value"] = ch["old"]
            entry["new_value"] = ch["new"]
        elif ch["type"] == "list_change":
            entry["details"] = ch["details"]
        report["comparison"]["changes"].append(entry)

    try:
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(green(f"\n  Exported report to: {export_path}"))
    except IOError as e:
        print(red(f"\n  [ERROR] Could not export: {e}"))

# ─────────────────────────────────────────────────────────────────────────────
# History View
# ─────────────────────────────────────────────────────────────────────────────

def show_history(log_entries, count):
    """Show the last N log entries as a summary table."""
    entries = log_entries[-count:] if count < len(log_entries) else log_entries

    print(f"\n{bold(SEPARATOR)}")
    print(bold(f"{'HWID LOG HISTORY':^80}"))
    print(bold(f"{'Showing last ' + str(len(entries)) + ' of ' + str(len(log_entries)) + ' entries':^80}"))
    print(bold(SEPARATOR))
    print(f"\n  {'#':<5} {'Timestamp':<22} {'Fingerprint':<20} {'Status'}")
    print(f"  {'-'*5} {'-'*22} {'-'*20} {'-'*25}")

    for i, entry in enumerate(entries):
        idx = len(log_entries) - len(entries) + i + 1
        ts = entry.get("timestamp", "?")
        fp = entry.get("fingerprint", "?")

        if i == 0 and idx == 1:
            status = dim("(baseline)")
        elif i > 0:
            prev_fp = entries[i - 1].get("fingerprint", "")
            if fp == prev_fp:
                status = green("No change")
            else:
                status = red("CHANGED")
        else:
            # First in this view but not first overall
            status = dim("(no previous in view)")

        print(f"  {idx:<5} {ts:<22} {fp:<20} {status}")

    print(f"\n{SEPARATOR}\n")

# ─────────────────────────────────────────────────────────────────────────────
# Task Scheduler
# ─────────────────────────────────────────────────────────────────────────────

def install_scheduled_task(log_path):
    """Create a Windows Task Scheduler task to run every 30 minutes."""
    script_path = os.path.abspath(sys.argv[0])

    # Find python executable
    python_exe = sys.executable
    if not python_exe:
        python_exe = "python"

    # If running as .exe, run the exe directly
    if script_path.endswith(".exe"):
        tr = f'"{script_path}" --log-path "{log_path}"'
    else:
        tr = f'"{python_exe}" "{script_path}" --log-path "{log_path}"'

    cmd = [
        "schtasks", "/Create",
        "/SC", "MINUTE",
        "/MO", "30",
        "/TN", TASK_NAME,
        "/TR", tr,
        "/F"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                creationflags=CREATE_NO_WINDOW)
        if result.returncode == 0:
            print(green(f"\n  Task '{TASK_NAME}' created successfully."))
            print(f"  It will run every 30 minutes and log to: {log_path}")
            print(f"  To remove: python {os.path.basename(script_path)} --uninstall-task\n")
        else:
            print(red(f"\n  [ERROR] Failed to create task. Try running as Administrator."))
            print(f"  {result.stderr.strip()}\n")
    except Exception as e:
        print(red(f"\n  [ERROR] {e}"))


def uninstall_scheduled_task():
    """Remove the Windows Task Scheduler task."""
    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"],
            capture_output=True, text=True, timeout=15,
            creationflags=CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            print(green(f"\n  Task '{TASK_NAME}' removed successfully.\n"))
        else:
            print(yellow(f"\n  Task '{TASK_NAME}' not found or already removed.\n"))
    except Exception as e:
        print(red(f"\n  [ERROR] {e}"))

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HWID Monitor & Logger - Track hardware ID changes over time.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hwid_monitor.py                        Full report + log
  python hwid_monitor.py --export report.json   Export snapshot for support
  python hwid_monitor.py --history 10           Show last 10 log entries
  python hwid_monitor.py --install-task         Schedule auto-run every 30 min
  python hwid_monitor.py --uninstall-task       Remove scheduled task
        """
    )
    parser.add_argument("--log-path", default=DEFAULT_LOG_PATH,
                        help=f"Path to JSON log file (default: {DEFAULT_LOG_PATH})")
    parser.add_argument("--export", metavar="FILE",
                        help="Export current snapshot to a JSON file (for support)")
    parser.add_argument("--history", type=int, metavar="N",
                        help="Show last N entries from the log")
    parser.add_argument("--quiet", action="store_true",
                        help="Only output if changes are detected")
    parser.add_argument("--install-task", action="store_true",
                        help="Create a Task Scheduler task to run every 30 minutes")
    parser.add_argument("--uninstall-task", action="store_true",
                        help="Remove the scheduled task")

    args = parser.parse_args()

    # Task management (no snapshot needed)
    if args.install_task:
        install_scheduled_task(args.log_path)
        return
    if args.uninstall_task:
        uninstall_scheduled_task()
        return

    # History view
    if args.history:
        log_entries = load_log(args.log_path)
        if not log_entries:
            print(yellow("\n  No log entries found. Run the tool first to create a baseline.\n"))
        else:
            show_history(log_entries, args.history)
        return

    # ── Main flow: collect, compare, log, report ──

    # Collect
    snapshot = collect_hwid_snapshot()

    # Load previous log
    log_entries = load_log(args.log_path)
    is_first_run = len(log_entries) == 0

    # Compare
    changes = []
    prev_timestamp = None
    if not is_first_run:
        prev = log_entries[-1]
        prev_timestamp = prev.get("timestamp", "?")
        changes = diff_snapshots(prev.get("components", {}), snapshot["components"])

    # Append and save
    log_entries.append(snapshot)
    save_log(args.log_path, log_entries)

    # Report
    if not args.quiet or changes or is_first_run:
        report = format_report(snapshot, changes, prev_timestamp, is_first_run)
        print(report)

    # Export
    if args.export:
        export_report(snapshot, changes, prev_timestamp, args.export)

    # Exit code: 0 = no changes (or first run), 1 = changes detected
    sys.exit(1 if changes else 0)


if __name__ == "__main__":
    main()
