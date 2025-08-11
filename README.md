# Little-or-Big
#!/usr/bin/env python3
"""
install_service.py

Installs a Windows service that:
 - Performs basic system hardening on install
 - Monitors processes and filesystem for unsigned/invalid Authenticode PE files
 - Logs to Windows Event Log and local log file
 - Configures service auto-start and recovery actions

USAGE (Admin):
  python install_service.py --install
  python install_service.py --uninstall
  python install_service.py run          # run in foreground for testing
"""
import os
import sys
import time
import shutil
import logging
import sqlite3
import subprocess
import threading
from pathlib import Path

# third-party / pywin32
try:
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    import win32evtlogutil
    import win32evtlog
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except Exception as e:
    print("Missing dependency:", e)
    print("Install with: pip install pywin32 watchdog psutil")
    sys.exit(1)

# ctypes for WinVerifyTrust
import ctypes
from ctypes import wintypes
from uuid import UUID

# ---------- CONFIG ----------
SERVICE_NAME = "WinSecurityAgent"
SERVICE_DISPLAY = "Windows Security Agent"
APP_NAME = SERVICE_NAME
DB_PATH = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "WinProtector" / "signatures.db"
QUARANTINE_DIR = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "WinProtector" / "quarantine"
LOG_FILE = Path(os.getenv("ProgramData", r"C:\ProgramData")) / "WinProtector" / "install_service.log"
WATCH_PATH = str(Path.home())  # default watch user profile for creation of suspicious files
PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}
os.makedirs(DB_PATH.parent, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)
logging.basicConfig(filename=str(LOG_FILE), level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# ---------- Event Log helper ----------
def report_event(message, event_type=servicemanager.EVENTLOG_INFORMATION_TYPE):
    try:
        win32evtlogutil.ReportEvent(APP_NAME, 0, eventCategory=0, eventType=event_type, strings=[message])
    except Exception as e:
        logging.exception("report_event failed: %s", e)
    logging.info(message)

# ---------- Hardening helpers ----------
def run_checked(cmd_list):
    logging.info("RUN: %s", cmd_list)
    subprocess.check_call(cmd_list, shell=False)

def perform_hardening():
    logging.info("Starting system hardening")
    try:
        # Disable SMBv1
        run_checked(["powershell", "-Command", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"])
        # Enable Firewall
        run_checked(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
        # Ensure Defender realtime monitoring is enabled (best-effort)
        run_checked(["powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"])
        # Set password min length example
        run_checked(["net", "accounts", "/minpwlen:12"])
        # Enable Logon auditing
        run_checked(["auditpol", "/set", "/subcategory:Logon", "/success:enable", "/failure:enable"])

        report_event("System hardening completed successfully.", servicemanager.EVENTLOG_INFORMATION_TYPE)
    except Exception as e:
        report_event(f"System hardening failed: {e}", servicemanager.EVENTLOG_ERROR_TYPE)
        logging.exception("Hardening failed: %s", e)

# ---------- Service hardening: recovery & autostart & ACLs ----------
def set_service_autostart(service_name):
    try:
        run_checked(["sc", "config", service_name, "start=", "auto"])
        logging.info("Service %s set to auto-start", service_name)
    except Exception as e:
        logging.exception("Failed to set autostart: %s", e)

def set_service_recovery(service_name, restart_ms=60000, reset_period_seconds=86400):
    try:
        actions = f"restart/{restart_ms}/restart/{restart_ms}/restart/{restart_ms}"
        run_checked(["sc", "failure", service_name, f"reset= {reset_period_seconds}", f"actions= {actions}"])
        run_checked(["sc", "failureflag", service_name, "1"])
        logging.info("Service recovery configured for %s", service_name)
    except Exception as e:
        logging.exception("Failed to set service recovery: %s", e)

def protect_path_with_icacls(path, grant_users_read=True):
    p = Path(path)
    if not p.exists():
        logging.warning("Path not found for ACL hardening: %s", p)
        return
    try:
        run_checked(["icacls", str(p), "/inheritance:r"])
        run_checked(["icacls", str(p), "/grant", "SYSTEM:(F)"])
        run_checked(["icacls", str(p), "/grant", "Administrators:(F)"])
        if grant_users_read:
            run_checked(["icacls", str(p), "/grant", "Users:(RX)"])
        logging.info("ACLs hardened on %s", p)
    except Exception as e:
        logging.exception("Failed ACL hardening on %s: %s", p, e)

# ---------- Quarantine ----------
def quarantine_file(path):
    p = Path(path)
    if not p.exists():
        return None
    target = QUARANTINE_DIR / f"{int(time.time())}_{p.name}"
    try:
        shutil.move(str(p), str(target))
        report_event(f"Quarantined {p} -> {target}", servicemanager.EVENTLOG_WARNING_TYPE)
        logging.warning("Quarantined %s -> %s", p, target)
        return target
    except Exception as e:
        logging.exception("Failed to quarantine %s: %s", p, e)
        return None

# ---------- Authenticode (WinVerifyTrust) ----------
# Based on WinTrust API usage. Returns (bool, message)
WinVerifyTrust = ctypes.windll.wintrust.WinVerifyTrust
WINTRUST_ACTION_GENERIC_VERIFY_V2 = UUID('{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}')

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0x00000000
WTD_CHOICE_FILE = 1
ERROR_SUCCESS = 0

class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", wintypes.LPVOID)
    ]

class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", wintypes.LPVOID)
    ]

def check_authenticode(file_path):
    """
    Return (True, 'valid_signature') when WinVerifyTrust returns ERROR_SUCCESS.
    Otherwise return (False, 'code_xxx' or exception text).
    Only attempt for common PE extensions.
    """
    try:
        p = Path(file_path)
        if p.suffix.lower() not in PE_EXTS:
            return (False, "not_pe_extension")
        wfi = WINTRUST_FILE_INFO()
        wfi.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        wfi.pcwszFilePath = ctypes.c_wchar_p(str(p))
        wfi.hFile = None
        wfi.pgKnownSubject = None
        wfi_p = ctypes.pointer(wfi)

        wtd = WINTRUST_DATA()
        ctypes.memset(ctypes.addressof(wtd), 0, ctypes.sizeof(wtd))
        wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = WTD_UI_NONE
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE
        wtd.dwUnionChoice = WTD_CHOICE_FILE
        wtd.pFile = wfi_p
        wtd.dwProvFlags = 0x00000020  # minimal flags

        guid = ctypes.c_buffer(WINTRUST_ACTION_GENERIC_VERIFY_V2.bytes_le)
        res = WinVerifyTrust(0, guid, ctypes.byref(wtd))
        if res == ERROR_SUCCESS:
            return (True, "valid_signature")
        else:
            return (False, f"WinVerifyTrust_return_{res}")
    except Exception as e:
        logging.exception("check_authenticode exception for %s: %s", file_path, e)
        return (False, f"auth_check_error:{e}")

# ---------- DB for known bad hashes (simple) ----------
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY,
            sha256 TEXT UNIQUE,
            name TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn

# ---------- Heuristics & monitors ----------
SUSPICIOUS_LOC_KEYWORDS = ("temp", "appdata", "local", "temp", "cache")

def is_suspicious_path(path):
    parts = [p.lower() for p in Path(path).parts]
    return any(k in parts for k in SUSPICIOUS_LOC_KEYWORDS)

def sha256_of_file(path, chunk_size=8192):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def handle_unsigned_pe(path, conn, auto_quarantine=True):
    # Log, optionally quarantine and store in DB? (we store event)
    signed, msg = check_authenticode(path)
    if signed:
        logging.info("PE signed and valid: %s", path)
        return
    reason = f"unsigned_or_invalid:{msg}"
    report_event(f"Unsigned/invalid PE detected: {path} ({msg})", servicemanager.EVENTLOG_WARNING_TYPE)
    logging.warning("Unsigned PE: %s (%s)", path, msg)
    if is_suspicious_path(path) and auto_quarantine:
        quarantine_file(path)

# Process monitor: check new processes' exe signature
def process_monitor_loop(stop_event, conn, interval=5):
    seen = set()
    while not stop_event.is_set():
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid")
                exe = info.get("exe")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if not exe or not Path(exe).exists():
                continue
            key = (pid, exe)
            if key in seen:
                continue
            seen.add(key)
            # Check PE signature if extension matches
            if Path(exe).suffix.lower() in PE_EXTS:
                signed, msg = check_authenticode(exe)
                if not signed:
                    report_event(f"New process with unsigned/invalid signature: {exe} (pid={pid}) -> {msg}",
                                 servicemanager.EVENTLOG_WARNING_TYPE)
                    logging.warning("New process unsigned: %s pid=%s msg=%s", exe, pid, msg)
                    if is_suspicious_path(exe):
                        quarantine_file(exe)
        stop_event.wait(interval)

# FS watcher: on created file check signature for PE
class PECreateHandler(FileSystemEventHandler):
    def __init__(self, conn):
        self.conn = conn
    def on_created(self, event):
        if event.is_directory:
            return
        p = Path(event.src_path)
        if p.suffix.lower() in PE_EXTS:
            # small delay to allow file write completion
            time.sleep(0.5)
            handle_unsigned_pe(str(p), self.conn)

def start_watcher(stop_event, conn, path=WATCH_PATH):
    handler = PECreateHandler(conn)
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    try:
        while not stop_event.is_set():
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

# ---------- Windows Service wrapper ----------
class SecurityAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY
    _svc_description_ = "Monitors processes and files for unsigned/invalid Authenticode binaries."

    def __init__(self, args):
        super().__init__(args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_event = threading.Event()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} starting")
        report_event(f"{SERVICE_NAME} starting", servicemanager.EVENTLOG_INFORMATION_TYPE)
        conn = init_db()
        # start monitor threads
        t_proc = threading.Thread(target=process_monitor_loop, args=(self.stop_event, conn, 5), daemon=True)
        t_proc.start()
        try:
            start_watcher(self.stop_event, conn, WATCH_PATH)
        except Exception as e:
            logging.exception("Watcher error: %s", e)
        servicemanager.LogInfoMsg(f"{SERVICE_NAME} stopped")
        report_event(f"{SERVICE_NAME} stopped", servicemanager.EVENTLOG_INFORMATION_TYPE)

# ---------- Installer logic ----------
def install_service():
    logging.info("Installing service...")
    # perform hardening first
    perform_hardening()

    # install service via pywin32 helper (the service class is in this file)
    # Note: HandleCommandLine can install, but we want explicit control.
    try:
        # Register the EVENT source if possible (best-effort)
        try:
            win32evtlogutil.AddSourceToRegistry(APP_NAME, msgDLL=None)
        except Exception:
            pass

        # Install service
        win32serviceutil.InstallService(
            pythonClassString=f"{__name__}.{SecurityAgentService.__name__}",
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY,
            description="Monitors processes and files for unsigned/invalid Authenticode binaries.",
            startType=win32service.SERVICE_AUTO_START
        )
        # start it
        win32serviceutil.StartService(SERVICE_NAME)
        report_event("Service installed and started", servicemanager.EVENTLOG_INFORMATION_TYPE)
        logging.info("Service installed and started")

        # post-install hardening: set recovery and ACLs
        set_service_autostart(SERVICE_NAME)
        set_service_recovery(SERVICE_NAME)
        # Protect our program files and data directories
        # If you plan to move EXE to Program Files, adjust EXE_PATH accordingly.
        python_exe = sys.executable
        protect_path_with_icacls(python_exe, grant_users_read=True)
        protect_path_with_icacls(DB_PATH, grant_users_read=False)
        protect_path_with_icacls(QUARANTINE_DIR, grant_users_read=False)
        report_event("Post-install hardening complete", servicemanager.EVENTLOG_INFORMATION_TYPE)
    except Exception as e:
        logging.exception("Failed to install service: %s", e)
        report_event(f"Service install failed: {e}", servicemanager.EVENTLOG_ERROR_TYPE)
        raise

def uninstall_service():
    logging.info("Uninstalling service...")
    try:
        try:
            win32serviceutil.StopService(SERVICE_NAME)
        except Exception:
            pass
        win32serviceutil.RemoveService(SERVICE_NAME)
        report_event("Service removed", servicemanager.EVENTLOG_INFORMATION_TYPE)
        logging.info("Service removed")
    except Exception as e:
        logging.exception("Failed to remove service: %s", e)
        report_event(f"Service remove failed: {e}", servicemanager.EVENTLOG_ERROR_TYPE)
        raise

# ---------- CLI ----------
def run_foreground():
    conn = init_db()
    stop_event = threading.Event()
    t = threading.Thread(target=process_monitor_loop, args=(stop_event, conn, 2), daemon=True)
    t.start()
    try:
        start_watcher(stop_event, conn, WATCH_PATH)
    except KeyboardInterrupt:
        stop_event.set()

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--install":
        install_service()
    elif len(sys.argv) == 2 and sys.argv[1] == "--uninstall":
        uninstall_service()
    elif len(sys.argv) == 2 and sys.argv[1] == "run":
        print("Running in foreground (for testing). Ctrl-C to stop.")
        run_foreground()
    else:
        # default behavior for direct pywin32 commands like "install", "remove" if used
        win32serviceutil.HandleCommandLine(SecurityAgentService)
