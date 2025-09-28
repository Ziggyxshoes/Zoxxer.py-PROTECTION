#!/usr/bin/env python3
# zoxxer.py - Zoxxer Advanced Security App (fixed & improved)
# Made by Zoxxer
# Zoxxers on Discord
#
# SECURITY: This tool can delete files (secure overwrite). Only confirm deletions you intend.

from __future__ import annotations

import os
import sys
import time
import json
import shutil
import random
import secrets
import string
import threading
import subprocess
from collections import deque
from datetime import datetime, timedelta
from typing import List, Optional, Callable, Tuple, Dict

# Optional libraries
try:
    from cryptography.fernet import Fernet
    _HAS_CRYPTO = True
except Exception:
    Fernet = None
    _HAS_CRYPTO = False

try:
    import psutil
    _HAS_PSUTIL = True
except Exception:
    psutil = None
    _HAS_PSUTIL = False

# Colorama MUST be initialized before theme dicts are created
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    _HAS_COLOR = True
except Exception:
    _HAS_COLOR = False
    class _Dummy:
        RESET = ""
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    Fore = _Dummy()
    class _DummyStyle:
        BRIGHT = NORMAL = RESET_ALL = ""
    Style = _DummyStyle()

try:
    import pyperclip
    _HAS_PYPERCLIP = True
except Exception:
    pyperclip = None
    _HAS_PYPERCLIP = False

# ---------------------
# Config & constants
# ---------------------
APP_NAME = "Zoxxer"
WATERMARK_1 = "Made by Zoxxer"
WATERMARK_2 = "Zoxxers on Discord"

LOG_FILE = "zoxxer_activity.log"
ENC_LOG_FILE = "zoxxer_activity.log.enc"
FERNET_KEY_FILE = "zoxxer_fernet.key"
CONFIG_FILE = "zoxxer_config.json"
HELPER_FILES = ["ZOXXER_README.txt", "zoxxer_config.json", "zoxxer_firewall_suggestions.txt"]

BACKGROUND_SECONDS = 4.0
BACKGROUND_DELAY = 0.02
OUTPUT_COLLAPSE_TIME = 4.0  # seconds
TAIL_MAX = 400
TAIL_SHOW = 10
THREAT_LIMIT = 120

MENU_OPTIONS = [
    "Privacy & Log Encryption",         # toggle 0
    "Firewall Helper (admin)",          # toggle 1
    "Network Monitor (local)",          # toggle 2
    "Patch/Update Checker",             # action 3
    "Secure Key Generator",             # action 4
    "Secure File Deletion (admin)",     # action 5
    "Theme / Color Settings",           # action 6
    "Download Needed Files",            # action 7
    "Exit"                              # action 8
]
IS_TOGGLE = [True, True, True, False, False, False, False, False, False]
STATES = [False] * len(MENU_OPTIONS)

SUSPICIOUS_KEYWORDS = ["hack", "keylogger", "malware", "trojan", "virus", "inject", "ransom", "crypt", "stealer"]
SUSPICIOUS_EXT = {".exe", ".scr", ".dll", ".bat", ".ps1", ".vbs", ".jar", ".apk", ".dmg"}  # apk/dmg included as suspicious when in user folders

THEMES: Dict[str, Dict[str, str]] = {
    "cyan":    {"accent": Fore.CYAN if _HAS_COLOR else "", "text": Style.BRIGHT if _HAS_COLOR else ""},
    "green":   {"accent": Fore.GREEN if _HAS_COLOR else "", "text": Style.BRIGHT if _HAS_COLOR else ""},
    "yellow":  {"accent": Fore.YELLOW if _HAS_COLOR else "", "text": Style.BRIGHT if _HAS_COLOR else ""},
    "magenta": {"accent": Fore.MAGENTA if _HAS_COLOR else "", "text": Style.BRIGHT if _HAS_COLOR else ""},
    "white":   {"accent": Fore.WHITE if _HAS_COLOR else "", "text": Style.NORMAL if _HAS_COLOR else ""},
}
DEFAULT_THEME = "cyan"
theme_name = DEFAULT_THEME

# tail buffer for right pane
tail = deque(maxlen=TAIL_MAX)
_last_activity = time.time()
_log_lock = threading.RLock()

_fernet = None
_fernet_key: Optional[bytes] = None

# ---------------------
# Utilities
# ---------------------
def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def safe_write(path: str, text: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except Exception as e:
        append_log_plain(f"[file-write-error] {path} -> {e}")
        return False

def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

# ---------------------
# Logging
# ---------------------
def ensure_fernet() -> bool:
    global _fernet, _fernet_key
    if not _HAS_CRYPTO:
        return False
    if _fernet is None:
        try:
            if os.path.exists(FERNET_KEY_FILE):
                _fernet_key = open(FERNET_KEY_FILE, "rb").read()
                _fernet = Fernet(_fernet_key)
            else:
                _fernet_key = Fernet.generate_key()
                _fernet = Fernet(_fernet_key)
                try:
                    with open(FERNET_KEY_FILE, "wb") as f:
                        f.write(_fernet_key)
                except Exception:
                    pass
            return True
        except Exception:
            return False
    return True

def append_log_plain(line: str) -> None:
    global _last_activity
    msg = f"{now_iso()}  {line}"
    with _log_lock:
        tail.append(msg)
        _last_activity = time.time()
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except Exception:
            pass

def append_log_encrypted(line: str) -> None:
    msg = f"{now_iso()}  {line}"
    global _last_activity
    with _log_lock:
        tail.append(msg)
        _last_activity = time.time()
        if ensure_fernet():
            try:
                token = _fernet.encrypt(msg.encode("utf-8"))
                with open(ENC_LOG_FILE, "ab") as f:
                    f.write(token + b"\n")
            except Exception as e:
                append_log_plain(f"[enc-fail] {e} | {line}")
        else:
            append_log_plain("[enc-unavailable] " + line)

def append_log(line: str, encrypted_if_privacy: bool = True) -> None:
    if STATES[0] and _HAS_CRYPTO and encrypted_if_privacy:
        append_log_encrypted(line)
    else:
        append_log_plain(line)

# ---------------------
# Secure delete
# ---------------------
def secure_overwrite_and_remove(path: str, passes: int = 1) -> bool:
    if not os.path.exists(path):
        append_log_plain(f"[secure-delete] not found: {path}")
        return False
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            for _ in range(max(1, passes)):
                f.seek(0)
                remaining = size
                bufsize = 8192
                while remaining > 0:
                    write_len = min(bufsize, remaining)
                    f.write(os.urandom(write_len))
                    remaining -= write_len
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        try:
            os.remove(path)
        except Exception:
            try:
                with open(path, "w") as f:
                    f.truncate(0)
                os.remove(path)
            except Exception as e:
                append_log_plain(f"[secure-delete-remove-fail] {e}")
                return False
        append_log(f"secure-delete: {path}")
        return True
    except Exception as e:
        append_log_plain(f"[secure-delete-exc] {path} -> {e}")
        try:
            os.remove(path)
        except Exception:
            pass
        return False

def secure_delete_list(paths: List[str], passes: int = 1, progress_cb: Optional[Callable[[int,int,str],None]] = None) -> int:
    total = len(paths)
    deleted = 0
    for i, p in enumerate(paths, start=1):
        if progress_cb:
            try:
                progress_cb(i, total, p)
            except Exception:
                pass
        ok = secure_overwrite_and_remove(p, passes=passes)
        if ok:
            deleted += 1
        time.sleep(0.2)
    append_log(f"secure-delete-list: total={total} deleted={deleted}")
    return deleted

# ---------------------
# Terminal UI
# ---------------------
def get_term_size() -> Tuple[int,int]:
    try:
        return shutil.get_terminal_size()
    except Exception:
        return (80,24)

def colorize(text: str, accent: bool = False) -> str:
    if not _HAS_COLOR:
        return text
    theme = THEMES.get(theme_name, {})
    if accent:
        return f"{theme.get('accent','')}{text}{Style.RESET_ALL}"
    return f"{theme.get('text','')}{text}{Style.RESET_ALL}"

def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def draw_ui() -> None:
    global _last_activity
    cols, rows = get_term_size()
    left_w = max(32, int(cols * 0.46))
    right_w = cols - left_w - 3
    left_lines: List[str] = []

    # header left
    for L in ASCII_BANNER.strip("\n").splitlines():
        left_lines.append(L[:left_w].ljust(left_w))
    left_lines.append((" " + WATERMARK_1).ljust(left_w))
    left_lines.append((" " + WATERMARK_2).ljust(left_w))
    left_lines.append("".ljust(left_w))

    for i, label in enumerate(MENU_OPTIONS, start=1):
        if IS_TOGGLE[i-1]:
            state_text = "Yes" if STATES[i-1] else "No"
            left_lines.append(f"[{i}] {label:30} : {state_text}"[:left_w].ljust(left_w))
        else:
            left_lines.append(f"[{i}] {label}"[:left_w].ljust(left_w))
    left_lines.append("".ljust(left_w))
    left_lines.append("[0] Refresh".ljust(left_w))

    with _log_lock:
        inactive = (time.time() - _last_activity) >= OUTPUT_COLLAPSE_TIME
        right_lines: List[str] = []
        if not inactive:
            tail_show = list(tail)[-TAIL_SHOW:]
            right_lines.append(colorize(" Live Output ".center(right_w, "-"), accent=True))
            for t in tail_show:
                if len(t) > right_w:
                    for j in range(0, len(t), right_w):
                        right_lines.append(t[j:j+right_w])
                else:
                    right_lines.append(t)
        else:
            right_lines.append(colorize(" Live Output (collapsed) ".center(right_w, "-"), accent=True))

    total = max(len(left_lines), len(right_lines))
    clear()
    for i in range(total):
        L = left_lines[i] if i < len(left_lines) else " " * left_w
        R = right_lines[i] if i < len(right_lines) else ""
        print(f"{L}   {R}")
    print("\n" + colorize("Tip: enter option number and press Enter. Toggle items flip Yes/No.", accent=True))

# ---------------------
# Background visuals
# ---------------------
def rnd_hex(min_len:int=4, max_len:int=12) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(random.randint(min_len, max_len)))

def rnd_encrypted_line(width:int) -> str:
    groups = []
    rem = width
    while rem > 4:
        g = rnd_hex()
        groups.append(g)
        rem -= (len(g) + 1)
        if random.random() < 0.07:
            token = random.choice(["::","--","==","~~","##","||","%%"])
            groups.append(token)
            rem -= (len(token) + 1)
    return " ".join(groups)[:width].ljust(width)

def background_visual(duration: float, delay: float) -> None:
    start = time.time()
    try:
        while time.time() - start < duration:
            cols, _ = get_term_size()
            line = rnd_encrypted_line(cols)
            append_log_plain(line.strip())
            print(line)
            time.sleep(delay)
    except KeyboardInterrupt:
        pass
    for _ in range(3):
        append_log_plain("[STREAM] [SYNC] [OK]")
        print("[STREAM] [SYNC] [OK]")
        time.sleep(delay)

# ---------------------
# Threat detector (advanced heuristics)
# ---------------------
def file_creation_age_days(path: str) -> float:
    try:
        stat = os.stat(path)
        # use creation time on windows, mtime on unix as best-effort
        if hasattr(stat, "st_ctime"):
            created = datetime.fromtimestamp(stat.st_ctime)
        else:
            created = datetime.fromtimestamp(stat.st_mtime)
        return (datetime.now() - created).days
    except Exception:
        return 9999.0

def is_executable_file(path: str) -> bool:
    try:
        if os.name == "nt":
            return os.path.splitext(path)[1].lower() in SUSPICIOUS_EXT
        else:
            return os.access(path, os.X_OK)
    except Exception:
        return False

def risk_score_for_path(path: str) -> Tuple[int, List[str]]:
    """Calculate a small risk score and reasons for a given path."""
    score = 0
    reasons: List[str] = []
    try:
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        # keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in name:
                score += 40
                reasons.append(f"filename contains keyword '{kw}'")
                break
        # suspicious extension
        if ext in SUSPICIOUS_EXT:
            score += 30
            reasons.append(f"suspicious extension '{ext}'")
        # executable bit / exe on unix
        if is_executable_file(path):
            score += 20
            reasons.append("executable bit or executable extension")
        # location: files in Desktop/Downloads should rarely be executables
        lowerpath = path.lower()
        if any(seg in lowerpath for seg in [os.path.join(os.path.expanduser("~"), "downloads").lower(),
                                           os.path.join(os.path.expanduser("~"), "desktop").lower()]):
            if ext in SUSPICIOUS_EXT or is_executable_file(path):
                score += 10
                reasons.append("executable in Downloads/Desktop area")
        # size anomalies (very small weird files or huge packed files)
        try:
            size = os.path.getsize(path)
            if size < 512 and ext in SUSPICIOUS_EXT:
                score += 5
                reasons.append("tiny executable file")
            if size > 200 * 1024 * 1024:  # >200MB
                score += 5
                reasons.append("very large file")
        except Exception:
            pass
        # recent creation within 7 days increases suspicion
        age_days = file_creation_age_days(path)
        if age_days <= 7:
            score += 10
            reasons.append(f"recently created ({int(age_days)} days)")
        # hidden / dotfile with exec extension
        if os.path.basename(path).startswith(".") and ext in SUSPICIOUS_EXT:
            score += 15
            reasons.append("hidden executable")
    except Exception as e:
        append_log_plain(f"risk-eval-error {e}")
    # cap
    return min(score, 100), reasons

def advanced_scan_user_home(limit: int = THREAT_LIMIT) -> List[Tuple[str,int,List[str]]]:
    """Scan home dir heuristically and return (path, score, reasons) sorted by score desc."""
    home = os.path.expanduser("~")
    found: List[Tuple[str,int,List[str]]] = []
    try:
        for root, dirs, files in os.walk(home, topdown=True):
            # prune heavy dirs
            prune = {".cache","node_modules",".local","venv","env","Library/Application Support"}
            dirs[:] = [d for d in dirs if d not in prune]
            for f in files:
                path = os.path.join(root, f)
                # basic allowlist: common harmless extensions
                ext = os.path.splitext(f)[1].lower()
                # skip very common benign file types to reduce noise
                if ext in {".txt", ".md", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".docx", ".xlsx", ".pptx", ".mp3", ".mp4"}:
                    continue
                # evaluate risk
                score, reasons = risk_score_for_path(path)
                if score >= 25:  # threshold to report
                    found.append((path, score, reasons))
                if len(found) >= limit:
                    break
            if len(found) >= limit:
                break
    except Exception as e:
        append_log_plain(f"scan-exc {e}")
    # sort by score desc
    found.sort(key=lambda x: x[1], reverse=True)
    append_log_plain(f"advanced-scan: found {len(found)} suspicious items")
    return found

# ---------------------
# Progress & spinner
# ---------------------
def progress_func(total: int, prefix: str = "", width: int = 36) -> Callable[[int], None]:
    def inner(done: int) -> None:
        frac = done / total if total else 1.0
        filled = int(width * frac)
        bar = "[" + "#" * filled + "-" * (width - filled) + "]"
        print(f"\r{prefix} {bar} {done}/{total}", end="", flush=True)
        if done >= total:
            print()
    return inner

def spinner(duration: float, message: str = "Working") -> None:
    chars = "|/-\\"
    end = time.time() + duration
    i = 0
    try:
        while time.time() < end:
            print(f"\r{message} {chars[i % len(chars)]}", end="", flush=True)
            time.sleep(0.08)
            i += 1
        print("\r" + " " * (len(message) + 4) + "\r", end="", flush=True)
    except KeyboardInterrupt:
        print()

# ---------------------
# Admin elevation helpers
# ---------------------
def relaunch_as_admin_windows() -> None:
    """Relaunch script as admin on Windows using ShellExecute (UAC)."""
    import ctypes
    script = sys.executable
    params = f"\"{os.path.abspath(__file__)}\""
    try:
        # ShellExecuteW returns >32 if success
        SEE_MASK_NOCLOSEPROCESS = 0x00000040
        lpVerb = "runas"
        lpFile = script
        lpParameters = params
        # Use ShellExecuteEx
        class SHELLEXECUTEINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("fMask", ctypes.c_ulong),
                ("hwnd", ctypes.c_void_p),
                ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p),
                ("lpParameters", ctypes.c_wchar_p),
                ("lpDirectory", ctypes.c_wchar_p),
                ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.c_void_p),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.c_wchar_p),
                ("hkeyClass", ctypes.c_void_p),
                ("dwHotKey", ctypes.c_ulong),
                ("hIcon", ctypes.c_void_p),
                ("hProcess", ctypes.c_void_p),
            ]
        sei = SHELLEXECUTEINFO()
        sei.cbSize = ctypes.sizeof(sei)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = lpVerb
        sei.lpFile = lpFile
        sei.lpParameters = lpParameters
        sei.lpDirectory = None
        sei.nShow = 1
        ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
        # exit current process
        sys.exit(0)
    except Exception as e:
        append_log_plain(f"relaunch-admin-win-fail: {e}")
        print("Failed to relaunch as admin (Windows).")

def relaunch_with_sudo_unix() -> None:
    """Relaunch script with sudo on Unix-like systems."""
    try:
        if os.geteuid() == 0:
            return  # already root
    except Exception:
        pass
    python = sys.executable or "python3"
    cmd = ["sudo", python] + sys.argv
    try:
        os.execvp("sudo", cmd)
    except Exception as e:
        append_log_plain(f"relaunch-sudo-fail: {e}")
        print("Failed to relaunch with sudo.")

def request_elevation() -> None:
    """Request elevation appropriate for OS; returns after relaunch or prints error."""
    if os.name == "nt":
        relaunch_as_admin_windows()
    else:
        relaunch_with_sudo_unix()

# ---------------------
# Feature implementations
# ---------------------
def feature_privacy_toggle() -> None:
    STATES[0] = not STATES[0]
    append_log(f"privacy:set {STATES[0]}")
    if STATES[0]:
        ok = ensure_fernet()
        if ok:
            append_log_encrypted("privacy: enabled (fernet active)")
            print("\nPrivacy enabled: logs will be encrypted (Fernet).")
        else:
            append_log_plain("privacy: enabled but cryptography unavailable")
            print("\nPrivacy enabled (fallback): cryptography not installed.")
            print("Install with: pip install cryptography")
    else:
        append_log_plain("privacy: disabled")
        print("\nPrivacy disabled: logs plain.")
    input("\nPress Enter to continue...")

def feature_firewall_toggle() -> None:
    STATES[1] = not STATES[1]
    append_log(f"firewall:set {STATES[1]}")
    if STATES[1] and not is_admin():
        print("please re-run with admin")
        append_log_plain("firewall: attempted without admin")
        input("\nPress Enter to continue...")
        return
    if STATES[1]:
        show_firewall_recs()
        ans = input("\nApply example rule to block port 9999 (y/N)? ").strip().lower()
        if ans in ("y","yes"):
            ok = apply_example_firewall()
            if ok:
                print("Applied example rule.")
            else:
                print("Failed to apply example rule.")
        input("\nPress Enter to continue...")
    else:
        print("Firewall helper disabled.")
        input("\nPress Enter to continue...")

def show_firewall_recs() -> None:
    print("\nFirewall suggestions (informational):")
    if os.name == "nt":
        print("PowerShell (Admin):")
        print("  Get-NetFirewallRule | Select Name,Enabled")
        print("  New-NetFirewallRule -DisplayName 'ZoxxerBlock9999' -Direction Inbound -Action Block -LocalPort 9999 -Protocol TCP")
    else:
        if shutil.which("ufw"):
            print("  sudo ufw deny 9999/tcp")
        else:
            print("  sudo iptables -A INPUT -p tcp --dport 9999 -j DROP")
    print("Only apply rules you understand.")

def apply_example_firewall() -> bool:
    try:
        if os.name == "nt":
            cmd = ["powershell","-Command","New-NetFirewallRule -DisplayName 'ZoxxerBlock9999' -Direction Inbound -Action Block -LocalPort 9999 -Protocol TCP"]
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            append_log_plain("firewall: example applied (win)")
            return True
        else:
            if shutil.which("ufw"):
                subprocess.check_call(["sudo","ufw","deny","9999/tcp"])
                append_log_plain("firewall: applied ufw deny 9999")
                return True
            elif shutil.which("iptables"):
                subprocess.check_call(["sudo","iptables","-A","INPUT","-p","tcp","--dport","9999","-j","DROP"])
                append_log_plain("firewall: applied iptables rule")
                return True
            else:
                append_log_plain("firewall: no supported firewall tool")
                return False
    except Exception as e:
        append_log_plain(f"firewall-apply-exc: {e}")
        return False

def feature_network_monitor_toggle() -> None:
    STATES[2] = not STATES[2]
    append_log(f"netmon:set {STATES[2]}")
    if STATES[2]:
        print("Starting local network monitor (background). Live output will show stats.")
        t = threading.Thread(target=_netmon_worker, daemon=True)
        t.start()
        input("\nPress Enter to continue...")
    else:
        print("Network monitor disabled.")
        input("\nPress Enter to continue...")

def _netmon_worker() -> None:
    append_log_plain("netmon: started")
    while STATES[2]:
        try:
            if _HAS_PSUTIL and psutil:
                conns = psutil.net_connections(kind="inet")
                listening = sum(1 for c in conns if getattr(c,"status","").upper() in ("LISTEN","LISTENING"))
                established = sum(1 for c in conns if getattr(c,"status","").upper() == "ESTABLISHED")
                append_log_plain(f"netmon: listen={listening} established={established}")
                if established > 200:
                    append_log_plain("[ALERT] netmon: high established")
            else:
                if shutil.which("netstat"):
                    try:
                        out = subprocess.check_output(["netstat","-an"], stderr=subprocess.DEVNULL, text=True, timeout=3)
                        lines = out.splitlines()
                        listening = sum(1 for L in lines if "LISTEN" in L or "LISTENING" in L)
                        established = sum(1 for L in lines if "ESTABLISHED" in L)
                        append_log_plain(f"netmon(netstat): listen={listening} estab={established}")
                    except Exception as e:
                        append_log_plain(f"netmon-netstat-exc {e}")
                else:
                    append_log_plain("netmon: psutil/netstat unavailable")
            time.sleep(1)
        except Exception as e:
            append_log_plain(f"netmon-exc {e}")
            time.sleep(2)
    append_log_plain("netmon: stopped")

def feature_patch_check() -> None:
    append_log("patch-check:start")
    steps = ["Contacting update feeds", "Evaluating installed packages", "Checking patches", "Finalizing"]
    p = progress_func(len(steps), prefix="PatchCheck")
    for i, s in enumerate(steps, start=1):
        append_log_plain(f"patch-step: {s}")
        p(i)
        time.sleep(0.8)
    print("\nPatch check finished (simulated).")
    append_log("patch-check: complete")
    input("\nPress Enter to continue...")

def feature_key_gen() -> None:
    append_log("key-gen:start")
    key = secrets.token_hex(32)
    print("\nGenerated 256-bit key (hex):\n")
    print(key)
    append_log_encrypted("key-gen: key generated")
    if _HAS_PYPERCLIP and pyperclip:
        try:
            pyperclip.copy(key)
            print("\nKey copied to clipboard.")
            append_log_plain("key-gen: copied to clipboard")
        except Exception:
            pass
    else:
        print("\nInstall pyperclip to enable clipboard copy: pip install pyperclip")
    input("\nPress Enter to continue...")

def feature_secure_delete_ui() -> None:
    append_log("secure-delete-ui:start")
    if not is_admin():
        print("please re-run with admin")
        append_log_plain("secure-delete-ui: no admin")
        input("\nPress Enter to continue...")
        return
    path = input("\nEnter full path to securely delete > ").strip()
    if not path:
        print("No path provided.")
        input("\nPress Enter to continue...")
        return
    if not os.path.exists(path):
        print("Not found.")
        append_log_plain(f"secure-delete-ui:notfound {path}")
        input("\nPress Enter to continue...")
        return
    try:
        passes = int(input("Overwrite passes (1 recommended) > ").strip() or "1")
    except Exception:
        passes = 1
    total = passes + 1
    p = progress_func(total, prefix="SecureDelete")
    for i in range(1, total+1):
        p(i)
        time.sleep(0.25)
    ok = secure_overwrite_and_remove(path, passes=passes)
    if ok:
        print("Secure deletion completed.")
        append_log_plain(f"secure-delete-ui: deleted {path}")
    else:
        print("Secure deletion failed.")
    input("\nPress Enter to continue...")

def feature_theme() -> None:
    global theme_name
    append_log("theme: open")
    print("\nAvailable themes:", ", ".join(THEMES.keys()))
    sel = input("Enter theme name (or blank to cancel) > ").strip().lower()
    if not sel:
        return
    if sel in THEMES:
        theme_name = sel
        append_log_plain(f"theme:set {sel}")
        # persist to config
        try:
            cfg = {}
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    try:
                        cfg = json.load(f)
                    except Exception:
                        cfg = {}
            cfg["theme"] = theme_name
            safe_write_config(cfg)
        except Exception:
            pass
        print(f"Theme set to {sel}.")
    else:
        print("Unknown theme.")
    input("\nPress Enter to continue...")

def save_config(cfg: dict) -> None:
    try:
        safe_write(CONFIG_FILE, json.dumps(cfg, indent=2))
    except Exception:
        pass

def safe_write_config(cfg: dict) -> None:
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            f.write(json.dumps(cfg, indent=2))
    except Exception:
        pass

# ---------------
# Helper files and initial prompts
# ---------------
def create_helper_files() -> List[str]:
    created = []
    try:
        if not os.path.exists("ZOXXER_README.txt"):
            text = f"""{APP_NAME} - Helper README

This folder contains helpful files created by {APP_NAME}.
Keep {FERNET_KEY_FILE} secure if present (encryption).
"""
            safe_write("ZOXXER_README.txt", text)
            created.append("ZOXXER_README.txt")
        if not os.path.exists("zoxxer_firewall_suggestions.txt"):
            fw = """Firewall suggestions:
Windows PowerShell (Admin):
  New-NetFirewallRule -DisplayName 'ZoxxerBlock9999' -Direction Inbound -Action Block -LocalPort 9999 -Protocol TCP

Linux:
  sudo ufw deny 9999/tcp
"""
            safe_write("zoxxer_firewall_suggestions.txt", fw)
            created.append("zoxxer_firewall_suggestions.txt")
        if not os.path.exists(CONFIG_FILE):
            cfg = {"auto_encrypt_logs": True if _HAS_CRYPTO else False, "theme": theme_name}
            safe_write(CONFIG_FILE, json.dumps(cfg, indent=2))
            created.append(CONFIG_FILE)
        if _HAS_CRYPTO and not os.path.exists(FERNET_KEY_FILE):
            k = Fernet.generate_key()
            try:
                with open(FERNET_KEY_FILE, "wb") as f:
                    f.write(k)
                created.append(FERNET_KEY_FILE)
                ensure_fernet()
            except Exception:
                pass
        append_log_plain(f"helper-files: created {created}")
    except Exception as e:
        append_log_plain(f"helper-files-exc: {e}")
    return created

def initial_helper_prompt() -> None:
    missing = [f for f in HELPER_FILES if not os.path.exists(f)]
    if _HAS_CRYPTO and not os.path.exists(FERNET_KEY_FILE):
        missing.append(FERNET_KEY_FILE)
    missing = sorted(set(missing))
    if not missing:
        return
    print("This code needs more files !")
    print("Missing files:", ", ".join(os.path.basename(m) for m in missing))
    ans = input("Would u like to download/create the needed files, Y/N > ").strip().lower()
    if ans not in ("y", "yes"):
        append_log_plain("helper: user declined")
        return
    created = create_helper_files()
    if created:
        print("Created:", ", ".join(created))
    else:
        print("No files created (check permissions)")
    input("\nPress Enter to continue...")

# ---------------------
# Advanced scan + delete flow
# ---------------------
def run_advanced_scan_and_handle() -> None:
    append_log_plain("advscan: start")
    found = advanced_scan_user_home(limit=THREAT_LIMIT)
    if not found:
        print("No suspicious items found on advanced scan.")
        append_log_plain("advscan: none found")
        time.sleep(1.0)
        return
    # show results
    print("\nDetected suspicious items (risk score 0-100):\n")
    for idx, (path, score, reasons) in enumerate(found, start=1):
        print(f"[{idx}] {path}")
        print(f"     Risk: {score} Reasons: {', '.join(reasons)}")
    # ask if user wants deletion
    ans = input("\nWould you like me to delete these items? Y/N > ").strip().lower()
    if ans not in ("y","yes"):
        append_log_plain("advscan: user declined delete")
        print("No files were deleted.")
        time.sleep(1.0)
        return
    # ensure admin
    if not is_admin():
        print("Not running as admin/root. Attempting to relaunch elevated...")
        append_log_plain("advscan: needing elevation")
        request_elevation()
        # after elevation, the elevated instance will re-run from start; exit current
        sys.exit(0)
    # confirm again
    confirm = input("Final confirm: permanently delete all listed items? This cannot be undone. Y/N > ").strip().lower()
    if confirm not in ("y","yes"):
        append_log_plain("advscan: user cancelled final confirm")
        print("Cancelled.")
        time.sleep(1.0)
        return
    # perform deletion with progress
    paths = [p for p, s, r in found]
    total = len(paths)
    p = progress_func(total, prefix="Deleting")
    def cb(i, total_n, path):
        p(i)
        append_log_plain(f"advscan: deleting {path}")
    deleted = secure_delete_list(paths, passes=1, progress_cb=cb)
    print(f"\nDeletion finished: {deleted}/{total} removed.")
    append_log_plain(f"advscan: deleted {deleted}/{total}")
    time.sleep(1.0)

# ---------------------
# Entrypoint helpers
# ---------------------
ASCII_BANNER = r"""
 _____                        
|__  /_____  ____  _____ _ __ 
  / // _ \ \/ /\ \/ / _ \ '__|
 / /| (_) >  <  >  <  __/ |   
/____\___/_/\_\/_/\_\___|_|   
"""

def preflight() -> None:
    append_log_plain("startup: begin")
    initial_helper_prompt()
    # run advanced scan early and let user choose
    run_advanced_scan_and_handle()
    print("\nInitializing...")
    append_log_plain("startup: background visual")
    try:
        background_visual(BACKGROUND_SECONDS, BACKGROUND_DELAY)
    except KeyboardInterrupt:
        append_log_plain("startup: background interrupted")
    if _HAS_CRYPTO:
        ensure_fernet()
    append_log_plain("startup: complete")

def menu_dispatch(idx: int) -> None:
    if idx < 0 or idx >= len(MENU_OPTIONS):
        append_log_plain(f"menu: invalid {idx}")
        return
    if IS_TOGGLE[idx]:
        if idx == 0:
            feature_privacy_toggle()
        elif idx == 1:
            feature_firewall_toggle()
        elif idx == 2:
            feature_network_monitor_toggle()
        else:
            STATES[idx] = not STATES[idx]
            append_log_plain(f"menu-toggle: {MENU_OPTIONS[idx]} = {STATES[idx]}")
        return
    action = MENU_OPTIONS[idx]
    if action == "Patch/Update Checker":
        feature_patch_check()
    elif action == "Secure Key Generator":
        feature_key_gen()
    elif action == "Secure File Deletion (admin)":
        feature_secure_delete_ui()
    elif action == "Theme / Color Settings":
        feature_theme()
    elif action == "Download Needed Files":
        created = create_helper_files()
        if created:
            print("Created:", ", ".join(created))
        else:
            print("No files created.")
        input("\nPress Enter to continue...")
    elif action == "Exit":
        append_log_plain("menu: exit")
        print("\nExiting. Stay safe.")
        input("\nPress Enter to close...")
        sys.exit(0)
    else:
        append_log_plain(f"menu: unhandled action {action}")

def main_loop() -> None:
    append_log_plain("main: loop start")
    while True:
        draw_ui()
        try:
            choice = input("\nSelect option number > ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nInterrupted. Exiting.")
            append_log_plain("main: interrupted")
            input("\nPress Enter to close...")
            sys.exit(0)
        if not choice:
            continue
        if not choice.isdigit():
            append_log_plain("main: invalid non-digit")
            print("Please enter a number.")
            time.sleep(0.4)
            continue
        n = int(choice)
        if n == 0:
            continue
        if 1 <= n <= len(MENU_OPTIONS):
            menu_dispatch(n - 1)
        else:
            print("Invalid choice.")
            time.sleep(0.4)

def main() -> None:
    print(f"{APP_NAME} starting — run in a terminal for best results.")
    append_log_plain(f"{APP_NAME}: start")
    preflight()
    main_loop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        try:
            append_log_plain(f"fatal: {e}")
        except Exception:
            pass
        print("A fatal error occurred:", e)
        input("\nPress Enter to exit...")
        sys.exit(1)

