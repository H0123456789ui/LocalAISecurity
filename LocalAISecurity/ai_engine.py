import os
import sys
import ctypes
import math
import time
import hashlib
import threading
import json
import numpy as np
from pathlib import Path

MODELS_DIR = Path(__file__).parent / "models"

SECURITY_CLASS_NAMES = ["正常", "流氓软件", "木马", "勒索软件"]
CLEAN_CLASS_NAMES = ["系统核心", "软件缓存", "安全可删", "大型冗余", "用户重要"]

_torch_available = False
_torch = None
try:
    import torch
    _torch = torch
    _torch_available = True
except ImportError:
    pass

if _torch_available:
    from models import SecurityBehaviorCNN, FileClassifyCNN


class SecurityAIInference:
    def __init__(self):
        self.model = None
        self.loaded = False
        self.load_error = None

    def load(self):
        if not _torch_available:
            self.load_error = "PyTorch not installed"
            return False
        try:
            model_path = MODELS_DIR / "security_model_best.pt"
            if not model_path.exists():
                self.load_error = f"Model file not found: {model_path}"
                return False
            self.model = SecurityBehaviorCNN()
            state_dict = _torch.load(model_path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(state_dict)
            self.model.eval()
            self.loaded = True
            return True
        except Exception as e:
            self.load_error = str(e)
            return False

    def predict(self, features_32d):
        if not self.loaded:
            return 0, 0.5, [0.25, 0.25, 0.25, 0.25]
        with _torch.no_grad():
            x = _torch.FloatTensor(features_32d).unsqueeze(0).unsqueeze(0)
            logits = self.model(x)
            probs = _torch.softmax(logits, dim=1).squeeze(0).numpy()
        cls = int(np.argmax(probs))
        conf = float(probs[cls])
        return cls, conf, probs.tolist()


class CleanAIInference:
    def __init__(self):
        self.model = None
        self.loaded = False
        self.load_error = None

    def load(self):
        if not _torch_available:
            self.load_error = "PyTorch not installed"
            return False
        try:
            model_path = MODELS_DIR / "clean_model_best.pt"
            if not model_path.exists():
                self.load_error = f"Model file not found: {model_path}"
                return False
            self.model = FileClassifyCNN()
            state_dict = _torch.load(model_path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(state_dict)
            self.model.eval()
            self.loaded = True
            return True
        except Exception as e:
            self.load_error = str(e)
            return False

    def predict(self, features_18d):
        if not self.loaded:
            return 4, 0.5, [0.0, 0.0, 0.0, 0.0, 1.0]
        with _torch.no_grad():
            x = _torch.FloatTensor(features_18d).unsqueeze(0).unsqueeze(0)
            logits = self.model(x)
            probs = _torch.softmax(logits, dim=1).squeeze(0).numpy()
        cls = int(np.argmax(probs))
        conf = float(probs[cls])
        return cls, conf, probs.tolist()


JUNK_CATEGORIES = {
    "temp": {
        "label": "临时文件", "risk": 0,
        "extensions": {".tmp", ".temp", ".bak", ".old", ".log"},
        "dir_patterns": ["\\temp", "\\tmp", "\\cache", "\\Temp", "\\Tmp"],
    },
    "cache": {
        "label": "缓存文件", "risk": 0,
        "extensions": {".cache", ".idx", ".dat"},
        "dir_patterns": ["\\Cache", "\\cache",
                         "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache",
                         "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache",
                         "\\AppData\\Local\\Mozilla\\Firefox\\Profiles"],
    },
    "log": {
        "label": "日志文件", "risk": 0,
        "extensions": {".log", ".evtx"},
        "dir_patterns": ["\\Logs", "\\logs", "\\Log"],
    },
    "update": {
        "label": "更新残留", "risk": 1,
        "extensions": {".cab", ".msu", ".esd"},
        "dir_patterns": ["\\SoftwareDistribution\\Download", "\\SoftwareDistribution"],
    },
    "prefetch": {
        "label": "预读取数据", "risk": 1,
        "extensions": {".pf"},
        "dir_patterns": ["\\Prefetch"],
    },
    "thumb": {
        "label": "缩略图缓存", "risk": 0,
        "extensions": {".db"},
        "dir_patterns": ["\\Thumbcache", "\\IconCache"],
    },
    "crash": {
        "label": "崩溃转储", "risk": 0,
        "extensions": {".dmp", ".mdmp", ".hdmp"},
        "dir_patterns": ["\\Crash", "\\crash", "\\CrashDumps", "\\WER"],
    },
    "installer": {
        "label": "安装包缓存", "risk": 1,
        "extensions": {".msi", ".msp"},
        "dir_patterns": ["\\Installer"],
    },
}


def _get_windows_dir():
    buf = ctypes.create_unicode_buffer(260)
    n = ctypes.windll.kernel32.GetWindowsDirectoryW(buf, 260)
    if n > 0 and n < 260:
        return buf.value
    return os.environ.get("SystemRoot", "C:\\Windows")


def _get_program_files_dirs():
    result = []
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        val = os.environ.get(key, "")
        if val:
            result.append(val)
    for d in ("C:\\Program Files", "C:\\Program Files (x86)"):
        norm = os.path.normpath(d)
        if os.path.isdir(norm) and norm not in result:
            result.append(norm)
    return result


def _build_system_locked_dirs():
    windir = _get_windows_dir()
    sysdrive = os.environ.get("SystemDrive", "C:")
    return [os.path.normpath(p) for p in [
        os.path.join(windir, "System32"),
        os.path.join(windir, "SysWOW64"),
        os.path.join(windir, "System"),
        os.path.join(windir, "Fonts"),
        os.path.join(windir, "INF"),
        os.path.join(windir, "Driver Store"),
        os.path.join(windir, "WinSxS"),
        os.path.join(windir, "Boot"),
        os.path.join(windir, "Panther"),
        os.path.join(windir, "Registration"),
        os.path.join(sysdrive + "\\", "$Recycle.Bin"),
        os.path.join(sysdrive + "\\", "Boot"),
        os.path.join(sysdrive + "\\", "EFI"),
        os.path.join(sysdrive + "\\", "Recovery"),
        os.path.join(os.environ.get("ProgramData", sysdrive + "\\ProgramData"),
                     "Microsoft\\Windows"),
        os.path.join(sysdrive + "\\", "Users\\All Users\\Microsoft\\Windows"),
    ] if os.path.isdir(os.path.dirname(p)) or True]


def _verify_signature_winapi(exe_path):
    """ctypes 调用 WinVerifyTrust，零进程开销 — 模块级函数"""
    from ctypes import wintypes

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
        "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
    )

    WTD_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_CLOSE = 2
    WTD_STATEACTION_VERIFY = 1

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.c_void_p),
        ]

    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.c_void_p),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    ole32 = ctypes.WinDLL("ole32.dll")
    iid = GUID()
    ole32.CLSIDFromString(str(WINTRUST_ACTION_GENERIC_VERIFY_V2), ctypes.byref(iid))

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = exe_path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.dwUIChoice = WTD_UI_NONE
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
    trust_data.dwUnionChoice = WTD_CHOICE_FILE
    trust_data.pFile = ctypes.addressof(file_info)
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY
    trust_data.hWVTStateData = None

    wintrust = ctypes.WinDLL("wintrust.dll")
    wintrust.WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.c_void_p, ctypes.c_void_p]
    wintrust.WinVerifyTrust.restype = wintypes.LONG

    status = wintrust.WinVerifyTrust(None, ctypes.byref(iid), ctypes.byref(trust_data))

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(iid), ctypes.byref(trust_data))

    return status == 0


class FileFeatureExtractor:

    def __init__(self):
        self._locked_dirs = _build_system_locked_dirs()
        self._program_files_dirs = _get_program_files_dirs()

    def extract_18d_features(self, filepath, stat):
        path_lower = filepath.lower()
        path_depth = filepath.count(os.sep)
        in_system_dir = any(path_lower.startswith(d.lower()) for d in self._locked_dirs)
        in_program_files = any(path_lower.startswith(d.lower()) for d in self._program_files_dirs)
        in_user_dir = "\\users\\" in path_lower
        in_appdata = "\\appdata\\" in path_lower
        in_temp = any(p in path_lower for p in ["\\temp", "\\tmp", "\\cache"])
        file_size_log = math.log1p(stat.st_size) / 20.0 if stat.st_size > 0 else 0
        try:
            create_days = (time.time() - stat.st_ctime) / 86400
        except Exception:
            create_days = 365
        try:
            access_days = (time.time() - stat.st_atime) / 86400
        except Exception:
            access_days = 365
        try:
            modify_days = (time.time() - stat.st_mtime) / 86400
        except Exception:
            modify_days = 365
        ext = os.path.splitext(filepath)[1].lower()
        ext_risk = 0.0
        for cat_info in JUNK_CATEGORIES.values():
            if ext in cat_info["extensions"]:
                ext_risk = max(ext_risk, 1.0 - cat_info["risk"] * 0.3)
        is_hidden = bool(stat.st_file_attributes & 2) if hasattr(stat, 'st_file_attributes') else False
        is_system = bool(stat.st_file_attributes & 4) if hasattr(stat, 'st_file_attributes') else False
        dir_match_score = 0.0
        for cat_info in JUNK_CATEGORIES.values():
            for dp in cat_info["dir_patterns"]:
                if dp.lower() in path_lower:
                    dir_match_score = max(dir_match_score, 1.0 - cat_info["risk"] * 0.2)
        return [
            float(path_depth) / 15.0,
            float(in_system_dir),
            float(in_program_files),
            float(in_user_dir),
            float(in_appdata),
            float(in_temp),
            file_size_log,
            float(create_days) / 365.0,
            float(access_days) / 365.0,
            float(modify_days) / 365.0,
            ext_risk,
            float(is_hidden),
            float(is_system),
            dir_match_score,
            float(ext == ".tmp" or ext == ".temp"),
            float(ext == ".log"),
            float(ext == ".cache" or ext == ".dat"),
            float(ext == ".dmp" or ext == ".bak"),
        ]

    def check_path_locked(self, filepath):
        norm = os.path.normpath(filepath)
        return any(norm.lower().startswith(d.lower()) for d in self._locked_dirs)

    def check_whitelist(self, filepath):
        whitelist_exts = {".dll", ".sys", ".exe", ".ini", ".cfg", ".inf", ".cat"}
        ext = os.path.splitext(filepath)[1].lower()
        return ext in whitelist_exts and self.check_path_locked(filepath)

    def compute_file_hash(self, filepath, algorithm="sha256", block_size=65536):
        try:
            h = hashlib.new(algorithm)
            with open(filepath, "rb") as f:
                while True:
                    block = f.read(block_size)
                    if not block:
                        break
                    h.update(block)
            return h.hexdigest()
        except (PermissionError, OSError):
            return ""

    def get_category(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()
        for cat_name, cat_info in JUNK_CATEGORIES.items():
            if ext in cat_info["extensions"]:
                return cat_name
        for cat_name, cat_info in JUNK_CATEGORIES.items():
            for dp in cat_info["dir_patterns"]:
                if dp.lower() in filepath.lower():
                    return cat_name
        return "other"


class ProcessFeatureCollector:
    def __init__(self):
        self._psutil = None
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            pass

    def is_available(self):
        return self._psutil is not None

    def collect_process_features(self, proc):
        if not self._psutil:
            return None
        try:
            with proc.oneshot():
                cpu_pct = proc.cpu_percent(interval=0)
                mem_info = proc.memory_info()
                num_threads = proc.num_threads()
                io_counters = proc.io_counters() if hasattr(proc, 'io_counters') else None
                try:
                    connections = proc.connections()
                    net_conns = len(connections)
                except (self._psutil.AccessDenied, self._psutil.NoSuchProcess):
                    net_conns = 0
                try:
                    cmdline = proc.cmdline()
                    cmdline_len = len(' '.join(cmdline)) if cmdline else 0
                except (self._psutil.AccessDenied, self._psutil.NoSuchProcess):
                    cmdline_len = 0
                try:
                    exe = proc.exe() or ""
                except (self._psutil.AccessDenied, self._psutil.NoSuchProcess):
                    exe = ""
                try:
                    name = proc.name() or ""
                except (self._psutil.AccessDenied, self._psutil.NoSuchProcess):
                    name = ""
                try:
                    create_time = proc.create_time()
                    uptime = time.time() - create_time
                except (self._psutil.AccessDenied, self._psutil.NoSuchProcess):
                    uptime = 0
                is_system = exe.lower().startswith("c:\\windows")
                is_program_files = "\\program files" in exe.lower()
                has_network = net_conns > 0
                io_read = io_counters.read_bytes if io_counters else 0
                io_write = io_counters.write_bytes if io_counters else 0
                name_lower = name.lower()
                suspicious_name = float(any(kw in name_lower for kw in [
                    "miner", "hack", "crack", "keygen", "patch", "loader",
                    "inject", "hook", "bypass", "exploit", "rat", "bot",
                    "trojan", "worm", "virus", "malware", "spy", "steal",
                    "crypt", "locker", "ransom", "shadow", "mimikatz",
                ]))
                exe_lower = exe.lower()
                suspicious_path = float(any(kw in exe_lower for kw in [
                    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                    "\\downloads\\", "\\public\\",
                ]))
                high_cpu = min(cpu_pct / 100.0, 1.0)
                high_mem = min(mem_info.rss / (1024 * 1024 * 1024), 1.0)
                high_threads = min(num_threads / 100.0, 1.0)
                high_io = min((io_read + io_write) / (1024 * 1024 * 100), 1.0)
                high_net = min(net_conns / 50.0, 1.0)
                has_gui = float(not proc.name().lower().endswith(('.exe', '.dll')) or
                                any(w in proc.name().lower() for w in
                                    ['explorer', 'chrome', 'firefox', 'edge', 'code',
                                     'devenv', 'winword', 'excel', 'powerpnt', 'wechat',
                                     'qq', 'dingtalk', 'steam', 'discord', 'telegram']))
                is_signed = float(exe.lower().startswith("c:\\windows") or
                                 "\\program files" in exe.lower() or
                                 "\\programdata" in exe.lower())
                is_service = float(any(w in exe_lower for w in [
                    "\\system32\\", "\\syswow64\\", "svchost", "services",
                    "lsass", "csrss", "wininit", "winlogon", "dwm",
                    "smss", "fontdrvhost", "lsaiso", "registry",
                ]))
                io_read_ratio = min(io_read / max(io_read + io_write, 1), 1.0)
                io_write_ratio = min(io_write / max(io_read + io_write, 1), 1.0)
                mem_virt_ratio = min(mem_info.vms / max(mem_info.rss, 1), 10.0) / 10.0
                features = [
                    high_cpu,
                    high_mem,
                    float(num_threads) / 50.0,
                    float(cmdline_len) / 500.0,
                    float(is_system),
                    float(has_network),
                    high_net,
                    float(uptime) / 86400.0,
                    high_io,
                    io_read_ratio,
                    suspicious_name,
                    suspicious_path,
                    float(is_program_files),
                    has_gui,
                    is_signed,
                    is_service,
                    high_threads,
                    mem_virt_ratio,
                    io_write_ratio,
                    float(len(name)) / 30.0,
                    min(float(cmdline_len) / 1000.0, 1.0),
                    float(bool(exe)),
                    float(net_conns > 10),
                    float(cpu_pct > 50),
                    float(mem_info.rss > 500 * 1024 * 1024),
                    float(num_threads > 50),
                    float(any(w in name_lower for w in ['update', 'setup', 'install'])),
                    float(any(w in name_lower for w in ['service', 'daemon', 'agent', 'helper'])),
                    float(suspicious_name > 0 and suspicious_path > 0),
                    float(is_system and high_cpu < 0.1),
                    float(not is_system and high_cpu > 0.5),
                    float(suspicious_name or suspicious_path),
                ]
                return [min(max(f, 0.0), 1.0) for f in features]
        except (self._psutil.NoSuchProcess, self._psutil.AccessDenied, self._psutil.ZombieProcess):
            return None


class SecurityMonitor:
    USER_SAFE_LIST_FILE = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "LocalAISecurity" / "user_safe_list.json"

    def __init__(self, ai_engine, on_threat=None):
        self.ai_engine = ai_engine
        self.on_threat = on_threat
        self.collector = ProcessFeatureCollector()
        self._running = False
        self._thread = None
        self._scan_interval = 5
        self._lock = threading.Lock()
        self._known_pids = set()
        self._threat_history = []
        self._system_whitelist = {
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
            "fontdrvhost.exe", "lsaiso.exe", "registry.exe",
            "explorer.exe", "taskhostw.exe", "conhost.exe",
            "sihost.exe", "ctfmon.exe", "dllhost.exe",
            "runtimebroker.exe", "searchindexer.exe", "spoolsv.exe",
            "audiodg.exe", "wudfhost.exe", "system", "system idle process",
            "memory compression", "registry",
        }
        self._signature_cache = {}
        self._user_safe_list = self._load_user_safe_list()

    def _load_user_safe_list(self):
        try:
            if self.USER_SAFE_LIST_FILE.exists():
                with open(self.USER_SAFE_LIST_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return set(data.get("safe_exes", []))
        except Exception:
            pass
        return set()

    def _save_user_safe_list(self):
        try:
            self.USER_SAFE_LIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                safe_list = list(self._user_safe_list)
            with open(self.USER_SAFE_LIST_FILE, "w", encoding="utf-8") as f:
                json.dump({"safe_exes": safe_list}, f, indent=2)
        except Exception:
            pass

    def add_to_safe_list(self, exe_path):
        with self._lock:
            self._user_safe_list.add(exe_path.lower())
        self._save_user_safe_list()

    def _check_digital_signature(self, exe_path):
        """使用 WinVerifyTrust API 验证数字签名，替代 PowerShell"""
        if not exe_path or not os.path.isfile(exe_path):
            return False
        exe_lower = exe_path.lower()
        with self._lock:
            if exe_lower in self._signature_cache:
                return self._signature_cache[exe_lower]
        try:
            is_valid = self._verify_signature_winapi(exe_path)
        except Exception:
            is_valid = False
        with self._lock:
            self._signature_cache[exe_lower] = is_valid
        return is_valid

    def _verify_signature_winapi(self, exe_path):
        return _verify_signature_winapi(exe_path)

    def _is_process_safe(self, proc_name, proc_exe):
        if proc_name.lower() in self._system_whitelist:
            return True
        exe_lower = (proc_exe or "").lower()
        if exe_lower.startswith("c:\\windows"):
            return True
        if "\\program files" in exe_lower or "\\programdata" in exe_lower:
            return True
        with self._lock:
            if exe_lower in self._user_safe_list:
                return True
        if proc_exe and self._check_digital_signature(proc_exe):
            return True
        return False

    def start(self):
        if self._running:
            return
        if not self.collector.is_available():
            return False
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    def _monitor_loop(self):
        psutil = self.collector._psutil
        # Try truly event-driven monitoring via WMI process creation events
        use_wmi = False
        try:
            import wmi as _wmi_mod
            import pythoncom
            pythoncom.CoInitialize()
            c = _wmi_mod.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            use_wmi = True
        except (ImportError, Exception):
            watcher = None

        if use_wmi:
            try:
                while self._running:
                    try:
                        proc_event = watcher(timeout_ms=1000)
                        if proc_event is not None:
                            pid = proc_event.ProcessId
                            try:
                                proc = psutil.Process(pid)
                                try:
                                    proc_name = proc.name()
                                    proc_exe = proc.exe() or ""
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue
                                if self._is_process_safe(proc_name, proc_exe):
                                    continue
                                features = self.collector.collect_process_features(proc)
                                if features is not None and self.ai_engine.loaded:
                                    cls, conf, probs = self.ai_engine.predict(features)
                                    if cls >= 1 and conf > 0.90:
                                        try:
                                            name = proc.name()
                                            exe = proc.exe()
                                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                                            name = f"PID:{pid}"
                                            exe = "unknown"
                                        threat_info = {
                                            "pid": pid,
                                            "name": name,
                                            "exe": exe,
                                            "classification": SECURITY_CLASS_NAMES[cls],
                                            "confidence": conf,
                                            "probabilities": probs,
                                            "timestamp": time.time(),
                                        }
                                        with self._lock:
                                            self._threat_history.append(threat_info)
                                        if self.on_threat:
                                            self.on_threat(threat_info)
                            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                                continue
                    except Exception:
                        time.sleep(0.1)
            finally:
                try:
                    import pythoncom
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
        else:
            # Fallback: polling with psutil when WMI is unavailable
            while self._running:
                try:
                    current_pids = set()
                    for proc in psutil.process_iter(['pid']):
                        current_pids.add(proc.info['pid'])
                    with self._lock:
                        new_pids = current_pids - self._known_pids
                        self._known_pids = current_pids
                    for pid in new_pids:
                        try:
                            proc = psutil.Process(pid)
                            try:
                                proc_name = proc.name()
                                proc_exe = proc.exe() or ""
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                            if self._is_process_safe(proc_name, proc_exe):
                                continue
                            features = self.collector.collect_process_features(proc)
                            if features is not None and self.ai_engine.loaded:
                                cls, conf, probs = self.ai_engine.predict(features)
                                if cls >= 1 and conf > 0.90:
                                    try:
                                        name = proc.name()
                                        exe = proc.exe()
                                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                                        name = f"PID:{pid}"
                                        exe = "unknown"
                                    threat_info = {
                                        "pid": pid,
                                        "name": name,
                                        "exe": exe,
                                        "classification": SECURITY_CLASS_NAMES[cls],
                                        "confidence": conf,
                                        "probabilities": probs,
                                        "timestamp": time.time(),
                                    }
                                    with self._lock:
                                        self._threat_history.append(threat_info)
                                    if self.on_threat:
                                        self.on_threat(threat_info)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue
                except Exception:
                    pass
                for _ in range(self._scan_interval * 10):
                    if not self._running:
                        break
                    time.sleep(0.1)

    def get_threat_history(self):
        with self._lock:
            return list(self._threat_history)

    def scan_all_processes(self):
        if not self.collector.is_available():
            return []
        psutil = self.collector._psutil
        results = []
        for proc in psutil.process_iter(['pid']):
            try:
                try:
                    name = proc.name()
                    exe = proc.exe()
                    pid = proc.pid
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                if self._is_process_safe(name, exe):
                    results.append({
                        "pid": pid,
                        "name": name,
                        "exe": exe,
                        "classification": SECURITY_CLASS_NAMES[0],
                        "class_id": 0,
                        "confidence": 0.95,
                        "is_threat": False,
                    })
                    continue
                features = self.collector.collect_process_features(proc)
                if features is not None:
                    if self.ai_engine.loaded:
                        cls, conf, probs = self.ai_engine.predict(features)
                    else:
                        cls, conf = 0, 0.5
                        probs = [0.25, 0.25, 0.25, 0.25]
                    results.append({
                        "pid": pid,
                        "name": name,
                        "exe": exe,
                        "classification": SECURITY_CLASS_NAMES[cls],
                        "class_id": cls,
                        "confidence": conf,
                        "is_threat": cls >= 1 and conf > 0.90,
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return results

    def scan_network_connections(self):
        if not self.collector.is_available():
            return []
        psutil = self.collector._psutil
        results = []
        suspicious_ports = {
            4444, 5555, 6666, 6667, 8888, 9999,
            1337, 31337, 1234, 12345, 54321, 65535,
        }
        try:
            net_conns = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, Exception):
            return results
        pid_conns = {}
        for conn in net_conns:
            pid = conn.pid or 0
            if pid not in pid_conns:
                pid_conns[pid] = []
            pid_conns[pid].append(conn)
        for pid, conns in pid_conns.items():
            if pid == 0:
                continue
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc_exe = proc.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = f"PID:{pid}"
                proc_exe = ""
            if self._is_process_safe(proc_name, proc_exe):
                continue
            remote_count = sum(1 for c in conns if c.raddr)
            suspicious_port_count = sum(
                1 for c in conns
                if c.laddr and c.laddr.port in suspicious_ports
            )
            listen_count = sum(1 for c in conns if c.status == 'LISTEN')
            established_count = sum(1 for c in conns if c.status == 'ESTABLISHED')
            net_features = self.collector.collect_process_features(
                psutil.Process(pid)) if self.collector.is_available() else None
            ai_cls, ai_conf = 0, 0.5
            if net_features is not None and self.ai_engine.loaded:
                ai_cls, ai_conf, _ = self.ai_engine.predict(net_features)
            net_risk = 0.0
            if suspicious_port_count > 0:
                net_risk = min(1.0, 0.5 + suspicious_port_count * 0.2)
            elif remote_count > 10:
                net_risk = min(0.8, remote_count * 0.05)
            elif listen_count > 5:
                net_risk = min(0.6, listen_count * 0.1)
            combined_risk = max(net_risk, ai_conf if ai_cls >= 1 else 0)
            is_suspicious = combined_risk > 0.7 or (ai_cls >= 1 and ai_conf > 0.85)
            conn_details = []
            for c in conns:
                detail = {
                    "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "remote_addr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                    "is_suspicious_port": c.laddr.port in suspicious_ports if c.laddr else False,
                }
                conn_details.append(detail)
            results.append({
                "pid": pid,
                "name": proc_name,
                "exe": proc_exe,
                "remote_count": remote_count,
                "suspicious_port_count": suspicious_port_count,
                "listen_count": listen_count,
                "established_count": established_count,
                "net_risk": net_risk,
                "ai_classification": SECURITY_CLASS_NAMES[ai_cls],
                "ai_confidence": ai_conf,
                "combined_risk": combined_risk,
                "is_suspicious": is_suspicious,
                "connections": conn_details,
            })
        results.sort(key=lambda x: x["combined_risk"], reverse=True)
        return results
