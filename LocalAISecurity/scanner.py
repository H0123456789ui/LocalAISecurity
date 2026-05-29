import os
import time
import ctypes
import ctypes.wintypes
import winreg
from i18n import t
from classifier import AIFileClassifier, FILE_CLASS
from ai_engine import (
    SecurityAIInference, SecurityMonitor, ProcessFeatureCollector,
    SECURITY_CLASS_NAMES, _verify_signature_winapi, _get_windows_dir,
    _get_program_files_dirs, _build_system_locked_dirs,
)


def _send_to_recycle_bin(filepath):
    """使用 Windows Shell API 将文件移入回收站，可恢复。"""
    if not os.path.isfile(filepath):
        return False
    path = os.path.abspath(filepath)
    path_buf = ctypes.create_unicode_buffer(path + "\0\0", len(path) + 2)

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", ctypes.wintypes.HWND),
            ("wFunc", ctypes.wintypes.UINT),
            ("pFrom", ctypes.c_wchar_p),
            ("pTo", ctypes.c_wchar_p),
            ("fFlags", ctypes.wintypes.WORD),
            ("fAnyOperationsAborted", ctypes.wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", ctypes.c_wchar_p),
        ]

    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_NOERRORUI = 0x0400
    FOF_SILENT = 0x0004
    FO_DELETE = 3

    shfile = SHFILEOPSTRUCTW()
    shfile.hwnd = 0
    shfile.wFunc = FO_DELETE
    shfile.pFrom = ctypes.cast(path_buf, ctypes.c_wchar_p)
    shfile.pTo = None
    shfile.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT
    shfile.fAnyOperationsAborted = False
    shfile.hNameMappings = None
    shfile.lpszProgressTitle = None

    try:
        result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(shfile))
        return result == 0 and not shfile.fAnyOperationsAborted
    except Exception:
        return False


def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


class DiskScanner:
    def __init__(self):
        self.ai = AIFileClassifier()
        self.results = {i: [] for i in range(5)}
        self.total_scanned = 0
        self.scan_time_ms = 0
        self._hash_cache = {}

    def scan(self, drive="C:\\", callback=None):
        start = time.time()
        self.results = {i: [] for i in range(5)}
        self.total_scanned = 0
        self._hash_cache = {}
        windir = os.environ.get("SystemRoot", os.environ.get("WINDIR", "C:\\Windows"))
        userprofile = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        scan_dirs = [
            os.environ.get("TEMP", os.path.join(windir, "Temp")),
            os.path.join(windir, "Temp"),
            os.path.join(windir, "SoftwareDistribution\\Download"),
            os.path.join(windir, "Logs"),
            os.path.join(windir, "Prefetch"),
            os.path.join(windir, "CrashDumps"),
            os.path.join(userprofile, "AppData\\Local\\Temp"),
            os.path.join(userprofile, "AppData\\Local\\Microsoft\\Windows\\Explorer"),
            os.path.join(userprofile, "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
            os.path.join(userprofile, "AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"),
            os.path.join(userprofile, "AppData\\Local\\Mozilla\\Firefox\\Profiles"),
            os.path.join(userprofile, "AppData\\Local\\CrashDumps"),
            os.path.join(userprofile, "Downloads"),
        ]
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                continue
            try:
                for root, dirs, files in os.walk(scan_dir):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            stat = os.stat(fpath)
                            if self.ai.check_path_locked(fpath):
                                continue
                            if self.ai.check_whitelist(fpath):
                                continue
                            cls_id, confidence, features = self.ai.classify(fpath, stat)
                            cat_name = self.ai.feature_extractor.get_category(fpath)
                            file_hash = ""
                            if cls_id >= 2 and stat.st_size < 50 * 1024 * 1024:
                                file_hash = self.ai.feature_extractor.compute_file_hash(fpath)
                            self.results[cls_id].append({
                                "path": fpath,
                                "size": stat.st_size,
                                "confidence": confidence,
                                "category": cat_name,
                                "features": features,
                                "class_id": cls_id,
                                "file_hash": file_hash,
                            })
                            self.total_scanned += 1
                            if callback and self.total_scanned % 50 == 0:
                                callback(self.total_scanned)
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                continue
        self.scan_time_ms = int((time.time() - start) * 1000)
        return self.results

    def get_stats(self):
        stats = {"total_files": self.total_scanned, "scan_time_ms": self.scan_time_ms}
        for cls_id in range(5):
            name, label, color, desc = FILE_CLASS[cls_id]
            items = self.results.get(cls_id, [])
            stats[f"cls{cls_id}_count"] = len(items)
            stats[f"cls{cls_id}_size"] = sum(i["size"] for i in items)
            stats[f"cls{cls_id}_label"] = label
        stats["cleanable_size"] = stats.get("cls2_size", 0) + stats.get("cls3_size", 0)
        return stats

    def execute_clean(self, items_to_delete):
        deleted = 0
        freed = 0
        failed = 0
        for item in items_to_delete:
            try:
                sz = os.path.getsize(item["path"])
                if _send_to_recycle_bin(item["path"]):
                    deleted += 1
                    freed += sz
                else:
                    failed += 1
            except (PermissionError, OSError):
                failed += 1
        return {"deleted": deleted, "freed": freed, "failed": failed}


# ============================================================
# 全盘安全扫描器
# ============================================================

SECURITY_ISSUE_CATEGORIES = {
    1: {"label": "病毒/恶意软件", "color": "#FF3B30", "icon": "🦠",
        "desc": "AI检测到的高置信度恶意进程或文件，建议立即处理"},
    2: {"label": "疑似病毒", "color": "#FF9500", "icon": "⚠️",
        "desc": "行为可疑但未达到病毒判定阈值，需人工确认"},
    3: {"label": "安全问题", "color": "#007AFF", "icon": "🔓",
        "desc": "系统安全隐患：可疑网络连接、异常启动项、弱配置等"},
    4: {"label": "其他风险", "color": "#AF52DE", "icon": "📋",
        "desc": "低风险项，建议定期检查"},
}


class FullSecurityScanner:
    """全盘安全扫描器 — 整合进程/网络/启动项/关键目录扫描"""

    def __init__(self, security_monitor=None):
        self._monitor = security_monitor
        self._ai = SecurityAIInference()
        self._ai.load()
        self._collector = ProcessFeatureCollector()
        self.results = {1: [], 2: [], 3: [], 4: []}
        self.scan_time_ms = 0
        self.total_issues = 0
        self._signature_cache = {}

    def run_full_scan(self, progress_cb=None):
        start = time.time()
        self.results = {1: [], 2: [], 3: [], 4: []}
        self.total_issues = 0

        if progress_cb:
            progress_cb("正在扫描进程...")
        self._scan_processes()

        if progress_cb:
            progress_cb("正在扫描网络连接...")
        self._scan_network()

        if progress_cb:
            progress_cb("正在扫描启动项...")
        self._scan_startup_items()

        if progress_cb:
            progress_cb("正在扫描关键目录...")
        self._scan_suspicious_files()

        for cat_id in self.results:
            self.total_issues += len(self.results[cat_id])
        self.scan_time_ms = int((time.time() - start) * 1000)
        return self.results

    def _classify_issue(self, item):
        """根据风险等级自动分类到 1-4"""
        risk = item.get("risk_level", "low")
        conf = item.get("confidence", 0)
        source = item.get("source", "")
        cls_id = item.get("class_id", 0)

        if source == "process":
            if cls_id == 3 and conf > 0.95:
                return 1
            elif cls_id >= 2 and conf > 0.85:
                return 2
            elif cls_id >= 1 and conf > 0.70:
                return 3
            else:
                return 4
        elif source == "network":
            net_risk = item.get("combined_risk", 0)
            if net_risk > 0.9:
                return 1
            elif net_risk > 0.7:
                return 2
            elif net_risk > 0.5:
                return 3
            else:
                return 4
        elif source == "startup":
            if risk == "high":
                return 2
            elif risk == "medium":
                return 3
            else:
                return 4
        elif source == "suspicious_file":
            if risk == "high":
                return 2
            elif risk == "medium":
                return 3
            else:
                return 4
        return 4

    def _scan_processes(self):
        psutil_mod = None
        try:
            import psutil
            psutil_mod = psutil
        except ImportError:
            return

        for proc in psutil_mod.process_iter(['pid']):
            try:
                try:
                    pid = proc.pid
                    name = proc.name()
                    exe = proc.exe() or ""
                except (psutil_mod.AccessDenied, psutil_mod.NoSuchProcess):
                    continue

                if pid == 0 or pid == 4:
                    continue

                if self._is_system_safe(name, exe):
                    continue

                features = self._collector.collect_process_features(proc)
                if features is None:
                    continue

                if self._ai.loaded:
                    cls_id, conf, probs = self._ai.predict(features)
                else:
                    name_lower = name.lower()
                    suspicious = any(kw in name_lower for kw in [
                        "miner", "hack", "crack", "keygen", "trojan", "virus", "rat",
                    ])
                    cls_id = 2 if suspicious else 0
                    conf = 0.7 if suspicious else 0.5
                    probs = [0.25] * 4

                if cls_id >= 1 and conf > 0.70:
                    signed, signer = self._check_sig(exe)
                    item = {
                        "source": "process",
                        "pid": pid,
                        "name": name,
                        "path": exe,
                        "classification": SECURITY_CLASS_NAMES[cls_id],
                        "class_id": cls_id,
                        "confidence": conf,
                        "probabilities": probs,
                        "is_signed": signed,
                        "signer": signer,
                        "risk_level": "high" if conf > 0.95 else (
                            "medium" if conf > 0.85 else "low"),
                        "description": self._describe_process(cls_id, conf, signed),
                        "action_type": "terminate",
                    }
                    cat = self._classify_issue(item)
                    self.results[cat].append(item)

            except (psutil_mod.NoSuchProcess, psutil_mod.AccessDenied,
                    psutil_mod.ZombieProcess):
                continue

    def _scan_network(self):
        scan_results = None
        if self._monitor:
            try:
                scan_results = self._monitor.scan_network_connections()
            except Exception:
                pass
        if not scan_results:
            try:
                temp_mon = SecurityMonitor(SecurityAIInference())
                scan_results = temp_mon.scan_network_connections()
            except Exception:
                return

        for conn in scan_results:
            if conn.get("is_suspicious", False):
                item = {
                    "source": "network",
                    "pid": conn["pid"],
                    "name": conn["name"],
                    "path": conn.get("exe", ""),
                    "remote_count": conn.get("remote_count", 0),
                    "suspicious_port_count": conn.get("suspicious_port_count", 0),
                    "net_risk": conn.get("combined_risk", 0),
                    "ai_classification": conn.get("ai_classification", ""),
                    "confidence": conn.get("ai_confidence", 0),
                    "combined_risk": conn.get("combined_risk", 0),
                    "risk_level": "high" if conn.get("combined_risk", 0) > 0.85 else (
                        "medium" if conn.get("combined_risk", 0) > 0.6 else "low"),
                    "connections": conn.get("connections", []),
                    "description": self._describe_network(conn),
                    "action_type": "block_network",
                }
                cat = self._classify_issue(item)
                self.results[cat].append(item)

    def _scan_startup_items(self):
        """扫描注册表和启动文件夹的启动项"""
        startup_keys = [
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hkey, subkey in startup_keys:
            try:
                key = winreg.OpenKey(hkey, subkey, 0,
                                     winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                idx = 0
                while True:
                    try:
                        val_name, val_data, val_type = winreg.EnumValue(key, idx)
                        idx += 1
                        risk, desc = self._analyze_startup_entry(val_name, val_data)
                        if risk in ("high", "medium"):
                            item = {
                                "source": "startup",
                                "name": val_name,
                                "command": val_data,
                                "registry_key": f"{'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{subkey}",
                                "risk_level": risk,
                                "confidence": 0.85 if risk == "high" else 0.65,
                                "description": desc,
                                "action_type": "remove_startup",
                            }
                            cat = self._classify_issue(item)
                            self.results[cat].append(item)
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                continue

        startup_folders = [
            os.path.join(os.environ.get("APPDATA", ""),
                         r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(os.environ.get("PROGRAMDATA", ""),
                         r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for sf in startup_folders:
            if not os.path.exists(sf):
                continue
            try:
                for fname in os.listdir(sf):
                    fpath = os.path.join(sf, fname)
                    if fname.lower().endswith(('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr')):
                        signed, signer = self._check_sig(fpath)
                        if not signed:
                            item = {
                                "source": "startup",
                                "name": fname,
                                "command": fpath,
                                "registry_key": f"启动文件夹: {sf}",
                                "risk_level": "medium",
                                "confidence": 0.70,
                                "description": f"启动文件夹中存在无数字签名程序: {fname}",
                                "action_type": "remove_startup",
                            }
                            cat = self._classify_issue(item)
                            self.results[cat].append(item)
            except (PermissionError, OSError):
                continue

    def _scan_suspicious_files(self):
        """扫描用户目录中的可疑可执行文件"""
        suspicious_exts = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr',
                          '.msi', '.jar', '.wsf', '.hta'}
        scan_roots = []
        userprofile = os.environ.get("USERPROFILE", "")
        if userprofile:
            scan_roots.append(os.path.join(userprofile, "Downloads"))
            scan_roots.append(os.path.join(userprofile, "Desktop"))
            scan_roots.append(os.path.join(userprofile, "Documents"))
        tmp = os.environ.get("TEMP", "")
        if tmp:
            scan_roots.append(tmp)

        locked_dirs = _build_system_locked_dirs()
        checked = set()

        for root_dir in scan_roots:
            if not os.path.exists(root_dir):
                continue
            for dirpath, dirnames, filenames in os.walk(root_dir):
                if len(checked) > 5000:
                    break
                depth = dirpath.replace(root_dir, "").count(os.sep)
                if depth > 4:
                    dirnames.clear()
                    continue
                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in suspicious_exts:
                        continue
                    fpath = os.path.join(dirpath, fname)
                    if fpath in checked:
                        continue
                    checked.add(fpath)
                    try:
                        norm = os.path.normpath(fpath)
                        if any(norm.lower().startswith(d.lower()) for d in locked_dirs):
                            continue
                        stat = os.stat(fpath)
                        signed, signer = self._check_sig(fpath)
                        if signed:
                            continue
                        risk = "high" if ext in ('.bat', '.ps1', '.vbs', '.scr') else "medium"
                        name_lower = fname.lower()
                        susp_names = ["crack", "keygen", "patch", "hack", "cheat",
                                      "inject", "loader", "activator", "bypass"]
                        if any(kw in name_lower for kw in susp_names):
                            risk = "high"
                        item = {
                            "source": "suspicious_file",
                            "name": fname,
                            "path": fpath,
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "is_signed": False,
                            "signer": "",
                            "risk_level": risk,
                            "confidence": 0.90 if risk == "high" else 0.70,
                            "description": self._describe_file(fname, fpath, risk),
                            "action_type": "delete_file",
                        }
                        cat = self._classify_issue(item)
                        self.results[cat].append(item)
                    except (PermissionError, OSError):
                        continue

    def _check_sig(self, path):
        if not path or not os.path.isfile(path):
            return False, ""
        path_lower = path.lower()
        if path_lower in self._signature_cache:
            return self._signature_cache[path_lower]
        try:
            result = _verify_signature_winapi(path)
        except Exception:
            result = False
        self._signature_cache[path_lower] = (result, "")
        return result, ""

    def _is_system_safe(self, name, exe):
        name_lower = name.lower()
        exe_lower = (exe or "").lower()
        system_procs = {
            "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe", "dwm.exe",
            "fontdrvhost.exe", "lsaiso.exe", "registry.exe",
            "explorer.exe", "taskhostw.exe", "conhost.exe",
            "sihost.exe", "ctfmon.exe", "dllhost.exe", "runtimebroker.exe",
            "searchindexer.exe", "spoolsv.exe", "audiodg.exe",
            "wudfhost.exe", "system", "system idle process", "memory compression",
            "registry", "winlogon.exe",
        }
        if name_lower in system_procs:
            return True
        if exe_lower.startswith("c:\\windows"):
            return True
        if "\\program files" in exe_lower:
            signed, _ = self._check_sig(exe)
            return signed
        return False

    def _describe_process(self, cls_id, conf, signed):
        cls_name = SECURITY_CLASS_NAMES[cls_id]
        if cls_id == 3:
            return f"AI检测为【{cls_name}】(置信度{conf:.0%})，建议立即终止并隔离"
        elif cls_id == 2:
            sig_info = "有数字签名" if signed else "无数字签名"
            return f"AI检测为【{cls_name}】(置信度{conf:.0%})，{sig_info}，建议进一步分析"
        elif cls_id == 1:
            return f"AI检测为【{cls_name}】(置信度{conf:.0%})，存在可疑行为特征"
        return f"进程行为偏离正常模式 (置信度{conf:.0%})"

    def _describe_network(self, conn):
        parts = []
        if conn.get("suspicious_port_count", 0) > 0:
            parts.append(f"监听可疑端口({conn['suspicious_port_count']}个)")
        if conn.get("remote_count", 0) > 10:
            parts.append(f"大量外部连接({conn['remote_count']}个)")
        if conn.get("listen_count", 0) > 5:
            parts.append(f"大量监听端口({conn['listen_count']}个)")
        if not parts:
            parts.append("网络行为异常")
        return "；".join(parts)

    def _describe_file(self, fname, fpath, risk):
        ext = os.path.splitext(fname)[1].lower()
        ext_desc = {
            '.bat': '批处理脚本', '.ps1': 'PowerShell脚本',
            '.vbs': 'VBScript脚本', '.scr': '屏幕保护程序(可执行)',
            '.exe': '可执行文件', '.dll': '动态链接库',
        }
        etype = ext_desc.get(ext, f'{ext}文件')
        loc = "下载目录" if "\\downloads\\" in fpath.lower() else (
            "桌面" if "\\desktop\\" in fpath.lower() else "用户目录")
        if risk == "high":
            return f"可疑{etype}，位于{loc}，无数字签名，建议立即检查"
        return f"无签名{etype}，位于{loc}，建议验证来源"

    def _analyze_startup_entry(self, name, command):
        cmd_lower = command.lower()
        name_lower = name.lower()
        suspicious_kw = [
            "temp", "appdata\\local\\temp", "downloads", "public",
            "hack", "crack", "keygen", "patch", "inject", "miner",
            "bypass", "stealer", "trojan",
        ]
        high_risk_kw = ["hack", "crack", "keygen", "trojan", "stealer", "miner", "inject"]
        for kw in high_risk_kw:
            if kw in cmd_lower or kw in name_lower:
                return "high", f"启动项名称/路径包含高危关键字: {kw}"
        for kw in suspicious_kw:
            if kw in cmd_lower:
                return "medium", f"启动项路径包含可疑关键字: {kw}"
        if "\\appdata\\" in cmd_lower and "\\temp\\" in cmd_lower:
            return "medium", "启动项位于临时目录"
        if cmd_lower.startswith("c:\\windows") or cmd_lower.startswith("c:\\program files"):
            return "low", "启动项位于系统/程序目录（正常）"
        exe_path = command.split('"')[1] if '"' in command else command.split()[0] if command.split() else command
        if os.path.isfile(exe_path):
            signed, _ = self._check_sig(exe_path)
            if not signed:
                return "medium", f"启动项程序无数字签名: {os.path.basename(exe_path)}"
        return "low", "启动项正常"

    def execute_action(self, selected_items):
        """对选中的问题执行处理操作"""
        results = {"terminated": 0, "deleted": 0, "removed_startup": 0, "failed": 0}
        for item in selected_items:
            action = item.get("action_type", "")
            try:
                if action == "terminate":
                    pid = item.get("pid", 0)
                    if pid > 0:
                        try:
                            import psutil
                            proc = psutil.Process(pid)
                            proc.terminate()
                            proc.wait(timeout=5)
                        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                            pass
                    exe_path = item.get("path", "")
                    if exe_path and os.path.isfile(exe_path):
                        if _send_to_recycle_bin(exe_path):
                            results["deleted"] += 1
                        else:
                            results["failed"] += 1
                    results["terminated"] += 1

                elif action == "delete_file":
                    path = item.get("path", "")
                    if path and os.path.isfile(path):
                        if _send_to_recycle_bin(path):
                            results["deleted"] += 1
                        else:
                            results["failed"] += 1

                elif action == "remove_startup":
                    cmd = item.get("command", "")
                    reg_key = item.get("registry_key", "")
                    if "启动文件夹:" in reg_key:
                        fpath = cmd
                        if os.path.isfile(fpath):
                            if _send_to_recycle_bin(fpath):
                                results["removed_startup"] += 1
                            else:
                                results["failed"] += 1
                    elif "HKCU" in reg_key:
                        self._remove_reg_startup(winreg.HKEY_CURRENT_USER, reg_key, item["name"])
                        results["removed_startup"] += 1
                    elif "HKLM" in reg_key:
                        self._remove_reg_startup(winreg.HKEY_LOCAL_MACHINE, reg_key, item["name"])
                        results["removed_startup"] += 1

                elif action == "block_network":
                    pid = item.get("pid", 0)
                    if pid > 0:
                        try:
                            import psutil
                            proc = psutil.Process(pid)
                            proc.terminate()
                            results["terminated"] += 1
                        except Exception:
                            results["failed"] += 1
            except Exception:
                results["failed"] += 1
        return results

    def _remove_reg_startup(self, hkey_base, full_key, value_name):
        """从注册表移除启动项"""
        parts = full_key.split("\\", 1)
        if len(parts) < 2:
            return
        subkey = parts[1]
        try:
            key = winreg.OpenKey(hkey_base, subkey, 0,
                                 winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
        except OSError:
            pass


# ============================================================
# C盘空间分析器
# ============================================================

class DriveAnalyzer:
    """C盘空间分析 — 完整递归扫描所有目录，精确计算各类文件占用"""

    def __init__(self):
        self._locked_dirs = _build_system_locked_dirs()
        self._program_dirs = _get_program_files_dirs()
        self._windir = _get_windows_dir()
        self._sysdrive = os.environ.get("SystemDrive", "C:")
        self._total_files_scanned = 0
        self._max_files = 1000000

    def analyze(self, progress_cb=None):
        """analyze with progress: progress_cb receives (fraction, message)"""
        def _report(pct, msg):
            if progress_cb:
                try:
                    progress_cb(pct, msg)
                except Exception:
                    pass

        result = {
            "system_size": 0, "system_count": 0,
            "program_size": 0, "program_count": 0,
            "user_size": 0, "user_count": 0,
            "other_size": 0, "other_count": 0,
            "large_files": [],
            "total_used": 0, "total_free": 0, "total_capacity": 0,
        }

        _report(0.00, "正在获取磁盘信息...")
        try:
            self._get_disk_space(result)
        except Exception as e:
            _report(0.05, f"磁盘信息获取失败: {e}")
        self._total_files_scanned = 0

        phase_defs = [
            (0.05, 0.30, "system", t("scan_phase_system")),
            (0.30, 0.55, "program", t("scan_phase_program")),
            (0.55, 0.70, "user", t("scan_phase_user")),
            (0.70, 0.85, "other", t("scan_phase_other")),
        ]

        for start_pct, end_pct, cat, msg in phase_defs:
            _report(start_pct, msg)
            try:
                self._scan_category(cat, result, progress_cb, start_pct, end_pct)
            except Exception as e:
                _report(end_pct, f"{msg}: {e}")
            _report(end_pct, msg + " 完成")

        _report(0.85, "正在扫描大文件 (>100MB)...")
        try:
            self._find_large_files(result, None)
        except Exception as e:
            _report(0.95, f"Large file scan: {e}")

        _report(1.00, "分析完成")
        result["total_used"] = (result["system_size"] + result["program_size"] +
                                 result["user_size"] + result["other_size"])
        return result

    def _get_disk_space(self, result):
        try:
            free_bytes = ctypes.c_ulonglong(0)
            total_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(self._sysdrive + "\\"),
                None, ctypes.byref(total_bytes), ctypes.byref(free_bytes))
            result["total_free"] = free_bytes.value
            result["total_capacity"] = total_bytes.value
        except Exception:
            pass

    def _scan_category(self, category, result, progress_cb,
                        phase_start, phase_end):
        windir_norm = os.path.normpath(self._windir).lower()
        program_dirs_norm = [os.path.normpath(p).lower() for p in self._program_dirs]
        drive_root = self._sysdrive + "\\"

        def _dir_progress(file_count, dir_name):
            if progress_cb:
                pct = phase_start + min(
                    file_count / max(self._max_files * 0.5, 1), 1.0
                ) * (phase_end - phase_start)
                progress_cb(min(pct, phase_end),
                           f"已扫描 {file_count} 个文件 ({dir_name})...")

        if category == "system":
            sz, cnt = self._get_dir_size_fast(self._windir, _dir_progress)
            result["system_size"] += sz
            result["system_count"] += cnt
        elif category == "program":
            for pd in self._program_dirs:
                if os.path.exists(pd):
                    sz, cnt = self._get_dir_size_fast(pd, _dir_progress)
                    result["program_size"] += sz
                    result["program_count"] += cnt
            programdata = os.path.join(self._sysdrive + "\\", "ProgramData")
            if os.path.exists(programdata):
                sz, cnt = self._get_dir_size_fast(programdata, _dir_progress)
                result["program_size"] += sz
                result["program_count"] += cnt
        elif category == "user":
            users_dir = os.path.join(self._sysdrive + "\\", "Users")
            if os.path.exists(users_dir):
                sz, cnt = self._get_dir_size_fast(users_dir, _dir_progress)
                result["user_size"] += sz
                result["user_count"] += cnt
        elif category == "other":
            try:
                for entry in os.scandir(drive_root):
                    if self._total_files_scanned > self._max_files:
                        break
                    try:
                        path_norm = os.path.normpath(entry.path).lower()
                        if path_norm == windir_norm:
                            continue
                        if any(path_norm == pn or path_norm.startswith(pn + "\\")
                               for pn in program_dirs_norm):
                            continue
                        if entry.name in ("Users", "ProgramData"):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            sz, cnt = self._get_dir_size_fast(entry.path, _dir_progress)
                            result["other_size"] += sz
                            result["other_count"] += cnt
                        elif entry.is_file(follow_symlinks=False):
                            sz = entry.stat(follow_symlinks=False).st_size
                            result["other_size"] += sz
                            result["other_count"] += 1
                            self._total_files_scanned += 1
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                pass

    def _get_dir_size_fast(self, root, progress_cb=None):
        """os.walk（正确处理 Windows junctions）+ os.scandir（快速 stat）"""
        total = 0
        count = 0
        basename = os.path.basename(root)
        root_depth = root.rstrip("\\").count(os.sep)
        last_report = 0
        report_interval = 2000
        time_start = time.time()

        def _onerror(err):
            pass  # 静默跳过权限错误

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False,
                                                     onerror=_onerror):
            if time.time() - time_start > 120:
                return total, count
            if self._total_files_scanned > self._max_files:
                return total, count
            depth = dirpath.count(os.sep) - root_depth
            if depth > 18:
                dirnames.clear()
            try:
                for entry in os.scandir(dirpath):
                    if time.time() - time_start > 120:
                        return total, count
                    try:
                        if entry.is_file(follow_symlinks=False):
                            sz = entry.stat(follow_symlinks=False).st_size
                            total += sz
                            count += 1
                            self._total_files_scanned += 1
                            if progress_cb and count - last_report >= report_interval:
                                progress_cb(count, basename)
                                last_report = count
                    except OSError:
                        continue
            except OSError:
                continue
        return total, count

    def _find_large_files(self, result, progress_cb=None):
        """查找大于100MB的大文件"""
        large = []
        scan_roots = [self._sysdrive + "\\"]
        scanned = 0
        for root_dir in scan_roots:
            if not os.path.exists(root_dir):
                continue
            for dirpath, dirnames, filenames in os.walk(root_dir):
                if scanned > 500000 or len(large) > 5000:
                    break
                depth = dirpath.count(os.sep) - (root_dir.count(os.sep) - 1)
                dirnames[:] = [d for d in dirnames if not d.startswith("$") and
                               d not in ("System Volume Information",)]
                if depth > 12:
                    dirnames.clear()
                for fname in filenames:
                    if len(large) > 5000:
                        break
                    fpath = os.path.join(dirpath, fname)
                    try:
                        sz = os.path.getsize(fpath)
                        if sz > 100 * 1024 * 1024:
                            can_delete = self._can_safely_delete(fpath)
                            large.append({
                                "path": fpath,
                                "size": sz,
                                "mtime": os.path.getmtime(fpath),
                                "can_delete": can_delete,
                                "delete_reason": self._delete_reason(fpath, can_delete),
                            })
                        scanned += 1
                        if progress_cb and scanned % 10000 == 0:
                            progress_cb(f"已扫描 {scanned} 个文件, 发现 {len(large)} 个大文件...")
                    except (PermissionError, OSError):
                        continue

        large.sort(key=lambda x: x["size"], reverse=True)
        result["large_files"] = large[:200]
        result["large_files_size"] = sum(f["size"] for f in large)
        result["large_files_count"] = len(large)

    def _can_safely_delete(self, fpath):
        norm = os.path.normpath(fpath).lower()
        ext = os.path.splitext(fpath)[1].lower()
        safe_patterns = [
            "\\downloads\\", "\\temp\\", "\\tmp\\", "\\cache\\",
            "\\download\\", "\\crashdumps\\", "\\logs\\",
        ]
        if any(p in norm for p in safe_patterns):
            return True
        safe_exts = {".tmp", ".temp", ".bak", ".old", ".log", ".dmp",
                      ".zip", ".rar", ".7z", ".iso", ".msi", ".cab"}
        if ext in safe_exts:
            return True
        if "\\appdata\\local\\temp\\" in norm:
            return True
        return False

    def _delete_reason(self, fpath, can_delete):
        if not can_delete:
            path_lower = fpath.lower()
            if "\\windows\\" in path_lower:
                return "系统文件，禁止删除"
            if "\\program files" in path_lower:
                return "软件文件，删除可能导致软件异常"
            if "\\programdata\\" in path_lower:
                return "软件数据文件"
            return "未知风险，建议保留"
        ext = os.path.splitext(fpath)[1].lower()
        if ext in (".zip", ".rar", ".7z", ".iso"):
            return "压缩/镜像文件，确认无用后可删除"
        if ext in (".tmp", ".temp", ".bak", ".old"):
            return "临时/备份文件，可安全删除"
        if ext in (".dmp", ".log"):
            return "日志/转储文件，可安全删除"
        if "\\downloads\\" in fpath.lower():
            return "下载目录文件，确认无用后可删除"
        if "\\temp\\" in fpath.lower():
            return "临时目录文件，可安全删除"
        return "可清理文件"

    def list_category_files(self, category, progress_cb=None):
        """列出指定分类的所有文件，含重要性、可删性元数据"""
        files = []
        if category == "system":
            roots = [self._windir]
        elif category == "program":
            roots = [pd for pd in self._program_dirs if os.path.exists(pd)]
            programdata = os.path.join(self._sysdrive + "\\", "ProgramData")
            if os.path.exists(programdata):
                roots.append(programdata)
        elif category == "user":
            userprofile = os.environ.get("USERPROFILE", "")
            roots = [userprofile] if userprofile else []
        elif category == "other":
            windir_norm = os.path.normpath(self._windir).lower()
            program_norm = [os.path.normpath(p).lower() for p in self._program_dirs]
            roots = []
            try:
                for entry in os.scandir(self._sysdrive + "\\"):
                    try:
                        path_norm = os.path.normpath(entry.path).lower()
                        if path_norm == windir_norm:
                            continue
                        if any(path_norm == pn or path_norm.startswith(pn + "\\")
                               for pn in program_norm):
                            continue
                        if entry.name in ("Users", "ProgramData"):
                            continue
                        roots.append(entry.path)
                    except OSError:
                        continue
            except OSError:
                pass
        else:
            return files

        scanned = 0
        max_files = 200000
        for root in roots:
            if not os.path.exists(root):
                continue
            if progress_cb:
                progress_cb(f"正在扫描: {os.path.basename(root)}...")
            try:
                for dirpath, dirnames, filenames in os.walk(root):
                    if scanned > max_files:
                        break
                    depth = dirpath.count(os.sep) - root.count(os.sep)
                    if depth > 15:
                        dirnames.clear()
                    for fname in filenames:
                        if scanned > max_files:
                            break
                        fpath = os.path.join(dirpath, fname)
                        try:
                            sz = os.path.getsize(fpath)
                            importance, can_delete, reason = self._classify_importance(
                                fpath, category)
                            files.append({
                                "path": fpath,
                                "size": sz,
                                "importance": importance,
                                "can_delete": can_delete,
                                "reason": reason,
                            })
                            scanned += 1
                            if progress_cb and scanned % 5000 == 0:
                                progress_cb(f"已扫描 {scanned} 个文件...")
                        except OSError:
                            continue
            except (PermissionError, OSError):
                continue

        files.sort(key=lambda x: x["size"], reverse=True)
        return files

    def _classify_importance(self, fpath, category):
        """根据文件路径判断重要性等级"""
        path_lower = os.path.normpath(fpath).lower()
        ext = os.path.splitext(fpath)[1].lower()
        windir_lower = self._windir.lower()

        sys_core_dirs = ["\\system32\\", "\\syswow64\\", "\\drivers\\",
                         "\\boot\\", "\\efi\\", "\\winsxs\\"]
        sys_cache_dirs = ["\\temp\\", "\\logs\\", "\\prefetch\\",
                          "\\softwaredistribution\\", "\\crashdumps\\"]
        user_important_dirs = ["\\documents\\", "\\desktop\\", "\\pictures\\",
                               "\\music\\", "\\videos\\", "\\downloads\\"]
        user_temp_dirs = ["\\appdata\\local\\temp\\", "\\appdata\\local\\crashdumps\\"]
        program_exe_exts = {".exe", ".dll", ".sys", ".msi"}
        cleanable_exts = {".tmp", ".temp", ".bak", ".old", ".log", ".dmp", ".cache"}

        if category == "system":
            if any(d in path_lower for d in sys_core_dirs):
                return ("系统核心", False, "系统核心文件，删除将导致系统崩溃")
            if ext in (".exe", ".dll", ".sys") and path_lower.startswith(windir_lower):
                return ("系统文件", False, "系统运行必需文件，禁止删除")
            if any(d in path_lower for d in sys_cache_dirs):
                return ("系统缓存", True, "系统缓存文件，可安全清理")
            if ext in cleanable_exts:
                return ("系统日志", True, "系统日志/临时文件，可安全清理")
            return ("系统其他", False, "系统目录文件，不建议删除")

        elif category == "program":
            if ext in program_exe_exts:
                return ("软件程序", False, "软件运行必需的可执行文件")
            if "\\uninstall\\" in path_lower or "uninst" in os.path.basename(fpath).lower():
                return ("卸载程序", False, "软件卸载程序，建议保留")
            if ext in cleanable_exts:
                return ("软件缓存", True, "软件产生的临时/缓存文件")
            if "\\cache\\" in path_lower or "\\temp\\" in path_lower:
                return ("软件缓存", True, "软件缓存数据，可安全清理")
            if "\\installer\\" in path_lower:
                return ("安装包", True, "安装包缓存，确认无用后可删除")
            return ("软件数据", False, "软件数据文件，删除可能导致软件异常")

        elif category == "user":
            if any(d in path_lower for d in user_important_dirs):
                if ext in cleanable_exts:
                    return ("个人临时", True, "个人目录中的临时文件")
                return ("个人重要", False, "用户个人文件，不建议删除")
            if any(d in path_lower for d in user_temp_dirs):
                return ("应用缓存", True, "应用程序缓存，可安全清理")
            if "\\appdata\\" in path_lower:
                if ext in cleanable_exts:
                    return ("应用缓存", True, "应用缓存文件，可安全清理")
                return ("应用数据", False, "应用程序数据，删除可能影响软件使用")
            return ("用户文件", False, "用户目录文件，建议保留")

        else:
            if ext in cleanable_exts:
                return ("临时文件", True, "临时/缓存文件，可清理")
            if ext in program_exe_exts:
                return ("可执行文件", False, "可执行文件，确认来源后可删除")
            return ("其他文件", False, "未分类文件，建议保留")
