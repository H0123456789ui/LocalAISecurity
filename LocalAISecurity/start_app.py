import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import sys
import os
import pystray

from i18n import t, set_language, get_language, LANG_OPTIONS

from ai_engine import (
    SecurityAIInference, SecurityMonitor,
    SECURITY_CLASS_NAMES,
)
from scanner import DiskScanner, format_size, FILE_CLASS, FullSecurityScanner, DriveAnalyzer

from ui_components import (
    AppleStyle, GlassButton, GlassCard, StartupDialog, ScanDetailWindow,
    SecurityScanWindow,
    load_config, save_config, is_auto_start_enabled, set_auto_start,
    create_tray_icon_image, APP_NAME,
)


class AISecurityApp:
    def __init__(self, root, start_minimized=False):
        self.root = root
        self.root.title(t("app_title"))
        self.root.geometry("700x580")
        self.root.resizable(False, False)
        self.root.configure(bg=AppleStyle.BG)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.is_running = False
        self.tray_icon = None
        self._closing = False
        self.scanner = DiskScanner()

        self.security_ai = SecurityAIInference()
        sec_loaded = self.security_ai.load()
        if sec_loaded:
            print("[AI] Security AI model loaded (PyTorch CNN)")
        else:
            print(f"[AI] Security AI model load failed: {self.security_ai.load_error}")

        self.security_monitor = SecurityMonitor(
            self.security_ai,
            on_threat=self._on_threat_detected
        )
        self._psutil_available = self.security_monitor.collector.is_available()
        if not self._psutil_available:
            print("[WARN] psutil not installed, security monitor unavailable")

        self._widgets_to_refresh = []
        self._build_ui()
        self.setup_tray()
        self.root.bind("<Unmap>", self.on_minimize)
        if start_minimized:
            self.root.after(100, self.hide_to_tray)

    def _build_ui(self):
        for w in self.root.winfo_children():
            w.destroy()

        main = tk.Frame(self.root, bg=AppleStyle.BG, padx=24, pady=16)
        main.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(main, bg=AppleStyle.BG)
        header.pack(fill=tk.X, pady=(0, 12))
        self._title_lbl = tk.Label(header, text="🔒 " + t("app_title"),
                                     font=("微软雅黑", 22, "bold"),
                                     bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY)
        self._title_lbl.pack(anchor="w")
        self._subtitle_lbl = tk.Label(header, text=t("app_subtitle"), font=("微软雅黑", 10),
                                       bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY)
        self._subtitle_lbl.pack(anchor="w", pady=(2, 0))

        status_area = tk.Frame(main, bg=AppleStyle.BG)
        status_area.pack(fill=tk.X, pady=(0, 12))

        sec_card = GlassCard(status_area)
        sec_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        self._sec_card_title = tk.Label(sec_card, text=t("card_security"),
                                         font=("微软雅黑", 16, "bold"),
                                         bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_PRIMARY)
        self._sec_card_title.pack(anchor="w")
        self.sec_status_lbl = tk.Label(sec_card, text=t("status_ready"),
                                        font=("微软雅黑", 12),
                                        bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_TERTIARY)
        self.sec_status_lbl.pack(anchor="w", pady=(4, 0))
        self.sec_progress = ttk.Progressbar(sec_card, orient=tk.HORIZONTAL, length=220, mode='indeterminate')
        self.sec_progress.pack(fill=tk.X, pady=(8, 0))

        clean_card = GlassCard(status_area)
        clean_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(6, 0))
        self._clean_card_title = tk.Label(clean_card, text=t("card_clean"),
                                           font=("微软雅黑", 16, "bold"),
                                           bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_PRIMARY)
        self._clean_card_title.pack(anchor="w")
        self.clean_status_lbl = tk.Label(clean_card, text=t("status_ready"),
                                          font=("微软雅黑", 12),
                                          bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_TERTIARY)
        self.clean_status_lbl.pack(anchor="w", pady=(4, 0))
        self.clean_progress = ttk.Progressbar(clean_card, orient=tk.HORIZONTAL, length=220, mode='indeterminate')
        self.clean_progress.pack(fill=tk.X, pady=(8, 0))

        btn_area = tk.Frame(main, bg=AppleStyle.BG)
        btn_area.pack(fill=tk.X, pady=(0, 8))
        GlassButton(btn_area, text=t("btn_start"), command=self.start_protection,
                    color=AppleStyle.ACCENT_GREEN, width=150, height=42).pack(side=tk.LEFT, padx=4)
        GlassButton(btn_area, text=t("btn_stop"), command=self.stop_protection,
                    color=AppleStyle.ACCENT_ORANGE, width=150, height=42).pack(side=tk.LEFT, padx=4)
        GlassButton(btn_area, text=t("btn_scan_c"), command=self.scan_drive,
                    color=AppleStyle.ACCENT_BLUE, width=150, height=42).pack(side=tk.LEFT, padx=4)
        GlassButton(btn_area, text=t("btn_full_scan"), command=self.full_security_scan,
                    color=AppleStyle.ACCENT_RED, width=150, height=42).pack(side=tk.LEFT, padx=4)

        settings_area = tk.Frame(main, bg=AppleStyle.BG)
        settings_area.pack(fill=tk.X, pady=(0, 8))
        self.auto_start_var = tk.BooleanVar(value=is_auto_start_enabled())
        self._auto_cb = tk.Checkbutton(settings_area, text=t("setting_autostart"),
                                        variable=self.auto_start_var,
                                        command=self.toggle_auto_start, font=("微软雅黑", 10),
                                        bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY,
                                        activebackground=AppleStyle.BG, activeforeground=AppleStyle.TEXT_PRIMARY,
                                        selectcolor=AppleStyle.CARD_BG)
        self._auto_cb.pack(side=tk.LEFT, padx=4)

        self.start_minimized_var = tk.BooleanVar(value=load_config().get("start_minimized", False))
        self._min_cb = tk.Checkbutton(settings_area, text=t("setting_minimized"),
                                       variable=self.start_minimized_var,
                                       command=self.toggle_start_minimized, font=("微软雅黑", 10),
                                       bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY,
                                       activebackground=AppleStyle.BG, activeforeground=AppleStyle.TEXT_PRIMARY,
                                       selectcolor=AppleStyle.CARD_BG)
        self._min_cb.pack(side=tk.LEFT, padx=4)

        lang_frame = tk.Frame(settings_area, bg=AppleStyle.BG)
        lang_frame.pack(side=tk.RIGHT, padx=4)
        tk.Label(lang_frame, text=t("setting_language") + ": ", font=("微软雅黑", 10),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY).pack(side=tk.LEFT)
        self._lang_var = tk.StringVar(value=LANG_OPTIONS.get(get_language(), "简体中文"))
        lang_combo = ttk.Combobox(lang_frame, textvariable=self._lang_var,
                                   values=list(LANG_OPTIONS.values()), state="readonly",
                                   width=10)
        lang_combo.pack(side=tk.LEFT)
        lang_combo.bind("<<ComboboxSelected>>", self._on_lang_select)

        log_card = GlassCard(main)
        log_card.pack(fill=tk.BOTH, expand=True)
        self._log_title = tk.Label(log_card, text=t("label_log"), font=("微软雅黑", 12),
                                    bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_PRIMARY)
        self._log_title.pack(anchor="w", pady=(0, 4))
        self.log_text = tk.Text(log_card, height=8, state=tk.DISABLED, font=("Consolas", 9),
                                bg="#FAFAFA", fg=AppleStyle.TEXT_PRIMARY, relief=tk.FLAT,
                                padx=8, pady=6, wrap=tk.WORD,
                                insertbackground=AppleStyle.TEXT_PRIMARY,
                                selectbackground=AppleStyle.ACCENT_BLUE)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        for tag, color in [("green", AppleStyle.ACCENT_GREEN), ("red", AppleStyle.ACCENT_RED),
                           ("blue", AppleStyle.ACCENT_BLUE), ("orange", AppleStyle.ACCENT_ORANGE)]:
            self.log_text.tag_configure(tag, foreground=color)

        self._restore_status()

        self.add_log(t("log_init"), "blue")
        if self.security_ai.loaded:
            self.add_log(t("log_security_loaded"), "green")
        else:
            self.add_log(t("log_security_fail", error=self.security_ai.load_error), "red")
        if self.scanner.ai.model_loaded:
            self.add_log(t("log_clean_loaded"), "green")
        else:
            self.add_log(t("log_clean_fail", error=self.scanner.ai.ai.load_error), "red")
        if self._psutil_available:
            self.add_log(t("log_psutil_ok"), "green")
        else:
            self.add_log(t("log_psutil_fail"), "orange")
        self.add_log(t("log_tray_hint"), "blue")
        self.add_log(t("log_waiting"))

    def _restore_status(self):
        if self.is_running:
            self.sec_status_lbl.config(text=t("status_running"), fg=AppleStyle.ACCENT_GREEN)
            self.clean_status_lbl.config(text=t("status_running"), fg=AppleStyle.ACCENT_GREEN)
        else:
            self.sec_status_lbl.config(text=t("status_ready"), fg=AppleStyle.TEXT_TERTIARY)
            self.clean_status_lbl.config(text=t("status_ready"), fg=AppleStyle.TEXT_TERTIARY)

    def _on_lang_select(self, event=None):
        display = self._lang_var.get()
        lang_map = {v: k for k, v in LANG_OPTIONS.items()}
        lang = lang_map.get(display, "zh")
        set_language(lang)
        cfg = load_config()
        cfg["language"] = lang
        save_config(cfg)
        self.root.title(t("app_title"))
        self._rebuild_ui()
        self.add_log(t("log_lang_changed"), "blue")

    def _rebuild_ui(self):
        self._build_ui()

    def setup_tray(self):
        icon_image = create_tray_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem(t("tray_show"), self.show_from_tray, default=True),
            pystray.MenuItem(t("tray_start"), self.tray_start_protection),
            pystray.MenuItem(t("tray_stop"), self.tray_stop_protection),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(t("tray_exit"), self.quit_from_tray),
        )
        self.tray_icon = pystray.Icon(APP_NAME, icon_image, t("app_title"), menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def on_minimize(self, event):
        if self.root.state() == 'iconic':
            self.root.after(50, self.hide_to_tray)

    def hide_to_tray(self):
        self.root.withdraw()
        self.add_log(t("log_minimized"), "blue")

    def show_from_tray(self, icon=None, item=None):
        self.root.after(0, self._show_window)

    def _show_window(self):
        self.root.deiconify()
        self.root.state('normal')
        self.root.lift()
        self.root.focus_force()

    def tray_start_protection(self, icon=None, item=None):
        self.root.after(0, self.start_protection)

    def tray_stop_protection(self, icon=None, item=None):
        self.root.after(0, self.stop_protection)

    def quit_from_tray(self, icon=None, item=None):
        self._closing = True
        if self.tray_icon:
            self.root.after(0, self._stop_tray)
        self.root.after(0, self.root.destroy)

    def _stop_tray(self):
        try:
            self.tray_icon.stop()
        except Exception:
            pass

    def on_close(self):
        self.hide_to_tray()

    def toggle_auto_start(self):
        enabled = self.auto_start_var.get()
        if set_auto_start(enabled):
            cfg = load_config()
            cfg["auto_start"] = enabled
            save_config(cfg)
            self.add_log(t("log_autostart_on") if enabled else t("log_autostart_off"), "blue")
        else:
            self.auto_start_var.set(not enabled)
            self.add_log(t("log_autostart_fail"), "red")

    def toggle_start_minimized(self):
        cfg = load_config()
        cfg["start_minimized"] = self.start_minimized_var.get()
        save_config(cfg)

    def add_log(self, message, tag=None):
        try:
            self.log_text.config(state=tk.NORMAL)
            ts = time.strftime('%H:%M:%S')
            self.log_text.insert(tk.END, f"[{ts}] {message}\n", tag)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        except Exception:
            pass

    def start_protection(self):
        self.is_running = True
        self.sec_status_lbl.config(text=t("status_running"), fg=AppleStyle.ACCENT_GREEN)
        self.clean_status_lbl.config(text=t("status_running"), fg=AppleStyle.ACCENT_GREEN)
        self.sec_progress.start()
        self.clean_progress.start()
        self.add_log(t("log_protection_start"), "green")
        if self._psutil_available and self.security_ai.loaded:
            started = self.security_monitor.start()
            if started:
                self.add_log(t("log_monitor_started"), "green")
            else:
                self.add_log(t("log_monitor_fail"), "red")
        elif not self._psutil_available:
            self.add_log(t("log_psutil_only"), "orange")
        elif not self.security_ai.loaded:
            self.add_log(t("log_model_only"), "orange")
        self.add_log(t("log_dual_active"), "green")
        if self.tray_icon:
            self.tray_icon.title = t("tray_running")

    def stop_protection(self):
        self.is_running = False
        self.security_monitor.stop()
        self.sec_status_lbl.config(text=t("status_stopped"), fg=AppleStyle.TEXT_TERTIARY)
        self.clean_status_lbl.config(text=t("status_stopped"), fg=AppleStyle.TEXT_TERTIARY)
        self.sec_progress.stop()
        self.clean_progress.stop()
        self.add_log(t("log_all_stopped"), "orange")
        if self.tray_icon:
            self.tray_icon.title = t("tray_standby")

    def _on_threat_detected(self, threat_info):
        self.root.after(0, lambda: self.add_log(t("log_threat",
            name=threat_info['name'], pid=threat_info['pid'],
            cls=threat_info['classification'], conf=threat_info['confidence']), "red"))
        self.root.after(0, lambda: self._show_threat_alert(threat_info))

    def _show_threat_alert(self, threat_info):
        try:
            result = messagebox.askyesnocancel(
                t("threat_title"),
                t("threat_msg", name=threat_info['name'], pid=threat_info['pid'],
                  path=threat_info['exe'], cls=threat_info['classification'],
                  conf=threat_info['confidence']),
                parent=self.root
            )
            if result is True:
                try:
                    import psutil
                    proc = psutil.Process(threat_info['pid'])
                    proc.terminate()
                    self.add_log(t("log_terminated",
                                   name=threat_info['name'], pid=threat_info['pid']), "green")
                except Exception as e:
                    self.add_log(t("log_terminate_fail", error=str(e)), "red")
            elif result is False:
                exe_path = threat_info.get("exe", "")
                if exe_path:
                    self.security_monitor.add_to_safe_list(exe_path)
                    self.add_log(t("log_safelist", name=threat_info['name']), "blue")
        except Exception:
            pass

    def scan_drive(self):
        def scan_thread():
            self.add_log(t("log_start_c_scan"), "blue")
            self.clean_progress.start()

            def progress_cb(count):
                self.add_log(t("log_scan_progress", count=count), "blue")

            results = self.scanner.scan("C:\\", callback=progress_cb)
            self.clean_progress.stop()

            stats = self.scanner.get_stats()
            self.add_log(t("log_scan_done", total=stats['total_files'],
                          time=stats['scan_time_ms'] / 1000), "green")
            self.add_log(t("log_safe_cleanable", count=stats['cls2_count'],
                          size=format_size(stats['cls2_size'])), "green")
            self.add_log(t("log_large_redundant", count=stats['cls3_count'],
                          size=format_size(stats['cls3_size'])), "orange")
            self.add_log(t("log_cleanable_total", size=format_size(stats['cleanable_size'])), "green")

            self.root.after(0, lambda: ScanDetailWindow(self.root, self.scanner))

        threading.Thread(target=scan_thread, daemon=True).start()

    def full_security_scan(self):
        self._security_scanner = FullSecurityScanner(security_monitor=self.security_monitor)

        def scan_thread():
            self.add_log(t("log_full_scan_start"), "red")
            self.sec_progress.start()

            def progress_cb(msg):
                self.add_log(t("log_full_scan_progress", msg=msg), "blue")

            self._security_scanner.run_full_scan(progress_cb=progress_cb)
            self.sec_progress.stop()

            total = self._security_scanner.total_issues
            cat1 = len(self._security_scanner.results.get(1, []))
            cat2 = len(self._security_scanner.results.get(2, []))
            cat3 = len(self._security_scanner.results.get(3, []))
            cat4 = len(self._security_scanner.results.get(4, []))

            self.add_log(t("log_full_scan_done", total=total, v=cat1, s=cat2, sec=cat3, o=cat4),
                        "red" if total > 0 else "green")

            self.root.after(0, lambda: SecurityScanWindow(
                self.root, self._security_scanner, self.security_monitor))

        threading.Thread(target=scan_thread, daemon=True).start()


def show_startup_dialog(root):
    cfg = load_config()
    if cfg.get("auto_start_configured", False):
        return cfg
    dialog = StartupDialog(root)
    result = dialog.show()
    if result and result.get("auto_start"):
        set_auto_start(True)
    else:
        set_auto_start(False)
    cfg["auto_start"] = result.get("auto_start", False) if result else False
    cfg["start_minimized"] = result.get("start_minimized", False) if result else False
    cfg["auto_start_configured"] = True
    save_config(cfg)
    return cfg


def main():
    is_minimized = "--minimized" in sys.argv
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root.withdraw()
    cfg = load_config()
    if not cfg.get("auto_start_configured", False):
        root.deiconify()
        cfg = show_startup_dialog(root)
        root.withdraw()
    start_minimized = is_minimized or cfg.get("start_minimized", False)
    app = AISecurityApp(root, start_minimized=start_minimized)
    if not start_minimized:
        root.deiconify()

    def global_exception_handler(exc_type, exc_value, exc_tb):
        import traceback
        tb_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            app.add_log(t("log_exception", error=str(exc_value)), "red")
        except Exception:
            print(f"Unhandled exception:\n{tb_text}")

    root.mainloop()


if __name__ == "__main__":
    main()
