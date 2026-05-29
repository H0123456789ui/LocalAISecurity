import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
import json
import sys
import winreg
from PIL import Image, ImageDraw
import pystray

from i18n import t, get_language, get_importance_config, get_category_labels, get_categories

from scanner import DiskScanner, format_size, FILE_CLASS, \
    FullSecurityScanner, DriveAnalyzer, SECURITY_ISSUE_CATEGORIES
from classifier import AIFileClassifier, JUNK_CATEGORIES
from ai_engine import SecurityAIInference, SecurityMonitor

APP_NAME = "LocalAISecurity"
CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), APP_NAME)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_APP_NAME = "LocalAISecurity"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {"auto_start": False, "start_minimized": False}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"auto_start": False, "start_minimized": False}


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def is_auto_start_enabled():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, REG_APP_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def set_auto_start(enable):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_RUN_KEY, 0, winreg.KEY_SET_VALUE)
        if enable:
            exe_path = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
            if not getattr(sys, "frozen", False):
                cmd = f'"{sys.executable}" "{exe_path}" --minimized'
            else:
                cmd = f'"{exe_path}" --minimized'
            winreg.SetValueEx(key, REG_APP_NAME, 0, winreg.REG_SZ, cmd)
        else:
            try:
                winreg.DeleteValue(key, REG_APP_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"set_auto_start error: {e}")
        return False


def create_tray_icon_image():
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([4, 4, size - 4, size - 4], fill=(30, 120, 220), outline=(20, 80, 180), width=2)
    shield_pts = [
        (size // 2, 10), (size - 12, 20), (size - 14, 38),
        (size // 2, size - 10), (14, 38), (12, 20),
    ]
    draw.polygon(shield_pts, fill=(255, 255, 255), outline=(20, 80, 180))
    inner_pts = [
        (size // 2, 18), (size - 18, 26), (size - 19, 36),
        (size // 2, size - 18), (19, 36), (18, 26),
    ]
    draw.polygon(inner_pts, fill=(30, 120, 220))
    check_x, check_y_start = size // 2, 26
    draw.line([(check_x - 6, check_y_start + 6), (check_x - 1, check_y_start + 11),
               (check_x + 7, check_y_start - 2)], fill=(255, 255, 255), width=3)
    return img


class AppleStyle:
    BG = "#F5F5F7"
    CARD_BG = "#FFFFFF"
    CARD_BORDER = "#E5E5EA"
    TEXT_PRIMARY = "#1D1D1F"
    TEXT_SECONDARY = "#86868B"
    TEXT_TERTIARY = "#AEAEB2"
    ACCENT_BLUE = "#007AFF"
    ACCENT_GREEN = "#34C759"
    ACCENT_RED = "#FF3B30"
    ACCENT_ORANGE = "#FF9500"
    RADIUS = 12


class GlassButton(tk.Canvas):
    def __init__(self, parent, text="", command=None, color=AppleStyle.ACCENT_BLUE,
                 text_color="white", width=140, height=40, font=None, **kwargs):
        super().__init__(parent, width=width, height=height,
                         bg=AppleStyle.BG, highlightthickness=0, **kwargs)
        self._command = command
        self._color = color
        self._text = text
        self._text_color = text_color
        self._width = width
        self._height = height
        self._font = font or ("微软雅黑", 12, "bold")
        self._hover = False
        self._pressed = False
        self._draw()
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _hex_to_rgb(self, hex_color):
        hex_color = hex_color.lstrip("#")
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def _rgb_to_hex(self, r, g, b):
        return f"#{int(max(0,min(255,r))):02x}{int(max(0,min(255,g))):02x}{int(max(0,min(255,b))):02x}"

    def _blend(self, fg_hex, bg_hex, alpha):
        fr, fg_, fb = self._hex_to_rgb(fg_hex)
        br, bg_, bb = self._hex_to_rgb(bg_hex)
        r = fr * alpha + br * (1 - alpha)
        g = fg_ * alpha + bg_ * (1 - alpha)
        b = fb * alpha + bb * (1 - alpha)
        return self._rgb_to_hex(r, g, b)

    def _draw(self):
        self.delete("all")
        w, h = self._width, self._height
        r = AppleStyle.RADIUS
        if self._pressed:
            body_fill = self._blend(self._color, "#FFFFFF", 0.75)
            border_color = self._blend(self._color, "#000000", 0.3)
        elif self._hover:
            body_fill = self._blend(self._color, "#FFFFFF", 0.85)
            border_color = self._color
        else:
            body_fill = self._color
            border_color = self._blend(self._color, "#FFFFFF", 0.6)
        self._round_rect(1, 1, w - 1, h - 1, r, fill=body_fill, outline=border_color, width=1)
        hl_color = self._blend("#FFFFFF", body_fill, 0.25)
        self._round_rect(2, 2, w - 2, h // 2, r, fill=hl_color, outline="", width=0)
        self.create_text(w // 2, h // 2, text=self._text, fill=self._text_color,
                         font=self._font, anchor="center")

    def _round_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)

    def _on_enter(self, e):
        self._hover = True
        self._draw()

    def _on_leave(self, e):
        self._hover = False
        self._pressed = False
        self._draw()

    def _on_press(self, e):
        self._pressed = True
        self._draw()

    def _on_release(self, e):
        self._pressed = False
        self._draw()
        if self._command:
            self._command()


class GlassCard(tk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, bg=AppleStyle.CARD_BG, padx=16, pady=12, **kwargs)
        self.configure(highlightbackground=AppleStyle.CARD_BORDER,
                       highlightthickness=1, highlightcolor=AppleStyle.CARD_BORDER)


class StartupDialog:
    def __init__(self, parent):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(t("startup_title"))
        self.dialog.geometry("440x280")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.configure(bg=AppleStyle.BG)
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() - 440) // 2
        y = (self.dialog.winfo_screenheight() - 280) // 2
        self.dialog.geometry(f"440x280+{x}+{y}")

        header = tk.Frame(self.dialog, bg=AppleStyle.ACCENT_BLUE, height=56)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(header, text=t("app_title"), font=("微软雅黑", 15, "bold"),
                 bg=AppleStyle.ACCENT_BLUE, fg="white").pack(expand=True)

        body = tk.Frame(self.dialog, bg=AppleStyle.BG, padx=28, pady=16)
        body.pack(fill=tk.BOTH, expand=True)

        tk.Label(body, text=t("startup_question"), font=("微软雅黑", 13),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w", pady=(4, 6))
        tk.Label(body, text="开启后：电脑开机时自动在系统托盘运行\n关闭后：需要手动双击程序图标启动",
                 font=("微软雅黑", 10), bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY,
                 justify=tk.LEFT).pack(anchor="w", pady=(0, 12))

        self.auto_start_var = tk.BooleanVar(value=True)
        self.start_minimized_var = tk.BooleanVar(value=True)
        tk.Checkbutton(body, text=t("setting_autostart"), variable=self.auto_start_var,
                       font=("微软雅黑", 11), bg=AppleStyle.BG, activebackground=AppleStyle.BG,
                       selectcolor=AppleStyle.CARD_BG).pack(anchor="w", pady=2)
        tk.Checkbutton(body, text=t("setting_minimized"), variable=self.start_minimized_var,
                       font=("微软雅黑", 11), bg=AppleStyle.BG, activebackground=AppleStyle.BG,
                       selectcolor=AppleStyle.CARD_BG).pack(anchor="w", pady=2)

        btn_frame = tk.Frame(body, bg=AppleStyle.BG)
        btn_frame.pack(fill=tk.X, pady=(12, 0))
        GlassButton(btn_frame, text=t("startup_btn_ok"), command=self.on_ok,
                    color=AppleStyle.ACCENT_BLUE, width=100, height=36).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_frame, text=t("startup_btn_skip"), command=self.on_skip,
                    color=AppleStyle.TEXT_TERTIARY, width=100, height=36).pack(side=tk.RIGHT, padx=4)
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_skip)

    def on_ok(self):
        self.result = {"auto_start": self.auto_start_var.get(),
                       "start_minimized": self.start_minimized_var.get()}
        self.dialog.destroy()

    def on_skip(self):
        self.result = {"auto_start": False, "start_minimized": False}
        self.dialog.destroy()

    def show(self):
        self.dialog.wait_window()
        return self.result


class ScanDetailWindow:
    def __init__(self, parent, scanner):
        self.parent = parent
        self.scanner = scanner
        self.window = tk.Toplevel(parent)
        self.window.title("C盘智能分析报告")
        self.window.geometry("920x760")
        self.window.resizable(True, True)
        self.window.configure(bg=AppleStyle.BG)
        self.window.transient(parent)
        self.window.grab_set()
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() - 920) // 2
        y = (self.window.winfo_screenheight() - 760) // 2
        self.window.geometry(f"920x760+{x}+{y}")

        self.check_vars = {}
        self._checkbox_drawers = []
        self._all_cleanable_items = []
        self._current_page = 0
        self._page_size = 200
        self._total_pages = 0
        self._drive_analyzer = DriveAnalyzer()
        self._drive_data = None
        self._notebook = None
        self._build_ui()
        self._start_drive_analysis()

    def _build_ui(self):
        stats = self.scanner.get_stats()
        header = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=16)
        header.pack(fill=tk.X)
        tk.Label(header, text=t("scan_title_report"), font=("微软雅黑", 22, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w")
        tk.Label(header, text=f"扫描耗时 {stats['scan_time_ms'] / 1000:.1f}s · "
                              f"共分析 {stats['total_files']} 个文件 · "
                              f"可清理 {format_size(stats['cleanable_size'])}",
                 font=("微软雅黑", 11), bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY).pack(anchor="w", pady=(4, 0))

        self._notebook = ttk.Notebook(self.window)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(8, 0))

        self._tab_overview = tk.Frame(self._notebook, bg=AppleStyle.BG)
        self._tab_cleanable = tk.Frame(self._notebook, bg=AppleStyle.BG)
        self._tab_large = tk.Frame(self._notebook, bg=AppleStyle.BG)
        self._notebook.add(self._tab_overview, text="  " + t("scan_tab_overview") + "  ")
        self._notebook.add(self._tab_cleanable, text="  " + t("scan_tab_cleanable") + "  ")
        self._notebook.add(self._tab_large, text="  " + t("scan_tab_large") + "  ")

        self._build_overview_tab(stats)
        self._build_cleanable_tab()
        self._build_large_files_tab()

        bottom = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=12)
        bottom.pack(fill=tk.X)
        self.size_label = tk.Label(bottom, text="已选择清理: 0 B",
                                   font=("微软雅黑", 12, "bold"), bg=AppleStyle.BG,
                                   fg=AppleStyle.ACCENT_GREEN)
        self.size_label.pack(side=tk.LEFT)
        btn_row = tk.Frame(bottom, bg=AppleStyle.BG)
        btn_row.pack(side=tk.RIGHT)
        GlassButton(btn_row, text=t("scan_btn_quick_clean"), command=self.quick_clean,
                    color=AppleStyle.ACCENT_GREEN, width=150, height=38).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_row, text=t("scan_btn_clean"), command=self.do_clean,
                    color=AppleStyle.ACCENT_RED, width=120, height=38).pack(side=tk.RIGHT, padx=4)

    def _start_drive_analysis(self):
        status_frame = tk.Frame(self._tab_overview, bg=AppleStyle.BG)
        status_frame.pack(pady=12, padx=20, fill=tk.X)

        self._drive_status = tk.Label(status_frame,
                                       text=t("scan_analyze_status"), font=("微软雅黑", 11),
                                       bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY)
        self._drive_status.pack(anchor="w")

        self._drive_progress = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL,
                                                mode='determinate', length=500)
        self._drive_progress.pack(fill=tk.X, pady=(6, 0))
        self._drive_progress['value'] = 0

        percent_label = tk.Label(status_frame, text="0%", font=("微软雅黑", 9),
                                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_TERTIARY)
        percent_label.pack(anchor="e", pady=(2, 0))
        self._drive_percent = percent_label

        def analyze_thread():
            try:
                self._drive_data = self._drive_analyzer.analyze(
                    progress_cb=lambda fraction, msg:
                        self.window.after(0, self._update_drive_status, fraction, msg))
                self.window.after(0, self._refresh_overview_tab)
            except Exception as e:
                self.window.after(0, self._on_scan_error, str(e))

        threading.Thread(target=analyze_thread, daemon=True).start()

    def _on_scan_error(self, error_msg):
        try:
            self._drive_status.config(text=f"分析出错: {error_msg}", fg=AppleStyle.ACCENT_RED)
            self._drive_progress.stop()
        except Exception:
            pass

    def _update_drive_status(self, fraction, msg):
        try:
            self._drive_status.config(text=msg)
            pct = int(fraction * 100)
            self._drive_progress['value'] = pct
            self._drive_percent.config(text=f"{pct}%")
        except Exception:
            pass

    def _build_overview_tab(self, stats):
        tk.Label(self._tab_overview, text=t("scan_overview_title"), font=("微软雅黑", 16, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(self._tab_overview, text=t("scan_overview_desc"),
                 font=("微软雅黑", 10), bg=AppleStyle.BG,
                 fg=AppleStyle.TEXT_SECONDARY).pack(anchor="w", padx=20)

        self._overview_content = tk.Frame(self._tab_overview, bg=AppleStyle.BG)
        self._overview_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=8)

        self._ai_scan_summary = tk.Frame(self._tab_overview, bg=AppleStyle.BG)
        self._ai_scan_summary.pack(fill=tk.X, padx=20, pady=8)

        tk.Label(self._ai_scan_summary, text=t("scan_ai_title"), font=("微软雅黑", 15, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w", pady=(4, 6))
        for cls_id in range(5):
            name, label, color, desc = FILE_CLASS[cls_id]
            count = stats.get(f"cls{cls_id}_count", 0)
            size = stats.get(f"cls{cls_id}_size", 0)
            if count == 0:
                continue
            card = GlassCard(self._ai_scan_summary)
            card.pack(fill=tk.X, pady=2)
            row = tk.Frame(card, bg=AppleStyle.CARD_BG)
            row.pack(fill=tk.X)
            dot = tk.Canvas(row, width=12, height=12, bg=AppleStyle.CARD_BG, highlightthickness=0)
            dot.pack(side=tk.LEFT, padx=(0, 8))
            dot.create_oval(2, 2, 10, 10, fill=color, outline="")
            tk.Label(row, text=f"{label}  {count} 项 · {format_size(size)}", font=("微软雅黑", 12),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_PRIMARY).pack(side=tk.LEFT)
            tk.Label(row, text=desc, font=("微软雅黑", 9),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.RIGHT)

    def _refresh_overview_tab(self):
        for w in self._overview_content.winfo_children():
            w.destroy()
        try:
            self._drive_status.master.destroy()
        except Exception:
            pass
        if not self._drive_data:
            return

        d = self._drive_data
        parts = [
            (t("scan_system"), d["system_size"], "#FF3B30"),
            (t("scan_program"), d["program_size"], "#FF9500"),
            (t("scan_user"), d["user_size"], "#007AFF"),
            (t("scan_other"), d.get("other_size", 0), "#AF52DE"),
            (t("scan_cleanable_item"), self.scanner.get_stats().get("cleanable_size", 0), "#34C759"),
        ]
        total = d.get("total_capacity", 1) or 1
        free = d.get("total_free", 0)

        bar_frame = tk.Frame(self._overview_content, bg=AppleStyle.BG, height=32)
        bar_frame.pack(fill=tk.X, pady=(8, 4))
        bar_canvas = tk.Canvas(bar_frame, height=32, bg=AppleStyle.BG, highlightthickness=0)
        bar_canvas.pack(fill=tk.X)
        bar_w = 700
        x_pos = 10
        for label, sz, color in parts:
            ratio = sz / total if total > 0 else 0
            w = max(int(ratio * bar_w), 0)
            if w > 0:
                bar_canvas.create_rectangle(x_pos, 4, x_pos + w, 28, fill=color, outline="")
                if w > 50:
                    bar_canvas.create_text(x_pos + w // 2, 16, text=format_size(sz),
                                           fill="white", font=("微软雅黑", 8, "bold"))
            x_pos += w

        free_ratio = free / total if total > 0 else 0
        free_w = max(int(free_ratio * bar_w), 0)
        if free_w > 0:
            bar_canvas.create_rectangle(x_pos, 4, x_pos + free_w, 28,
                                         fill="#E5E5EA", outline="")
            if free_w > 50:
                bar_canvas.create_text(x_pos + free_w // 2, 16, text=format_size(free),
                                       fill=AppleStyle.TEXT_SECONDARY,
                                       font=("微软雅黑", 8, "bold"))

        legend = tk.Frame(self._overview_content, bg=AppleStyle.BG)
        legend.pack(fill=tk.X, pady=4)

        category_map = [
            ("系统文件", d["system_size"], "#FF3B30", "system"),
            ("已安装软件", d["program_size"], "#FF9500", "program"),
            ("用户文件", d["user_size"], "#007AFF", "user"),
            (t("scan_other"), d.get("other_size", 0), "#AF52DE", "other"),
            (t("scan_cleanable_item"), self.scanner.get_stats().get("cleanable_size", 0),
             "#34C759", "cleanable"),
        ]
        for label, sz, color, cat_key in category_map:
            row = tk.Frame(legend, bg=AppleStyle.BG, cursor="hand2")
            row.pack(fill=tk.X, pady=2)

            def _on_enter(e, r=row):
                r.configure(bg="#E8E8ED")
                for c in r.winfo_children():
                    try:
                        c.configure(bg="#E8E8ED")
                    except Exception:
                        pass

            def _on_leave(e, r=row):
                r.configure(bg=AppleStyle.BG)
                for c in r.winfo_children():
                    try:
                        c.configure(bg=AppleStyle.BG)
                    except Exception:
                        pass

            def _on_click(e, ck=cat_key, lbl=label):
                self._open_category_detail(ck)

            row.bind("<Enter>", _on_enter)
            row.bind("<Leave>", _on_leave)
            row.bind("<Button-1>", _on_click)

            dot = tk.Canvas(row, width=12, height=12, bg=AppleStyle.BG,
                           highlightthickness=0, cursor="hand2")
            dot.pack(side=tk.LEFT, padx=(0, 6))
            dot.create_oval(1, 1, 11, 11, fill=color, outline="")
            dot.bind("<Enter>", _on_enter)
            dot.bind("<Leave>", _on_leave)
            dot.bind("<Button-1>", _on_click)

            lbl_widget = tk.Label(row, text=f"{label}: {format_size(sz)}",
                                  font=("微软雅黑", 11), bg=AppleStyle.BG,
                                  fg=AppleStyle.ACCENT_BLUE, cursor="hand2")
            lbl_widget.pack(side=tk.LEFT)
            lbl_widget.bind("<Enter>", _on_enter)
            lbl_widget.bind("<Leave>", _on_leave)
            lbl_widget.bind("<Button-1>", _on_click)

            arrow = tk.Label(row, text=" ›", font=("微软雅黑", 14),
                            bg=AppleStyle.BG, fg=AppleStyle.TEXT_TERTIARY,
                            cursor="hand2")
            arrow.pack(side=tk.LEFT)
            arrow.bind("<Enter>", _on_enter)
            arrow.bind("<Leave>", _on_leave)
            arrow.bind("<Button-1>", _on_click)
        free_row = tk.Frame(legend, bg=AppleStyle.BG)
        free_row.pack(fill=tk.X, pady=2)
        dot2 = tk.Canvas(free_row, width=10, height=10, bg=AppleStyle.BG, highlightthickness=0)
        dot2.pack(side=tk.LEFT, padx=(0, 6))
        dot2.create_oval(1, 1, 9, 9, fill="#E5E5EA", outline="#C0C0C8")
        tk.Label(free_row, text=f"空闲空间: {format_size(free)}",
                 font=("微软雅黑", 10), bg=AppleStyle.BG,
                 fg=AppleStyle.ACCENT_GREEN).pack(side=tk.LEFT)

        info_frame = tk.Frame(self._overview_content, bg=AppleStyle.BG)
        info_frame.pack(fill=tk.X, pady=(8, 4))
        tk.Label(info_frame,
                 text=f"磁盘总容量: {format_size(total)}  |  "
                      f"已使用: {format_size(total - free)}  |  "
                      f"大文件数 (>100MB): {d.get('large_files_count', 0)}",
                 font=("微软雅黑", 10), bg=AppleStyle.BG,
                 fg=AppleStyle.TEXT_SECONDARY).pack(anchor="w")

        self._refresh_large_files_tab()

    def _open_category_detail(self, cat_key):
        if cat_key == "cleanable":
            self._notebook.select(self._tab_cleanable)
            return
        CategoryDetailWindow(self.window, cat_key, self._drive_analyzer, self.scanner)

    def _build_cleanable_tab(self):
        list_frame = tk.Frame(self._tab_cleanable, bg=AppleStyle.BG, padx=20, pady=8)
        list_frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(list_frame, text=t("scan_cleanable_list"), font=("微软雅黑", 14, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w", pady=(0, 6))

        canvas_frame = tk.Frame(list_frame, bg=AppleStyle.BG)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        self.canvas = tk.Canvas(canvas_frame, bg=AppleStyle.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.scroll_inner = tk.Frame(self.canvas, bg=AppleStyle.BG)
        self.scroll_inner.bind("<Configure>",
                               lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scroll_inner, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.bind_all("<MouseWheel>", lambda e: self.canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        self._all_cleanable_items = (self.scanner.results.get(1, []) +
                                     self.scanner.results.get(2, []) +
                                     self.scanner.results.get(3, []))
        self._total_pages = max(1, (len(self._all_cleanable_items) + self._page_size - 1) // self._page_size)
        self._current_page = 0
        self._load_page(0)

        btn_row = tk.Frame(self._tab_cleanable, bg=AppleStyle.BG)
        btn_row.pack(fill=tk.X, pady=(4, 0))
        GlassButton(btn_row, text=t("scan_btn_safe_page"), command=self.select_safe,
                    color=AppleStyle.ACCENT_GREEN, width=130, height=32).pack(side=tk.LEFT, padx=4)
        GlassButton(btn_row, text=t("scan_btn_deselect"), command=self.deselect_all,
                    color=AppleStyle.TEXT_TERTIARY, width=100, height=32).pack(side=tk.LEFT, padx=4)

    def _build_large_files_tab(self):
        self._large_list_frame = tk.Frame(self._tab_large, bg=AppleStyle.BG, padx=20, pady=8)
        self._large_list_frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(self._large_list_frame, text=t("scan_large_list"), font=("微软雅黑", 14, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w", pady=(0, 6))
        tk.Label(self._large_list_frame,
                 text=t("scan_large_scanning"), font=("微软雅黑", 10),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY).pack(anchor="w")

        self._large_check_vars = {}
        self._large_items = []

    def _refresh_large_files_tab(self):
        for w in self._large_list_frame.winfo_children():
            w.destroy()
        if not self._drive_data or not self._drive_data.get("large_files"):
            tk.Label(self._large_list_frame, text=t("scan_large_none"),
                     font=("微软雅黑", 11), bg=AppleStyle.BG,
                     fg=AppleStyle.TEXT_TERTIARY).pack(pady=20)
            return

        large_files = self._drive_data["large_files"]
        tk.Label(self._large_list_frame,
                 text=f"超大文件列表 (>100MB)  —  共 {len(large_files)} 个, "
                      f"占用 {format_size(self._drive_data.get('large_files_size', 0))}",
                 font=("微软雅黑", 14, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w", pady=(0, 6))

        canvas_frame = tk.Frame(self._large_list_frame, bg=AppleStyle.BG)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        large_canvas = tk.Canvas(canvas_frame, bg=AppleStyle.BG, highlightthickness=0)
        lf_scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=large_canvas.yview)
        lf_inner = tk.Frame(large_canvas, bg=AppleStyle.BG)
        lf_inner.bind("<Configure>",
                      lambda e: large_canvas.configure(scrollregion=large_canvas.bbox("all")))
        large_canvas.create_window((0, 0), window=lf_inner, anchor="nw")
        large_canvas.configure(yscrollcommand=lf_scrollbar.set)
        large_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lf_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._large_check_vars.clear()
        self._large_items = large_files
        for idx, file_info in enumerate(large_files):
            can_del = file_info.get("can_delete", False)
            reason = file_info.get("delete_reason", "")
            var = tk.BooleanVar(value=can_del)
            self._large_check_vars[idx] = (var, file_info)

            row_card = tk.Frame(lf_inner, bg=AppleStyle.CARD_BG, padx=10, pady=4)
            row_card.pack(fill=tk.X, pady=1, padx=2)
            row_card.configure(highlightbackground=AppleStyle.CARD_BORDER,
                               highlightthickness=1, highlightcolor=AppleStyle.CARD_BORDER)

            cb_canvas = tk.Canvas(row_card, width=20, height=20,
                                  bg=AppleStyle.CARD_BG, highlightthickness=0, bd=0)
            cb_canvas.pack(side=tk.LEFT, padx=(0, 8), pady=2)
            cb_canvas.config(cursor="hand2")

            def _draw_large_cb(c=cb_canvas, v=var):
                c.delete("all")
                s = 20
                if v.get():
                    c.create_rectangle(2, 2, s-2, s-2, fill=AppleStyle.ACCENT_GREEN, outline="")
                    c.create_line(5, 10, 9, s-5, fill="white", width=2)
                    c.create_line(9, s-5, s-6, 5, fill="white", width=2)
                else:
                    c.create_rectangle(2, 2, s-2, s-2, fill="", outline="#B0B0B8", width=1.5)

            def _toggle_large_cb(event, v=var, draw=_draw_large_cb):
                if reason and "禁止删除" not in reason:
                    v.set(not v.get())
                    draw()

            cb_canvas.bind("<Button-1>", _toggle_large_cb)
            _draw_large_cb()

            info_frame = tk.Frame(row_card, bg=AppleStyle.CARD_BG)
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
            path_text = file_info["path"]
            if len(path_text) > 90:
                path_text = "..." + path_text[-87:]
            tk.Label(info_frame, text=path_text, font=("Consolas", 9),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_SECONDARY,
                     anchor="w").pack(fill=tk.X)
            detail = tk.Frame(info_frame, bg=AppleStyle.CARD_BG)
            detail.pack(fill=tk.X)
            tk.Label(detail, text=f"{format_size(file_info['size'])}",
                     font=("微软雅黑", 9, "bold"), bg=AppleStyle.CARD_BG,
                     fg=AppleStyle.ACCENT_BLUE).pack(side=tk.LEFT)
            color = AppleStyle.ACCENT_GREEN if can_del else AppleStyle.ACCENT_RED
            tk.Label(detail, text=f"  {reason}", font=("微软雅黑", 8),
                     bg=AppleStyle.CARD_BG, fg=color).pack(side=tk.LEFT, padx=4)

    def _load_page(self, page_num):
        for widget in self.scroll_inner.winfo_children():
            widget.destroy()
        self.check_vars.clear()
        self._checkbox_drawers.clear()

        start_idx = page_num * self._page_size
        end_idx = min(start_idx + self._page_size, len(self._all_cleanable_items))
        page_items = self._all_cleanable_items[start_idx:end_idx]

        if not page_items:
            tk.Label(self.scroll_inner, text=t("scan_none"),
                     font=("微软雅黑", 11), bg=AppleStyle.BG,
                     fg=AppleStyle.TEXT_TERTIARY).pack(pady=20)
            return

        total = len(self._all_cleanable_items)
        page_info = tk.Label(self.scroll_inner,
                             text=f"第 {page_num + 1}/{self._total_pages} 页 · "
                                 f"显示 {start_idx + 1}-{end_idx} / 共 {total} 项",
                             font=("微软雅黑", 10), bg=AppleStyle.BG,
                             fg=AppleStyle.TEXT_TERTIARY)
        page_info.pack(anchor="w", pady=(4, 8))

        for idx, item in enumerate(page_items):
            global_idx = start_idx + idx
            cat_name = item.get("category", "other")
            cls_id = item.get("class_id", 1)
            cat_info = JUNK_CATEGORIES.get(cat_name, {})
            cat_label = cat_info.get("label", "其他")
            risk = cat_info.get("risk", 0)
            if cls_id == 1 and risk == 2:
                risk = 1

            var = tk.BooleanVar(value=(risk == 0))
            self.check_vars[global_idx] = (var, item)

            row_card = tk.Frame(self.scroll_inner, bg=AppleStyle.CARD_BG, padx=10, pady=5)
            row_card.pack(fill=tk.X, pady=1, padx=2)
            row_card.configure(highlightbackground=AppleStyle.CARD_BORDER,
                               highlightthickness=1, highlightcolor=AppleStyle.CARD_BORDER)

            cb_canvas = tk.Canvas(row_card, width=22, height=22,
                                  bg=AppleStyle.CARD_BG, highlightthickness=0, bd=0)
            cb_canvas.pack(side=tk.LEFT, padx=(0, 8), pady=4)
            cb_canvas.config(cursor="hand2")

            def _draw_checkbox(canvas=cb_canvas, v=var):
                canvas.delete("all")
                s = 22
                if v.get():
                    canvas.create_rectangle(2, 2, s-2, s-2, fill=AppleStyle.ACCENT_GREEN,
                                            outline="", width=0)
                    canvas.create_line(6, 11, 10, s-5, fill="white", width=2)
                    canvas.create_line(10, s-5, s-7, 6, fill="white", width=2)
                else:
                    canvas.create_rectangle(2, 2, s-2, s-2, fill="",
                                            outline="#B0B0B8", width=1.5)

            def _toggle_checkbox(event, v=var, draw=_draw_checkbox):
                v.set(not v.get())
                draw()
                self._update_selected_size()

            cb_canvas.bind("<Button-1>", _toggle_checkbox)
            _draw_checkbox()
            self._checkbox_drawers.append(_draw_checkbox)

            info_frame = tk.Frame(row_card, bg=AppleStyle.CARD_BG)
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)
            path_text = item["path"]
            if len(path_text) > 75:
                path_text = "..." + path_text[-72:]
            tk.Label(info_frame, text=path_text, font=("Consolas", 9),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_SECONDARY,
                     anchor="w").pack(fill=tk.X)
            detail_row = tk.Frame(info_frame, bg=AppleStyle.CARD_BG)
            detail_row.pack(fill=tk.X)
            tk.Label(detail_row, text=f"{format_size(item['size'])} · {cat_label}",
                     font=("微软雅黑", 9), bg=AppleStyle.CARD_BG,
                     fg=AppleStyle.ACCENT_BLUE).pack(side=tk.LEFT)
            tk.Label(detail_row, text=f"AI {item['confidence']:.0%}",
                     font=("微软雅黑", 9), bg=AppleStyle.CARD_BG,
                     fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT, padx=8)

        nav_bar = tk.Frame(self.scroll_inner, bg=AppleStyle.BG)
        nav_bar.pack(fill=tk.X, pady=(8, 4))
        if self._current_page > 0:
            GlassButton(nav_bar, text=t("scan_prev"), command=lambda: self._go_page(-1),
                        color=AppleStyle.TEXT_SECONDARY, width=100, height=32).pack(side=tk.LEFT)
        tk.Label(nav_bar, text=f"第 {page_num+1}/{self._total_pages} 页 (共{total}项)",
                 font=("微软雅黑", 9), bg=AppleStyle.BG, fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT, expand=True)
        if self._current_page < self._total_pages - 1:
            GlassButton(nav_bar, text=t("scan_next"), command=lambda: self._go_page(1),
                        color=AppleStyle.ACCENT_BLUE, width=100, height=32).pack(side=tk.RIGHT)

        for var, _ in self.check_vars.values():
            var.trace_add("write", lambda *a: self._update_selected_size())

        self.window.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _go_page(self, delta):
        new_page = self._current_page + delta
        if 0 <= new_page < self._total_pages:
            self._current_page = new_page
            self._load_page(new_page)

    def _update_selected_size(self):
        cleanable_size = sum(item["size"] for var, item in self.check_vars.values() if var.get())
        large_size = sum(f["size"] for var, f in self._large_check_vars.values() if var.get())
        total = cleanable_size + large_size
        self.size_label.config(text=f"已选择清理: {format_size(total)}")
        for draw_fn in self._checkbox_drawers:
            try:
                draw_fn()
            except Exception:
                pass

    def select_safe(self):
        for var, item in self.check_vars.values():
            cat_name = item.get("category", "other")
            risk = JUNK_CATEGORIES.get(cat_name, {}).get("risk", 2)
            if risk == 0:
                var.set(True)
        self._update_selected_size()

    def deselect_all(self):
        for var, _ in self.check_vars.values():
            var.set(False)
        for var, _ in self._large_check_vars.values():
            var.set(False)
        self._update_selected_size()

    def quick_clean(self):
        """一键清理安全项：仅删除 SAFE_CLEANABLE (cls=2) 的文件"""
        safe_items = self.scanner.results.get(2, [])
        if not safe_items:
            messagebox.showinfo("提示", t("scan_no_cleanable"), parent=self.window)
            return
        total_size = sum(i["size"] for i in safe_items)
        if not messagebox.askyesno(t("scan_btn_quick_clean"),
                                    f"即将清理 {len(safe_items)} 个安全可删文件\n"
                                    f"释放 {format_size(total_size)} 空间\n\n"
                                    f"确认继续？", parent=self.window):
            return
        result = self.scanner.execute_clean(safe_items)
        msg = (f"清理完成！\n\n"
               f"成功删除: {result['deleted']} 个文件\n"
               f"释放空间: {format_size(result['freed'])}\n"
               f"失败(被占用): {result['failed']} 个")
        messagebox.showinfo("清理结果", msg, parent=self.window)

        stats = self.scanner.get_stats()
        cleanable = stats.get("cleanable_size", 0)
        self.size_label.config(text=f"剩余可清理: {format_size(cleanable)}")

    def do_clean(self):
        cleanable_selected = [item for var, item in self.check_vars.values() if var.get()]
        large_selected = [f for var, f in self._large_check_vars.values() if var.get()]
        all_selected = cleanable_selected + large_selected
        if not all_selected:
            messagebox.showinfo("提示", t("scan_no_select"), parent=self.window)
            return
        total_size = sum(i["size"] for i in all_selected)
        if not messagebox.askyesno("确认清理",
                                    f"即将清理 {len(all_selected)} 个文件，释放 {format_size(total_size)} 空间\n\n"
                                    f"此操作不可撤销，确认继续？", parent=self.window):
            return

        result = self.scanner.execute_clean(cleanable_selected)
        large_deleted = 0
        large_freed = 0
        for item in large_selected:
            path = item["path"]
            try:
                sz = os.path.getsize(path)
                from scanner import _send_to_recycle_bin
                if _send_to_recycle_bin(path):
                    large_deleted += 1
                    large_freed += sz
            except (PermissionError, OSError):
                pass

        msg = (f"清理完成！\n\n"
               f"可清理项: 删除 {result['deleted']} 个\n"
               f"大文件: 删除 {large_deleted} 个\n"
               f"共释放: {format_size(result['freed'] + large_freed)}\n"
               f"失败(被占用): {result['failed']} 个")
        messagebox.showinfo("清理结果", msg, parent=self.window)
        self.window.destroy()

    def _update_drive_ui_after_analysis(self):
        if self._drive_data:
            self._refresh_large_files_tab()


def _IMPORTANCE_CONFIG():
    return get_importance_config()

def _CATEGORY_LABELS():
    return get_category_labels()


class CategoryDetailWindow:
    """分类文件详情窗口 — 支持浏览、过滤、选择性清理"""

    def __init__(self, parent, category, drive_analyzer, scanner=None):
        self.parent = parent
        self.category = category
        self._analyzer = drive_analyzer
        self._scanner = scanner
        self._all_files = []
        self._check_vars = {}
        self._checkbox_drawers = []
        self._current_page = 0
        self._page_size = 200
        self._total_pages = 0
        self._filter_level = "all"

        cat_label, cat_desc = _CATEGORY_LABELS().get(category, (category, ""))
        self.window = tk.Toplevel(parent)
        self.window.title(f"C盘 — {cat_label}详情")
        self.window.geometry("900x700")
        self.window.resizable(True, True)
        self.window.configure(bg=AppleStyle.BG)
        self.window.transient(parent)
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() - 900) // 2
        y = (self.window.winfo_screenheight() - 700) // 2
        self.window.geometry(f"900x700+{x}+{y}")
        self._build_ui(cat_label, cat_desc)
        self._start_scan()

    def _build_ui(self, cat_label, cat_desc):
        header = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=16)
        header.pack(fill=tk.X)
        tk.Label(header, text=f"📂 {cat_label} — 文件详情", font=("微软雅黑", 20, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w")
        self._scan_status = tk.Label(header, text=t("scan_status_scanning"), font=("微软雅黑", 11),
                                      bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY)
        self._scan_status.pack(anchor="w", pady=(4, 0))

        self._progress = ttk.Progressbar(header, orient=tk.HORIZONTAL, mode='indeterminate')
        self._progress.pack(fill=tk.X, pady=(4, 0))
        self._progress.start()

        filter_bar = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=4)
        filter_bar.pack(fill=tk.X)
        tk.Label(filter_bar, text="筛选:", font=("微软雅黑", 10),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_SECONDARY).pack(side=tk.LEFT, padx=(0, 6))
        for level, label in [("all", t("cat_filter_all")), ("can_delete", t("cat_filter_cleanable")), ("important", t("cat_filter_important"))]:
            GlassButton(filter_bar,
                        text=label,
                        command=lambda l=level: self._set_filter(l),
                        color=AppleStyle.ACCENT_BLUE if level == "all" else AppleStyle.TEXT_SECONDARY,
                        width=90, height=28).pack(side=tk.LEFT, padx=3)

        self._list_frame = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=4)
        self._list_frame.pack(fill=tk.BOTH, expand=True)

        bottom = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=12)
        bottom.pack(fill=tk.X)
        self._size_label = tk.Label(bottom, text="已选择: 0 B",
                                     font=("微软雅黑", 12, "bold"), bg=AppleStyle.BG,
                                     fg=AppleStyle.ACCENT_GREEN)
        self._size_label.pack(side=tk.LEFT)
        btn_row = tk.Frame(bottom, bg=AppleStyle.BG)
        btn_row.pack(side=tk.RIGHT)
        GlassButton(btn_row, text=t("cat_btn_clean"), command=self._do_clean,
                    color=AppleStyle.ACCENT_RED, width=150, height=38).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_row, text=t("cat_btn_select_cleanable"), command=self._select_cleanable,
                    color=AppleStyle.ACCENT_GREEN, width=130, height=38).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_row, text=t("scan_btn_deselect"), command=self._deselect_all,
                    color=AppleStyle.TEXT_TERTIARY, width=100, height=38).pack(side=tk.RIGHT, padx=4)

    def _start_scan(self):
        def scan_thread():
            self._all_files = self._analyzer.list_category_files(
                self.category,
                progress_cb=lambda msg: self.window.after(0, self._update_status, msg))
            self.window.after(0, self._on_scan_done)

        threading.Thread(target=scan_thread, daemon=True).start()

    def _update_status(self, msg):
        try:
            self._scan_status.config(text=msg)
        except Exception:
            pass

    def _on_scan_done(self):
        self._progress.stop()
        self._progress.pack_forget()

        total = len(self._all_files)
        total_size = sum(f["size"] for f in self._all_files)
        cleanable = sum(1 for f in self._all_files if f["can_delete"])
        cleanable_size = sum(f["size"] for f in self._all_files if f["can_delete"])

        self._scan_status.config(
            text=f"共 {total} 个文件 · {format_size(total_size)}  |  "
                 f"可清理 {cleanable} 项 · {format_size(cleanable_size)}")

        self._total_pages = max(1, (total + self._page_size - 1) // self._page_size)
        self._current_page = 0
        self._build_file_list()

    def _get_filtered_files(self):
        if self._filter_level == "can_delete":
            return [f for f in self._all_files if f["can_delete"]]
        elif self._filter_level == "important":
            return [f for f in self._all_files if not f["can_delete"]]
        return self._all_files

    def _set_filter(self, level):
        self._filter_level = level
        self._current_page = 0
        filtered = self._get_filtered_files()
        self._total_pages = max(1, (len(filtered) + self._page_size - 1) // self._page_size)
        self._build_file_list()

    def _build_file_list(self):
        for w in self._list_frame.winfo_children():
            w.destroy()
        self._check_vars.clear()
        self._checkbox_drawers.clear()

        filtered = self._get_filtered_files()
        start_idx = self._current_page * self._page_size
        end_idx = min(start_idx + self._page_size, len(filtered))
        page_items = filtered[start_idx:end_idx]

        if not page_items:
            tk.Label(self._list_frame, text=t("cat_no_match"),
                     font=("微软雅黑", 11), bg=AppleStyle.BG,
                     fg=AppleStyle.TEXT_TERTIARY).pack(pady=30)
            return

        total = len(filtered)
        info_bar = tk.Frame(self._list_frame, bg=AppleStyle.BG)
        info_bar.pack(fill=tk.X, pady=(4, 4))
        tk.Label(info_bar, text=f"第 {self._current_page + 1}/{self._total_pages} 页 · "
                                f"{start_idx + 1}-{end_idx} / 共 {total} 项",
                 font=("微软雅黑", 10), bg=AppleStyle.BG, fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT)
        if self._filter_level != "all":
            filter_name = {"can_delete": "仅可清理", "important": "仅重要/不可删"}[self._filter_level]
            tk.Label(info_bar, text=f"[筛选: {filter_name}]",
                     font=("微软雅黑", 9), bg=AppleStyle.BG,
                     fg=AppleStyle.ACCENT_BLUE).pack(side=tk.LEFT, padx=8)
        tk.Label(info_bar, text="点击复选框选择，可多选批量清理",
                 font=("微软雅黑", 9), bg=AppleStyle.BG,
                 fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.RIGHT)

        canvas_frame = tk.Frame(self._list_frame, bg=AppleStyle.BG)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(canvas_frame, bg=AppleStyle.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=AppleStyle.BG)
        inner.bind("<Configure>", lambda e, c=canvas: c.configure(scrollregion=c.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        for idx, f in enumerate(page_items):
            item_key = start_idx + idx
            importance = f.get("importance", t("scan_other"))
            can_del = f.get("can_delete", False)
            imp_cfg = _IMPORTANCE_CONFIG().get(importance, _IMPORTANCE_CONFIG()[t("scan_other")])
            var = tk.BooleanVar(value=can_del)
            self._check_vars[item_key] = (var, f)

            row_card = tk.Frame(inner, bg=AppleStyle.CARD_BG, padx=10, pady=3)
            row_card.pack(fill=tk.X, pady=1, padx=2)
            row_card.configure(highlightbackground=AppleStyle.CARD_BORDER,
                               highlightthickness=1, highlightcolor=AppleStyle.CARD_BORDER)

            cb_canvas = tk.Canvas(row_card, width=20, height=20,
                                  bg=AppleStyle.CARD_BG, highlightthickness=0, bd=0)
            cb_canvas.pack(side=tk.LEFT, padx=(0, 8), pady=2)
            cb_canvas.config(cursor="hand2")

            def _draw_cb(c=cb_canvas, v=var):
                c.delete("all")
                s = 20
                if v.get():
                    c.create_rectangle(2, 2, s-2, s-2, fill=AppleStyle.ACCENT_GREEN, outline="")
                    c.create_line(5, 10, 9, s-5, fill="white", width=2)
                    c.create_line(9, s-5, s-6, 5, fill="white", width=2)
                else:
                    c.create_rectangle(2, 2, s-2, s-2, fill="", outline="#B0B0B8", width=1.5)

            def _toggle_cb(event, v=var, draw=_draw_cb):
                v.set(not v.get())
                draw()
                self._update_size()

            cb_canvas.bind("<Button-1>", _toggle_cb)
            _draw_cb()
            self._checkbox_drawers.append(_draw_cb)

            info = tk.Frame(row_card, bg=AppleStyle.CARD_BG)
            info.pack(side=tk.LEFT, fill=tk.X, expand=True)
            path_text = f["path"]
            if len(path_text) > 85:
                path_text = "..." + path_text[-82:]
            tk.Label(info, text=path_text, font=("Consolas", 9),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_SECONDARY,
                     anchor="w").pack(fill=tk.X)

            meta = tk.Frame(info, bg=AppleStyle.CARD_BG)
            meta.pack(fill=tk.X)
            tk.Label(meta, text=f"{format_size(f['size'])}",
                     font=("微软雅黑", 9, "bold"), bg=AppleStyle.CARD_BG,
                     fg=AppleStyle.ACCENT_BLUE).pack(side=tk.LEFT)
            tk.Label(meta, text=f"  {importance}", font=("微软雅黑", 9),
                     bg=AppleStyle.CARD_BG, fg=imp_cfg["color"]).pack(side=tk.LEFT, padx=2)
            reason = f.get("reason", "")
            if reason:
                tk.Label(meta, text=f"  {reason}", font=("微软雅黑", 8),
                         bg=AppleStyle.CARD_BG,
                         fg=AppleStyle.ACCENT_GREEN if can_del else AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT)

        nav = tk.Frame(self._list_frame, bg=AppleStyle.BG)
        nav.pack(fill=tk.X, pady=(6, 2))
        if self._current_page > 0:
            GlassButton(nav, text=t("scan_prev"), command=lambda: self._go_page(-1),
                        color=AppleStyle.TEXT_SECONDARY, width=100, height=30).pack(side=tk.LEFT)
        tk.Label(nav, text=f"第 {self._current_page+1}/{self._total_pages} 页",
                 font=("微软雅黑", 9), bg=AppleStyle.BG,
                 fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT, expand=True)
        if self._current_page < self._total_pages - 1:
            GlassButton(nav, text=t("scan_next"), command=lambda: self._go_page(1),
                        color=AppleStyle.ACCENT_BLUE, width=100, height=30).pack(side=tk.RIGHT)

        for var, _ in self._check_vars.values():
            var.trace_add("write", lambda *a: self._update_size())

    def _go_page(self, delta):
        new_page = self._current_page + delta
        if 0 <= new_page < self._total_pages:
            self._current_page = new_page
            self._build_file_list()

    def _update_size(self):
        selected = sum(f["size"] for var, f in self._check_vars.values() if var.get())
        count = sum(1 for var, _ in self._check_vars.values() if var.get())
        self._size_label.config(text=f"已选择: {count} 项 · {format_size(selected)}")
        for draw in self._checkbox_drawers:
            try:
                draw()
            except Exception:
                pass

    def _select_cleanable(self):
        for var, f in self._check_vars.values():
            if f.get("can_delete", False):
                var.set(True)
        self._update_size()

    def _deselect_all(self):
        for var, _ in self._check_vars.values():
            var.set(False)
        self._update_size()

    def _do_clean(self):
        selected = [f for var, f in self._check_vars.values() if var.get()]
        if not selected:
            messagebox.showinfo("提示", t("scan_no_select"), parent=self.window)
            return

        cannot_delete = [f for f in selected if not f.get("can_delete", False)]
        if cannot_delete:
            names = "\n".join(f["path"][-60:] for f in cannot_delete[:5])
            extra = f"\n...等共 {len(cannot_delete)} 项" if len(cannot_delete) > 5 else ""
            if not messagebox.askyesno("⚠ 警告",
                                        f"选中项中有 {len(cannot_delete)} 个不建议删除的文件：\n\n"
                                        f"{names}{extra}\n\n"
                                        f"强制删除可能导致系统或软件异常！\n"
                                        f"确认继续？", parent=self.window):
                return

        total_size = sum(f["size"] for f in selected)
        if not messagebox.askyesno("确认清理",
                                    f"即将清理 {len(selected)} 个文件\n"
                                    f"释放 {format_size(total_size)} 空间\n\n"
                                    f"文件将被移入回收站，可恢复。确认继续？",
                                    parent=self.window):
            return

        from scanner import _send_to_recycle_bin
        deleted, freed, failed = 0, 0, 0
        for f in selected:
            try:
                if _send_to_recycle_bin(f["path"]):
                    deleted += 1
                    freed += f["size"]
                else:
                    failed += 1
            except Exception:
                failed += 1

        msg = (f"清理完成！\n\n"
               f"成功删除: {deleted} 个\n"
               f"释放: {format_size(freed)}\n"
               f"失败(被占用): {failed} 个")
        messagebox.showinfo("清理结果", msg, parent=self.window)
        self.window.destroy()


class SecurityScanWindow:
    """全盘安全扫描结果窗口"""

    def __init__(self, parent, scanner, security_monitor=None):
        self.parent = parent
        self.scanner = scanner
        self._monitor = security_monitor
        self.window = tk.Toplevel(parent)
        self.window.title("全盘安全扫描报告")
        self.window.geometry("900x720")
        self.window.resizable(True, True)
        self.window.configure(bg=AppleStyle.BG)
        self.window.transient(parent)
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() - 900) // 2
        y = (self.window.winfo_screenheight() - 720) // 2
        self.window.geometry(f"900x720+{x}+{y}")

        self._check_vars = {}
        self._all_items = []
        self._notebook = None
        self._build_ui()

    def _build_ui(self):
        results = self.scanner.results
        total = self.scanner.total_issues
        scan_time = self.scanner.scan_time_ms

        header = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=16)
        header.pack(fill=tk.X)
        tk.Label(header, text="🛡 全盘安全扫描报告", font=("微软雅黑", 22, "bold"),
                 bg=AppleStyle.BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w")
        tk.Label(header, text=f"扫描耗时 {scan_time / 1000:.1f}s · 共发现 {total} 个问题",
                 font=("微软雅黑", 11), bg=AppleStyle.BG,
                 fg=AppleStyle.TEXT_SECONDARY).pack(anchor="w", pady=(4, 0))

        summary = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=4)
        summary.pack(fill=tk.X)
        for cat_id in (1, 2, 3, 4):
            cat_info = SECURITY_ISSUE_CATEGORIES[cat_id]
            items = results.get(cat_id, [])
            count = len(items)
            card = GlassCard(summary)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
            tk.Label(card, text=f"{cat_info['icon']} {cat_info['label']}",
                     font=("微软雅黑", 13, "bold"),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_PRIMARY).pack(anchor="w")
            tk.Label(card, text=f"{count} 项", font=("微软雅黑", 20, "bold"),
                     bg=AppleStyle.CARD_BG, fg=cat_info["color"]).pack(anchor="w", pady=(4, 0))
            tk.Label(card, text=cat_info["desc"][:25], font=("微软雅黑", 9),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_TERTIARY).pack(anchor="w")

        self._notebook = ttk.Notebook(self.window)
        self._notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(8, 0))

        self._tabs = {}
        for cat_id in (1, 2, 3, 4):
            cat_info = SECURITY_ISSUE_CATEGORIES[cat_id]
            items = results.get(cat_id, [])
            if not items:
                continue
            tab = tk.Frame(self._notebook, bg=AppleStyle.BG)
            self._notebook.add(tab, text=f"  {cat_info['icon']} {cat_info['label']} ({len(items)})  ")
            self._tabs[cat_id] = tab
            self._build_issue_list(tab, cat_id, items)

        bottom = tk.Frame(self.window, bg=AppleStyle.BG, padx=24, pady=12)
        bottom.pack(fill=tk.X)
        self._action_label = tk.Label(bottom, text="",
                                       font=("微软雅黑", 12, "bold"), bg=AppleStyle.BG,
                                       fg=AppleStyle.ACCENT_GREEN)
        self._action_label.pack(side=tk.LEFT)

        btn_row = tk.Frame(bottom, bg=AppleStyle.BG)
        btn_row.pack(side=tk.RIGHT)
        GlassButton(btn_row, text=t("sec_handle_all"), command=self.handle_all,
                    color=AppleStyle.ACCENT_RED, width=170, height=42).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_row, text=t("sec_handle_selected"), command=self.handle_selected,
                    color=AppleStyle.ACCENT_ORANGE, width=140, height=42).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_row, text=t("sec_select_high"), command=self.select_high_risk,
                    color=AppleStyle.ACCENT_BLUE, width=120, height=42).pack(side=tk.RIGHT, padx=4)
        GlassButton(btn_row, text=t("scan_btn_deselect"), command=self.deselect_all,
                    color=AppleStyle.TEXT_TERTIARY, width=100, height=42).pack(side=tk.RIGHT, padx=4)

    def _build_issue_list(self, tab, cat_id, items):
        canvas_frame = tk.Frame(tab, bg=AppleStyle.BG, padx=12, pady=8)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(canvas_frame, bg=AppleStyle.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=AppleStyle.BG)
        inner.bind("<Configure>", lambda e, c=canvas: c.configure(scrollregion=c.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        for idx, item in enumerate(items):
            risk = item.get("risk_level", "low")
            default_checked = (risk == "high" or cat_id <= 2)
            var = tk.BooleanVar(value=default_checked)
            self._check_vars[id(item)] = (var, item)
            self._all_items.append(item)

            cat_info = SECURITY_ISSUE_CATEGORIES[cat_id]
            border_color = cat_info["color"]

            row_card = tk.Frame(inner, bg=AppleStyle.CARD_BG, padx=10, pady=5)
            row_card.pack(fill=tk.X, pady=2, padx=2)
            row_card.configure(highlightbackground=border_color,
                               highlightthickness=1, highlightcolor=border_color)

            cb_canvas = tk.Canvas(row_card, width=20, height=20,
                                  bg=AppleStyle.CARD_BG, highlightthickness=0, bd=0)
            cb_canvas.pack(side=tk.LEFT, padx=(0, 8), pady=2)
            cb_canvas.config(cursor="hand2")

            def _draw_cb(c=cb_canvas, v=var):
                c.delete("all")
                s = 20
                if v.get():
                    c.create_rectangle(2, 2, s-2, s-2, fill=AppleStyle.ACCENT_GREEN, outline="")
                    c.create_line(5, 10, 9, s-5, fill="white", width=2)
                    c.create_line(9, s-5, s-6, 5, fill="white", width=2)
                else:
                    c.create_rectangle(2, 2, s-2, s-2, fill="", outline="#B0B0B8", width=1.5)

            def _toggle_cb(event, v=var, draw=_draw_cb):
                v.set(not v.get())
                draw()

            cb_canvas.bind("<Button-1>", _toggle_cb)
            _draw_cb()

            info_frame = tk.Frame(row_card, bg=AppleStyle.CARD_BG)
            info_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

            title_row = tk.Frame(info_frame, bg=AppleStyle.CARD_BG)
            title_row.pack(fill=tk.X)
            source = item.get("source", "")
            title = item.get("name", item.get("path", "未知"))
            if len(title) > 60:
                title = "..." + title[-57:]
            tk.Label(title_row, text=title, font=("微软雅黑", 11, "bold"),
                     bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_PRIMARY).pack(side=tk.LEFT)
            risk_label = {"high": t("risk_high"), "medium": t("risk_medium"), "low": t("risk_low")}.get(risk, "")
            risk_color = {"high": AppleStyle.ACCENT_RED, "medium": AppleStyle.ACCENT_ORANGE,
                          "low": AppleStyle.TEXT_TERTIARY}.get(risk, AppleStyle.TEXT_TERTIARY)
            tk.Label(title_row, text=f" {risk_label}", font=("微软雅黑", 8, "bold"),
                     bg=AppleStyle.CARD_BG, fg=risk_color).pack(side=tk.LEFT, padx=4)
            conf = item.get("confidence", 0)
            if conf > 0:
                tk.Label(title_row, text=f"AI {conf:.0%}", font=("微软雅黑", 8),
                         bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT, padx=4)

            desc_text = item.get("description", "")
            if desc_text:
                tk.Label(info_frame, text=desc_text, font=("微软雅黑", 9),
                         bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_SECONDARY,
                         anchor="w", wraplength=550, justify=tk.LEFT).pack(fill=tk.X)

            extra_row = tk.Frame(info_frame, bg=AppleStyle.CARD_BG)
            extra_row.pack(fill=tk.X, pady=(2, 0))
            path = item.get("path", item.get("command", ""))
            if path and path != title:
                if len(path) > 70:
                    path = "..." + path[-67:]
                tk.Label(extra_row, text=path, font=("Consolas", 8),
                         bg=AppleStyle.CARD_BG, fg=AppleStyle.TEXT_TERTIARY).pack(side=tk.LEFT)

            action_type = item.get("action_type", "")
            action_labels = {
                "terminate": t("action_terminate"),
                "delete_file": t("action_delete"),
                "remove_startup": t("action_startup"),
                "block_network": t("action_block"),
            }
            action_text = action_labels.get(action_type, "")
            if action_text:
                tk.Label(extra_row, text=action_text, font=("微软雅黑", 8, "bold"),
                         bg=AppleStyle.CARD_BG, fg=AppleStyle.ACCENT_BLUE).pack(side=tk.RIGHT)

    def select_high_risk(self):
        for var, item in self._check_vars.values():
            if item.get("risk_level") == "high":
                var.set(True)
        self._update_action_label()

    def deselect_all(self):
        for var, _ in self._check_vars.values():
            var.set(False)
        self._update_action_label()

    def _update_action_label(self):
        selected = sum(1 for var, _ in self._check_vars.values() if var.get())
        self._action_label.config(text=f"已选中 {selected} 项待处理")

    def handle_selected(self):
        selected = [item for var, item in self._check_vars.values() if var.get()]
        if not selected:
            messagebox.showinfo("提示", t("sec_no_select"), parent=self.window)
            return

        high_risk = [i for i in selected if i.get("risk_level") == "high"]
        msg = f"即将处理 {len(selected)} 个问题"
        if high_risk:
            msg += f"（含 {len(high_risk)} 个高危项）"
        msg += "\n\n处理操作：\n• 病毒/可疑进程：终止+删除文件\n• 启动项：移除\n• 可疑文件：移入回收站\n\n确认继续？"

        if not messagebox.askyesno("确认处理", msg, parent=self.window):
            return

        results = self.scanner.execute_action(selected)
        result_msg = (f"处理完成！\n\n"
                      f"终止进程: {results['terminated']} 个\n"
                      f"删除文件: {results['deleted']} 个\n"
                      f"移除启动项: {results['removed_startup']} 个\n"
                      f"失败: {results['failed']} 个")
        messagebox.showinfo("处理结果", result_msg, parent=self.window)
        self.window.destroy()

    def handle_all(self):
        all_items = [item for var, item in self._check_vars.values()]
        if not all_items:
            messagebox.showinfo("提示", t("sec_no_issues"), parent=self.window)
            return

        high_risk = [i for i in all_items if i.get("risk_level") == "high"]
        msg = f"即将一键处理全部 {len(all_items)} 个问题"
        if high_risk:
            msg += f"（含 {len(high_risk)} 个高危项）"
        msg += "\n\n⚠ 此操作将：\n• 终止所有可疑进程\n• 删除可疑文件\n• 移除异常启动项\n\n确认继续？"

        if not messagebox.askyesno("一键处理确认", msg, parent=self.window):
            return

        results = self.scanner.execute_action(all_items)
        result_msg = (f"一键处理完成！\n\n"
                      f"终止进程: {results['terminated']} 个\n"
                      f"删除文件: {results['deleted']} 个\n"
                      f"移除启动项: {results['removed_startup']} 个\n"
                      f"失败: {results['failed']} 个")
        messagebox.showinfo("处理结果", result_msg, parent=self.window)
        self.window.destroy()
