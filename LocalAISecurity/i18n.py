"""LocalAISecurity 国际化模块 — 简体中文 / English"""
import os
import json

CONFIG_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "LocalAISecurity")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

_current_lang = "zh"

TRANSLATIONS = {
    # ── 通用 ──
    "app_title": {"zh": "双AI智能安全体", "en": "Dual-AI Smart Security"},
    "app_subtitle": {"zh": "安全防护AI + AI智能C盘瘦身", "en": "Security AI + AI Disk Cleanup"},

    # ── 主窗口按钮 ──
    "btn_start": {"zh": "▶ 启动防护", "en": "▶ Start Protection"},
    "btn_stop": {"zh": "⏹ 停止防护", "en": "⏹ Stop Protection"},
    "btn_scan_c": {"zh": "🔍 C盘扫描", "en": "🔍 C-Drive Scan"},
    "btn_full_scan": {"zh": "🛡 全盘杀毒", "en": "🛡 Full Scan"},

    # ── 主窗口状态卡 ──
    "card_security": {"zh": "🛡 安全防护AI", "en": "🛡 Security AI"},
    "card_clean": {"zh": "💿 C盘清理AI", "en": "💿 Disk Cleanup AI"},
    "status_ready": {"zh": "● 就绪", "en": "● Ready"},
    "status_running": {"zh": "● 运行中", "en": "● Running"},
    "status_stopped": {"zh": "● 已停止", "en": "● Stopped"},

    # ── 主窗口设置 ──
    "setting_autostart": {"zh": "开机自动启动", "en": "Auto-start with Windows"},
    "setting_minimized": {"zh": "开机最小化到托盘", "en": "Start minimized to tray"},
    "setting_language": {"zh": "语言", "en": "Language"},
    "label_log": {"zh": "📋 系统日志", "en": "📋 System Log"},

    # ── 主窗口日志 ──
    "log_init": {"zh": "系统已初始化", "en": "System initialized"},
    "log_security_loaded": {"zh": "安全AI引擎: PyTorch CNN模型已加载 (4分类)", "en": "Security AI: PyTorch CNN model loaded (4-class)"},
    "log_security_fail": {"zh": "安全AI引擎: 模型加载失败 - {error}", "en": "Security AI: Model load failed - {error}"},
    "log_clean_loaded": {"zh": "清理AI引擎: PyTorch CNN模型已加载 (5分类)", "en": "Cleanup AI: PyTorch CNN model loaded (5-class)"},
    "log_clean_fail": {"zh": "清理AI引擎: 模型加载失败 - {error}", "en": "Cleanup AI: Model load failed - {error}"},
    "log_psutil_ok": {"zh": "进程监控: psutil已就绪", "en": "Process monitor: psutil ready"},
    "log_psutil_fail": {"zh": "进程监控: psutil未安装，安全监控不可用", "en": "Process monitor: psutil not installed, security unavailable"},
    "log_tray_hint": {"zh": "提示: 点击最小化可隐藏到系统托盘", "en": "Tip: Minimize to hide to system tray"},
    "log_waiting": {"zh": "等待用户操作...", "en": "Waiting for user action..."},
    "log_minimized": {"zh": "已最小化到系统托盘", "en": "Minimized to system tray"},
    "log_protection_start": {"zh": "启动安全防护监控...", "en": "Starting security monitor..."},
    "log_monitor_started": {"zh": "进程行为AI监控: 已启动 (psutil + CNN推理)", "en": "Process AI monitor: started (psutil + CNN)"},
    "log_monitor_fail": {"zh": "进程行为AI监控: 启动失败", "en": "Process AI monitor: start failed"},
    "log_psutil_only": {"zh": "进程监控: psutil未安装，仅UI模式运行", "en": "Process monitor: psutil missing, UI-only mode"},
    "log_model_only": {"zh": "进程监控: AI模型未加载，仅UI模式运行", "en": "Process monitor: AI model not loaded, UI-only mode"},
    "log_dual_active": {"zh": "双AI引擎已激活，系统进入保护状态", "en": "Dual AI engines active, system protected"},
    "log_all_stopped": {"zh": "所有监控已停止，系统进入待机状态", "en": "All monitors stopped, system standby"},
    "log_threat": {"zh": "⚠ 威胁检测: {name} (PID:{pid}) 分类:{cls} 置信度:{conf:.0%}", "en": "⚠ Threat: {name} (PID:{pid}) Class:{cls} Confidence:{conf:.0%}"},
    "log_terminated": {"zh": "已终止威胁进程: {name} (PID:{pid})", "en": "Threat process terminated: {name} (PID:{pid})"},
    "log_terminate_fail": {"zh": "终止进程失败: {error}", "en": "Terminate failed: {error}"},
    "log_safelist": {"zh": "已加入安全列表: {name}", "en": "Added to safe list: {name}"},
    "log_autostart_on": {"zh": "开机自动启动: 已开启", "en": "Auto-start: Enabled"},
    "log_autostart_off": {"zh": "开机自动启动: 已关闭", "en": "Auto-start: Disabled"},
    "log_autostart_fail": {"zh": "设置开机启动失败", "en": "Auto-start setup failed"},
    "log_start_c_scan": {"zh": "开始C盘AI智能扫描...", "en": "Starting C-drive AI scan..."},
    "log_scan_progress": {"zh": "已扫描 {count} 个文件...", "en": "Scanned {count} files..."},
    "log_scan_done": {"zh": "扫描完成！共分析 {total} 个文件，耗时 {time:.1f}s", "en": "Scan done! {total} files analyzed in {time:.1f}s"},
    "log_safe_cleanable": {"zh": "安全可删: {count} 项 ({size})", "en": "Safe cleanable: {count} items ({size})"},
    "log_large_redundant": {"zh": "大型冗余: {count} 项 ({size})", "en": "Large redundant: {count} items ({size})"},
    "log_cleanable_total": {"zh": "可清理总空间: {size}", "en": "Total cleanable: {size}"},
    "log_full_scan_start": {"zh": "🛡 开始全盘安全扫描...", "en": "🛡 Starting full security scan..."},
    "log_full_scan_progress": {"zh": "[全盘扫描] {msg}", "en": "[Full Scan] {msg}"},
    "log_full_scan_done": {"zh": "全盘扫描完成！共 {total} 个问题: 病毒 {v} / 疑似 {s} / 安全 {sec} / 其他 {o}", "en": "Full scan done! {total} issues: Virus {v} / Suspicious {s} / Security {sec} / Other {o}"},
    "log_lang_changed": {"zh": "语言已切换为简体中文", "en": "Language switched to English"},
    "log_exception": {"zh": "异常: {error}", "en": "Exception: {error}"},

    # ── 托盘菜单 ──
    "tray_show": {"zh": "打开主界面", "en": "Show Window"},
    "tray_start": {"zh": "启动防护", "en": "Start Protection"},
    "tray_stop": {"zh": "停止防护", "en": "Stop Protection"},
    "tray_exit": {"zh": "退出程序", "en": "Exit"},
    "tray_running": {"zh": "双AI智能安全体 - 防护运行中", "en": "Dual-AI Security - Active"},
    "tray_standby": {"zh": "双AI智能安全体 - 待机", "en": "Dual-AI Security - Standby"},

    # ── 威胁弹窗 ──
    "threat_title": {"zh": "⚠ 安全威胁警告", "en": "⚠ Security Threat Alert"},
    "threat_msg": {"zh": "检测到可疑进程！\n\n进程: {name}\nPID: {pid}\n路径: {path}\nAI分类: {cls}\n置信度: {conf:.0%}\n\n是(Y): 终止该进程\n否(N): 加入安全列表(不再提醒)\n取消: 忽略本次", "en": "Suspicious process detected!\n\nProcess: {name}\nPID: {pid}\nPath: {path}\nAI Class: {cls}\nConfidence: {conf:.0%}\n\nYes: Terminate process\nNo: Add to safe list\nCancel: Ignore"},

    # ── 开机启动弹窗 ──
    "startup_title": {"zh": "开机启动设置", "en": "Startup Settings"},
    "startup_question": {"zh": "是否开启开机自动启动？", "en": "Enable auto-start with Windows?"},
    "startup_desc": {"zh": "开启后：电脑开机时自动在系统托盘运行\n关闭后：需要手动双击程序图标启动", "en": "Enabled: Auto-run in system tray on boot\nDisabled: Manually launch the app"},
    "startup_btn_ok": {"zh": "确定", "en": "OK"},
    "startup_btn_skip": {"zh": "跳过", "en": "Skip"},

    # ── C盘扫描结果窗口 ──
    "scan_title_report": {"zh": "💿 C盘智能分析报告", "en": "💿 C-Drive Analysis Report"},
    "scan_subtitle": {"zh": "扫描耗时 {time:.1f}s · 共分析 {total} 个文件 · 可清理 {size}", "en": "Scan time {time:.1f}s · {total} files · Cleanable {size}"},
    "scan_tab_overview": {"zh": "📊 C盘总览", "en": "📊 Overview"},
    "scan_tab_cleanable": {"zh": "🗑 可清理文件", "en": "🗑 Cleanable"},
    "scan_tab_large": {"zh": "📦 超大文件", "en": "📦 Large Files"},
    "scan_overview_title": {"zh": "C盘空间总览", "en": "C-Drive Space Overview"},
    "scan_overview_desc": {"zh": "分析系统目录、软件目录、用户目录的磁盘占用情况", "en": "Analyzing system, program, and user directory usage"},
    "scan_ai_title": {"zh": "AI扫描结果", "en": "AI Scan Results"},
    "scan_system": {"zh": "系统文件 (Windows)", "en": "System Files (Windows)"},
    "scan_program": {"zh": "已安装软件", "en": "Installed Software"},
    "scan_user": {"zh": "用户文件 (Users)", "en": "User Files (Users)"},
    "scan_other": {"zh": "其他文件", "en": "Other Files"},
    "scan_cleanable_item": {"zh": "可清理文件", "en": "Cleanable Files"},
    "scan_free": {"zh": "空闲空间", "en": "Free Space"},
    "scan_capacity": {"zh": "磁盘总容量", "en": "Total Capacity"},
    "scan_used": {"zh": "已使用", "en": "Used"},
    "scan_large_count": {"zh": "大文件数 (>100MB)", "en": "Large files (>100MB)"},
    "scan_analyzing": {"zh": "正在分析C盘空间...", "en": "Analyzing C-drive space..."},
    "scan_phase_disk": {"zh": "正在获取磁盘信息...", "en": "Getting disk info..."},
    "scan_phase_system": {"zh": "正在扫描系统文件 (Windows)...", "en": "Scanning system files (Windows)..."},
    "scan_phase_program": {"zh": "正在扫描软件目录...", "en": "Scanning program directories..."},
    "scan_phase_user": {"zh": "正在扫描用户目录 (Users)...", "en": "Scanning user directory (Users)..."},
    "scan_phase_other": {"zh": "正在扫描其他目录...", "en": "Scanning other directories..."},
    "scan_phase_large": {"zh": "正在扫描大文件 (>100MB)...", "en": "Scanning large files (>100MB)..."},
    "scan_phase_done": {"zh": "分析完成", "en": "Analysis complete"},
    "scan_phase_error": {"zh": "分析出错: {error}", "en": "Analysis error: {error}"},
    "scan_cleanable_list": {"zh": "可清理文件详情（勾选后点击清理）", "en": "Cleanable files (check to clean)"},
    "scan_large_list": {"zh": "超大文件列表 (>100MB)", "en": "Large Files (>100MB)"},
    "scan_large_scanning": {"zh": "正在分析C盘大文件...", "en": "Analyzing large files..."},
    "scan_large_none": {"zh": "（未发现大文件）", "en": "(No large files found)"},
    "scan_large_header": {"zh": "超大文件列表 (>100MB)  —  共 {count} 个, 占用 {size}", "en": "Large Files (>100MB) — {count} files, {size}"},
    "scan_btn_quick_clean": {"zh": "一键清理安全项", "en": "Quick Clean Safe Items"},
    "scan_btn_clean": {"zh": "执行清理", "en": "Clean Selected"},
    "scan_btn_safe_page": {"zh": "全选本页安全项", "en": "Select Safe (Page)"},
    "scan_btn_deselect": {"zh": "取消全选", "en": "Deselect All"},
    "scan_selected": {"zh": "已选择清理", "en": "Selected"},
    "scan_remaining": {"zh": "剩余可清理", "en": "Remaining cleanable"},
    "scan_clean_confirm": {"zh": "即将清理 {count} 个文件，释放 {size} 空间\n\n此操作不可撤销，确认继续？", "en": "Will delete {count} files, freeing {size}\n\nThis cannot be undone. Continue?"},
    "scan_clean_done": {"zh": "清理完成！\n\n可清理项: 删除 {a} 个\n大文件: 删除 {b} 个\n共释放: {size}\n失败(被占用): {fail} 个", "en": "Cleanup done!\n\nCleanable: {a} deleted\nLarge: {b} deleted\nFreed: {size}\nFailed (in use): {fail}"},
    "scan_quick_clean_confirm": {"zh": "即将清理 {count} 个安全可删文件\n释放 {size} 空间\n\n确认继续？", "en": "Will clean {count} safe files\nFreeing {size}\n\nContinue?"},
    "scan_quick_clean_done": {"zh": "清理完成！\n\n成功删除: {n} 个文件\n释放空间: {size}\n失败(被占用): {fail} 个", "en": "Cleanup done!\n\nDeleted: {n}\nFreed: {size}\nFailed (in use): {fail}"},
    "scan_no_cleanable": {"zh": "没有可安全清理的文件", "en": "No safe cleanable files"},
    "scan_no_select": {"zh": "请先勾选要清理的文件", "en": "Please select files to clean"},
    "scan_page": {"zh": "第 {page}/{total} 页 · 显示 {start}-{end} / 共 {all} 项", "en": "Page {page}/{total} · {start}-{end} / {all} items"},
    "scan_page_simple": {"zh": "第 {page}/{total} 页 (共{all}项)", "en": "Page {page}/{total} ({all} items)"},
    "scan_prev": {"zh": "◀ 上一页", "en": "◀ Previous"},
    "scan_next": {"zh": "下一页 ▶", "en": "Next ▶"},
    "scan_none": {"zh": "（无可清理文件）", "en": "(No cleanable files)"},
    "scan_analyze_status": {"zh": "正在分析C盘空间...", "en": "Analyzing C-drive space..."},
    "scan_status_scanning": {"zh": "正在扫描文件...", "en": "Scanning files..."},

    # ── C盘分类详情窗口 ──
    "cat_title": {"zh": "📂 {cat} — 文件详情", "en": "📂 {cat} — File Details"},
    "cat_filter_all": {"zh": "全部", "en": "All"},
    "cat_filter_cleanable": {"zh": "可清理", "en": "Cleanable"},
    "cat_filter_important": {"zh": "重要/不可删", "en": "Important"},
    "cat_btn_clean": {"zh": "执行清理选中项", "en": "Clean Selected"},
    "cat_btn_select_cleanable": {"zh": "全选可清理项", "en": "Select Cleanable"},
    "cat_btn_deselect": {"zh": "取消全选", "en": "Deselect All"},
    "cat_no_match": {"zh": "（无匹配文件）", "en": "(No matching files)"},
    "cat_selected": {"zh": "已选择: {count} 项 · {size}", "en": "Selected: {count} · {size}"},
    "cat_warn_title": {"zh": "⚠ 警告", "en": "⚠ Warning"},
    "cat_warn_msg": {"zh": "选中项中有 {count} 个不建议删除的文件：\n\n{names}{extra}\n\n强制删除可能导致系统或软件异常！\n确认继续？", "en": "{count} selected files should NOT be deleted:\n\n{names}{extra}\n\nDeleting may cause system/software issues!\nContinue?"},
    "cat_confirm": {"zh": "确认清理", "en": "Confirm Cleanup"},
    "cat_confirm_msg": {"zh": "即将清理 {count} 个文件\n释放 {size} 空间\n\n文件将被移入回收站，可恢复。确认继续？", "en": "Will delete {count} files\nFreeing {size}\n\nFiles go to Recycle Bin. Continue?"},
    "cat_done": {"zh": "清理完成！\n\n成功删除: {n} 个\n释放: {size}\n失败(被占用): {fail} 个", "en": "Done!\n\nDeleted: {n}\nFreed: {size}\nFailed (in use): {fail}"},

    # ── 全盘扫描结果窗口 ──
    "sec_title": {"zh": "🛡 全盘安全扫描报告", "en": "🛡 Full Security Scan Report"},
    "sec_subtitle": {"zh": "扫描耗时 {time:.1f}s · 共发现 {total} 个问题", "en": "Scan time {time:.1f}s · {total} issues found"},
    "sec_handle_all": {"zh": "一键处理所有问题", "en": "Handle All Issues"},
    "sec_handle_selected": {"zh": "处理选中项", "en": "Handle Selected"},
    "sec_select_high": {"zh": "全选高危", "en": "Select High Risk"},
    "sec_deselect": {"zh": "取消全选", "en": "Deselect All"},
    "sec_select_count": {"zh": "已选中 {n} 项待处理", "en": "{n} items selected"},
    "sec_confirm_title": {"zh": "确认处理", "en": "Confirm Action"},
    "sec_confirm_msg": {"zh": "即将处理 {total} 个问题{high}\n\n处理操作：\n• 病毒/可疑进程：终止+删除文件\n• 启动项：移除\n• 可疑文件：移入回收站\n\n确认继续？", "en": "Will handle {total} issues{high}\n\nActions:\n• Virus/Suspicious: Terminate + Delete\n• Startup items: Remove\n• Suspicious files: Move to Recycle Bin\n\nContinue?"},
    "sec_confirm_high": {"zh": "（含 {n} 个高危项）", "en": " (including {n} high-risk)"},
    "sec_all_title": {"zh": "一键处理确认", "en": "Confirm Handle All"},
    "sec_all_msg": {"zh": "即将一键处理全部 {total} 个问题{high}\n\n⚠ 此操作将：\n• 终止所有可疑进程\n• 删除可疑文件\n• 移除异常启动项\n\n确认继续？", "en": "Will handle ALL {total} issues{high}\n\n⚠ This will:\n• Terminate all suspicious processes\n• Delete suspicious files\n• Remove suspicious startup items\n\nContinue?"},
    "sec_result": {"zh": "处理完成！\n\n终止进程: {term} 个\n删除文件: {del_f} 个\n移除启动项: {startup} 个\n失败: {fail} 个", "en": "Done!\n\nProcesses terminated: {term}\nFiles deleted: {del_f}\nStartup items removed: {startup}\nFailed: {fail}"},
    "sec_no_issues": {"zh": "没有发现需要处理的问题", "en": "No issues to handle"},
    "sec_no_select": {"zh": "请先勾选要处理的问题", "en": "Please select issues to handle"},

    # ── 安全扫描分类 ──
    "sec_cat_1_label": {"zh": "病毒/恶意软件", "en": "Virus/Malware"},
    "sec_cat_1_desc": {"zh": "AI检测到的高置信度恶意进程或文件，建议立即处理", "en": "High-confidence malicious process/file detected by AI"},
    "sec_cat_2_label": {"zh": "疑似病毒", "en": "Suspicious"},
    "sec_cat_2_desc": {"zh": "行为可疑但未达到病毒判定阈值，需人工确认", "en": "Suspicious behavior, needs manual review"},
    "sec_cat_3_label": {"zh": "安全问题", "en": "Security Issues"},
    "sec_cat_3_desc": {"zh": "系统安全隐患：可疑网络连接、异常启动项、弱配置等", "en": "Security risks: suspicious connections, startup items, weak config"},
    "sec_cat_4_label": {"zh": "其他风险", "en": "Other Risks"},
    "sec_cat_4_desc": {"zh": "低风险项，建议定期检查", "en": "Low-risk items, review periodically"},

    # ── 风险等级 ──
    "risk_high": {"zh": "高危", "en": "High"},
    "risk_medium": {"zh": "中危", "en": "Medium"},
    "risk_low": {"zh": "低危", "en": "Low"},

    # ── 处理操作标签 ──
    "action_terminate": {"zh": "终止进程+删除文件", "en": "Terminate + Delete"},
    "action_delete": {"zh": "移入回收站", "en": "Recycle Bin"},
    "action_startup": {"zh": "移除启动项", "en": "Remove Startup"},
    "action_block": {"zh": "终止进程(网络威胁)", "en": "Terminate (Network Threat)"},

    # ── 扫描进度 ──
    "progress_scanning_process": {"zh": "正在扫描进程...", "en": "Scanning processes..."},
    "progress_scanning_network": {"zh": "正在扫描网络连接...", "en": "Scanning network connections..."},
    "progress_scanning_startup": {"zh": "正在扫描启动项...", "en": "Scanning startup items..."},
    "progress_scanning_files": {"zh": "正在扫描关键目录...", "en": "Scanning key directories..."},
    "progress_stats_system": {"zh": "正在统计系统文件 (Windows)...", "en": "Analyzing system files (Windows)..."},
    "progress_stats_program": {"zh": "正在统计软件目录 ({name})...", "en": "Analyzing program files ({name})..."},
    "progress_stats_user": {"zh": "正在统计用户目录 (Users)...", "en": "Analyzing user files (Users)..."},
    "progress_stats_programdata": {"zh": "正在统计软件数据 (ProgramData)...", "en": "Analyzing program data (ProgramData)..."},
    "progress_files_scanned": {"zh": "已扫描 {n} 个文件 ({dir})...", "en": "Scanned {n} files ({dir})..."},
    "progress_large_scanned": {"zh": "已扫描 {n} 个文件, 发现 {m} 个大文件...", "en": "Scanned {n} files, found {m} large files..."},
    "progress_category_scanning": {"zh": "正在扫描: {name}...", "en": "Scanning: {name}..."},
    "progress_category_scanned": {"zh": "已扫描 {n} 个文件...", "en": "Scanned {n} files..."},
    "cat_done_summary": {"zh": "共 {total} 个文件 · {size}  |  可清理 {n} 项 · {csize}", "en": "{total} files · {size}  |  Cleanable {n} · {csize}"},

    # ── 文件重要性标签 ──
    "importance_system_core": {"zh": "系统核心", "en": "System Core"},
    "importance_system_file": {"zh": "系统文件", "en": "System File"},
    "importance_system_cache": {"zh": "系统缓存", "en": "System Cache"},
    "importance_system_log": {"zh": "系统日志", "en": "System Log"},
    "importance_system_other": {"zh": "系统其他", "en": "System Other"},
    "importance_program_exe": {"zh": "软件程序", "en": "App Program"},
    "importance_program_data": {"zh": "软件数据", "en": "App Data"},
    "importance_program_cache": {"zh": "软件缓存", "en": "App Cache"},
    "importance_installer": {"zh": "安装包", "en": "Installer"},
    "importance_uninstaller": {"zh": "卸载程序", "en": "Uninstaller"},
    "importance_user_important": {"zh": "个人重要", "en": "Personal"},
    "importance_user_temp": {"zh": "个人临时", "en": "Personal Temp"},
    "importance_app_data": {"zh": "应用数据", "en": "App Data"},
    "importance_app_cache": {"zh": "应用缓存", "en": "App Cache"},
    "importance_user_file": {"zh": "用户文件", "en": "User File"},
    "importance_temp_file": {"zh": "临时文件", "en": "Temp File"},
    "importance_exe_file": {"zh": "可执行文件", "en": "Executable"},
    "importance_other_file": {"zh": "其他文件", "en": "Other File"},

    # ── 文件分类名 ──
    "class_system_core": {"zh": "系统核心", "en": "System Core"},
    "class_software_cache": {"zh": "软件缓存", "en": "Software Cache"},
    "class_safe_cleanable": {"zh": "安全可删", "en": "Safe Cleanable"},
    "class_large_redundant": {"zh": "大型冗余", "en": "Large Redundant"},
    "class_user_important": {"zh": "用户重要", "en": "User Important"},

    # ── 安全分类名 ──
    "security_class_normal": {"zh": "正常", "en": "Normal"},
    "security_class_pup": {"zh": "流氓软件", "en": "PUP"},
    "security_class_trojan": {"zh": "木马", "en": "Trojan"},
    "security_class_ransomware": {"zh": "勒索软件", "en": "Ransomware"},

    # ── 描述文字 ──
    "desc_system_core": {"zh": "系统运行必需的核心文件，绝对禁止删除。", "en": "Essential system files. DO NOT delete."},
    "desc_software_cache": {"zh": "软件运行必需的缓存，删除可能导致软件异常。", "en": "Required software cache. May break apps."},
    "desc_safe_cleanable": {"zh": "普通垃圾文件，可安全删除，不影响系统。", "en": "Junk files. Safe to delete."},
    "desc_large_redundant": {"zh": "占用大量空间的冗余文件，删除需确认。", "en": "Space-wasting redundant files. Confirm before deleting."},
    "desc_user_important": {"zh": "用户个人重要文件，强制保护，不建议删除。", "en": "Personal important files. Protected."},

    # ── 文件可删原因 ──
    "reason_zip_iso": {"zh": "压缩/镜像文件，确认无用后可删除", "en": "Archive/image file, can delete if unused"},
    "reason_temp": {"zh": "临时/备份文件，可安全删除", "en": "Temp/backup file, safe to delete"},
    "reason_log_dump": {"zh": "日志/转储文件，可安全删除", "en": "Log/dump file, safe to delete"},
    "reason_downloads": {"zh": "下载目录文件，确认无用后可删除", "en": "Download directory file"},
    "reason_temp_dir": {"zh": "临时目录文件，可安全删除", "en": "Temp directory file, safe to delete"},
    "reason_cleanable": {"zh": "可清理文件", "en": "Cleanable file"},
    "reason_system_core": {"zh": "系统核心文件，删除将导致系统崩溃", "en": "Core system file, deleting will crash system"},
    "reason_system_protected": {"zh": "系统运行必需文件，禁止删除", "en": "Essential system file, deletion prohibited"},
    "reason_system_cache": {"zh": "系统缓存文件，可安全清理", "en": "System cache, safe to clean"},
    "reason_system_log": {"zh": "系统日志/临时文件，可安全清理", "en": "System log/temp, safe to clean"},
    "reason_system_other": {"zh": "系统目录文件，不建议删除", "en": "System directory file, not recommended to delete"},
    "reason_program_exe": {"zh": "软件运行必需的可执行文件", "en": "Required program executable"},
    "reason_program_uninstaller": {"zh": "软件卸载程序，建议保留", "en": "Uninstaller, keep it"},
    "reason_program_cache": {"zh": "软件产生的临时/缓存文件", "en": "Program temp/cache"},
    "reason_program_cache_dir": {"zh": "软件缓存数据，可安全清理", "en": "Program cache, safe to clean"},
    "reason_installer_cache": {"zh": "安装包缓存，确认无用后可删除", "en": "Installer cache, can delete if unused"},
    "reason_program_data": {"zh": "软件数据文件，删除可能导致软件异常", "en": "Program data, may break software"},
    "reason_user_temp": {"zh": "个人目录中的临时文件", "en": "Temp file in personal directory"},
    "reason_user_important": {"zh": "用户个人文件，不建议删除", "en": "Personal file, not recommended"},
    "reason_app_cache": {"zh": "应用程序缓存，可安全清理", "en": "App cache, safe to clean"},
    "reason_app_data": {"zh": "应用程序数据，删除可能影响软件使用", "en": "App data, may affect software"},
    "reason_user_file": {"zh": "用户目录文件，建议保留", "en": "User directory file, keep it"},
    "reason_temp_generic": {"zh": "临时/缓存文件，可清理", "en": "Temp/cache file, cleanable"},
    "reason_exe_generic": {"zh": "可执行文件，确认来源后可删除", "en": "Executable, can delete if source verified"},
    "reason_other": {"zh": "未分类文件，建议保留", "en": "Unclassified, keep it"},
    "reason_system_file_forbidden": {"zh": "系统文件，禁止删除", "en": "System file, deletion prohibited"},
    "reason_program_forbidden": {"zh": "软件文件，删除可能导致软件异常", "en": "Program file, may break software"},
    "reason_programdata_forbidden": {"zh": "软件数据文件", "en": "Program data file"},
    "reason_unknown": {"zh": "未知风险，建议保留", "en": "Unknown risk, keep it"},

    # ── 筛选标签 ──
    "filter_all": {"zh": "筛选: 全部", "en": "Filter: All"},
    "filter_cleanable": {"zh": "筛选: 仅可清理", "en": "Filter: Cleanable"},
    "filter_important": {"zh": "筛选: 仅重要/不可删", "en": "Filter: Important"},
    "filter_tip": {"zh": "点击复选框选择，可多选批量清理", "en": "Check to select for batch cleanup"},
}

# ── 语言选项 ──
LANG_OPTIONS = {
    "zh": "简体中文",
    "en": "English",
}


def load_language():
    """从配置文件加载语言设置"""
    global _current_lang
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                lang = cfg.get("language", "zh")
                if lang in ("zh", "en"):
                    _current_lang = lang
    except Exception:
        pass
    return _current_lang


def get_language():
    return _current_lang


def set_language(lang):
    global _current_lang
    if lang in ("zh", "en"):
        _current_lang = lang


def t(key, **kwargs):
    """返回当前语言的翻译字符串，支持 {} 和 {name} 两种占位符"""
    entry = TRANSLATIONS.get(key, {})
    text = entry.get(_current_lang, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError, IndexError):
            try:
                text = text.format(*kwargs.values())
            except Exception:
                pass
    return text


def get_categories(cat_type):
    """获取分类标签（用于 scanner.py 中的 SECURITY_ISSUE_CATEGORIES / FILE_CLASS）"""
    if cat_type == "security":
        return {
            1: {"label": t("sec_cat_1_label"), "color": "#FF3B30", "icon": "🦠", "desc": t("sec_cat_1_desc")},
            2: {"label": t("sec_cat_2_label"), "color": "#FF9500", "icon": "⚠️", "desc": t("sec_cat_2_desc")},
            3: {"label": t("sec_cat_3_label"), "color": "#007AFF", "icon": "🔓", "desc": t("sec_cat_3_desc")},
            4: {"label": t("sec_cat_4_label"), "color": "#AF52DE", "icon": "📋", "desc": t("sec_cat_4_desc")},
        }
    elif cat_type == "file_class":
        return {
            0: ("SYSTEM_CORE", t("class_system_core"), "#FF3B30", t("desc_system_core")),
            1: ("SOFTWARE_CACHE", t("class_software_cache"), "#FF9500", t("desc_software_cache")),
            2: ("SAFE_CLEANABLE", t("class_safe_cleanable"), "#34C759", t("desc_safe_cleanable")),
            3: ("LARGE_REDUNDANT", t("class_large_redundant"), "#007AFF", t("desc_large_redundant")),
            4: ("USER_IMPORTANT", t("class_user_important"), "#AF52DE", t("desc_user_important")),
        }
    return {}


def get_importance_config():
    """获取文件重要性配置（用于 ui_components.py IMPORTANCE_CONFIG）"""
    return {
        "系统核心": {"color": "#FF3B30", "icon": "🔴", "can_del": False, "label": t("importance_system_core")},
        "系统文件": {"color": "#FF3B30", "icon": "🔴", "can_del": False, "label": t("importance_system_file")},
        "系统缓存": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_system_cache")},
        "系统日志": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_system_log")},
        "系统其他": {"color": "#FF9500", "icon": "🟠", "can_del": False, "label": t("importance_system_other")},
        "软件程序": {"color": "#FF9500", "icon": "🟠", "can_del": False, "label": t("importance_program_exe")},
        "软件数据": {"color": "#FF9500", "icon": "🟠", "can_del": False, "label": t("importance_program_data")},
        "软件缓存": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_program_cache")},
        "安装包": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_installer")},
        "卸载程序": {"color": "#FF9500", "icon": "🟠", "can_del": False, "label": t("importance_uninstaller")},
        "个人重要": {"color": "#AF52DE", "icon": "🟣", "can_del": False, "label": t("importance_user_important")},
        "个人临时": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_user_temp")},
        "应用数据": {"color": "#FF9500", "icon": "🟠", "can_del": False, "label": t("importance_app_data")},
        "应用缓存": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_app_cache")},
        "用户文件": {"color": "#AF52DE", "icon": "🟣", "can_del": False, "label": t("importance_user_file")},
        "临时文件": {"color": "#34C759", "icon": "🟢", "can_del": True, "label": t("importance_temp_file")},
        "可执行文件": {"color": "#FF9500", "icon": "🟠", "can_del": False, "label": t("importance_exe_file")},
        "其他文件": {"color": "#86868B", "icon": "⚪", "can_del": False, "label": t("importance_other_file")},
    }


def get_category_labels():
    """获取C盘分类标签"""
    return {
        "system": (t("scan_system"), "Windows 目录"),
        "program": (t("scan_program"), "Program Files + ProgramData"),
        "user": (t("scan_user"), "Users 目录"),
        "other": (t("scan_other"), "其他目录及根文件"),
    }


# 启动时加载语言
load_language()
