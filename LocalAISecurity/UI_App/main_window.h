/**
 * @file main_window.h
 * @brief 极简UI主窗口 - 头文件
 * 五大页面：首页/AI C盘瘦身/安全风险日志/信任白名单/设置中心
 * 使用Win32 API实现，零第三方UI框架依赖，控制体积
 */

#pragma once

#include <string>

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#define NOMINMAX
#include <windows.h>
#include <commctrl.h>

namespace UIApp {

// ============================================================
// 页面标识
// ============================================================
enum class PageID : int {
    HOME = 0,              // 首页：双AI运行状态、防护模式、资源占用
    AI_CLEAN = 1,          // AI C盘瘦身页
    SECURITY_LOG = 2,      // 安全风险日志页
    TRUST_LIST = 3,        // 信任白名单页
    SETTINGS = 4           // 设置中心
};

// ============================================================
// 主窗口类
// ============================================================
class MainWindow {
public:
    MainWindow();
    ~MainWindow();

    /** 创建并显示主窗口 */
    bool create(HINSTANCE hInstance, int nCmdShow);

    /** 消息循环 */
    int run();

    /** 切换页面 */
    void switch_page(PageID page);

    // ---- 首页数据更新 ----
    void update_security_status(bool active, int threat_count);
    void update_clean_status(bool active, uint64_t cleanable_size);
    void update_resource_usage(double cpu_percent, uint64_t memory_bytes);
    void update_protection_mode(const std::string& mode);

    // ---- AI C盘瘦身页数据更新 ----
    void update_scan_progress(int percent);
    void update_scan_result(uint64_t total_files,
                            uint64_t cleanable_count,
                            uint64_t cleanable_size);
    void update_clean_progress(int percent);

    // ---- 安全风险日志页数据更新 ----
    void add_security_log_entry(const std::string& time,
                                const std::string& process,
                                const std::string& threat,
                                const std::string& action);

    // ---- 信任白名单页 ----
    void add_trust_entry(const std::string& path, const std::string& reason);
    void remove_trust_entry(int index);

    // ---- 设置中心 ----
    bool get_network_enabled() const;
    void set_network_enabled(bool enabled);
    bool get_game_mode() const;
    void set_game_mode(bool enabled);

private:
    HWND hwnd_;
    HINSTANCE hInstance_;

    // 页面控件句柄
    PageID current_page_;

    // 首页控件
    HWND lbl_security_status_;
    HWND lbl_clean_status_;
    HWND lbl_cpu_usage_;
    HWND lbl_memory_usage_;
    HWND lbl_protection_mode_;
    HWND progress_bar_;

    // AI C盘瘦身页控件
    HWND btn_safe_clean_;
    HWND btn_deep_clean_;
    HWND btn_diagnosis_;
    HWND lbl_scan_progress_;
    HWND lbl_cleanable_size_;
    HWND listview_clean_;

    // 安全风险日志页控件
    HWND listview_log_;

    // 信任白名单页控件
    HWND listview_trust_;
    HWND btn_add_trust_;
    HWND btn_remove_trust_;

    // 设置中心控件
    HWND chk_network_;
    HWND chk_game_mode_;
    HWND btn_check_update_;
    HWND lbl_version_;

    // 窗口过程
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT handle_message(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // 页面创建方法
    void create_home_page(HWND parent);
    void create_clean_page(HWND parent);
    void create_log_page(HWND parent);
    void create_trust_page(HWND parent);
    void create_settings_page(HWND parent);

    // 隐藏/显示页面
    void show_page(PageID page);
    void hide_all_pages();

    // 常量
    static const int WINDOW_WIDTH = 800;
    static const int WINDOW_HEIGHT = 560;
    static const int SIDEBAR_WIDTH = 160;
    static const int CONTENT_X = 170;
    static const int CONTENT_WIDTH = 620;
};

} // namespace UIApp
