/**
 * @file main_window.cpp
 * @brief 极简UI主窗口 - 实现
 * Win32原生API，零第三方UI框架，极简风格
 */

#include "main_window.h"
#include <sstream>
#include <iomanip>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

namespace UIApp {

// ============================================================
// 常量定义
// ============================================================
static const wchar_t* CLASS_NAME = L"LocalAISecurityWnd";
static const wchar_t* APP_TITLE = L"双AI智能安全体";

// 侧边栏按钮ID
#define IDC_BTN_HOME        1001
#define IDC_BTN_CLEAN       1002
#define IDC_BTN_LOG         1003
#define IDC_BTN_TRUST       1004
#define IDC_BTN_SETTINGS    1005

// C盘瘦身页按钮ID
#define IDC_BTN_SAFE_CLEAN  2001
#define IDC_BTN_DEEP_CLEAN  2002
#define IDC_BTN_DIAGNOSIS   2003

// 信任白名单页按钮ID
#define IDC_BTN_ADD_TRUST   3001
#define IDC_BTN_REMOVE_TRUST 3002

// 设置中心控件ID
#define IDC_CHK_NETWORK     4001
#define IDC_CHK_GAME_MODE   4002
#define IDC_BTN_UPDATE      4003

// ============================================================
// 构造/析构
// ============================================================
MainWindow::MainWindow()
    : hwnd_(nullptr), hInstance_(nullptr), current_page_(PageID::HOME),
      lbl_security_status_(nullptr), lbl_clean_status_(nullptr),
      lbl_cpu_usage_(nullptr), lbl_memory_usage_(nullptr),
      lbl_protection_mode_(nullptr), progress_bar_(nullptr),
      btn_safe_clean_(nullptr), btn_deep_clean_(nullptr), btn_diagnosis_(nullptr),
      lbl_scan_progress_(nullptr), lbl_cleanable_size_(nullptr),
      listview_clean_(nullptr), listview_log_(nullptr),
      listview_trust_(nullptr), btn_add_trust_(nullptr), btn_remove_trust_(nullptr),
      chk_network_(nullptr), chk_game_mode_(nullptr),
      btn_check_update_(nullptr), lbl_version_(nullptr) {}

MainWindow::~MainWindow() = default;

// ============================================================
// 创建窗口
// ============================================================
bool MainWindow::create(HINSTANCE hInstance, int nCmdShow) {
    hInstance_ = hInstance;

    // 注册窗口类
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;

    RegisterClassExW(&wc);

    // 初始化公共控件
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    // 创建主窗口
    hwnd_ = CreateWindowExW(
        0, CLASS_NAME, APP_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT,
        WINDOW_WIDTH, WINDOW_HEIGHT,
        nullptr, nullptr, hInstance, this);

    if (!hwnd_) return false;

    ShowWindow(hwnd_, nCmdShow);
    UpdateWindow(hwnd_);

    return true;
}

// ============================================================
// 消息循环
// ============================================================
int MainWindow::run() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

// ============================================================
// 窗口过程
// ============================================================
LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;

    if (msg == WM_NCCREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        self = reinterpret_cast<MainWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
    } else {
        self = reinterpret_cast<MainWindow*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }

    if (self) {
        return self->handle_message(hwnd, msg, wParam, lParam);
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT MainWindow::handle_message(HWND hwnd, UINT msg,
                                    WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // 创建侧边栏
        const wchar_t* btn_labels[] = {L"首页", L"AI C盘瘦身", L"安全日志", L"信任白名单", L"设置中心"};
        UINT_PTR btn_ids[] = {IDC_BTN_HOME, IDC_BTN_CLEAN, IDC_BTN_LOG, IDC_BTN_TRUST, IDC_BTN_SETTINGS};

        for (int i = 0; i < 5; i++) {
            CreateWindowW(L"BUTTON", btn_labels[i],
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 20 + i * 50, SIDEBAR_WIDTH - 20, 40,
                hwnd, reinterpret_cast<HMENU>(btn_ids[i]),
                hInstance_, nullptr);
        }

        // 创建所有页面内容（初始隐藏，由switch_page控制可见性）
        create_home_page(hwnd);
        create_clean_page(hwnd);
        create_log_page(hwnd);
        create_trust_page(hwnd);
        create_settings_page(hwnd);
        switch_page(PageID::HOME);
        break;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_BTN_HOME:     switch_page(PageID::HOME); break;
        case IDC_BTN_CLEAN:    switch_page(PageID::AI_CLEAN); break;
        case IDC_BTN_LOG:      switch_page(PageID::SECURITY_LOG); break;
        case IDC_BTN_TRUST:    switch_page(PageID::TRUST_LIST); break;
        case IDC_BTN_SETTINGS: switch_page(PageID::SETTINGS); break;

        case IDC_BTN_SAFE_CLEAN:
            // 触发安全一键清理
            break;
        case IDC_BTN_DEEP_CLEAN:
            // 触发深度清理
            break;
        case IDC_BTN_DIAGNOSIS:
            // 触发空间诊断
            break;
        case IDC_BTN_ADD_TRUST:
            // 添加信任项
            break;
        case IDC_BTN_REMOVE_TRUST:
            // 移除信任项
            break;
        case IDC_BTN_UPDATE:
            // 检查更新
            break;
        }
        break;
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// ============================================================
// 页面切换
// ============================================================
void MainWindow::switch_page(PageID page) {
    hide_all_pages();
    show_page(page);
    current_page_ = page;
}

void MainWindow::hide_all_pages() {
    auto hide = [](HWND h) { if (h) ShowWindow(h, SW_HIDE); };
    hide(lbl_security_status_);
    hide(lbl_clean_status_);
    hide(lbl_cpu_usage_);
    hide(lbl_memory_usage_);
    hide(lbl_protection_mode_);
    hide(progress_bar_);
    hide(btn_safe_clean_);
    hide(btn_deep_clean_);
    hide(btn_diagnosis_);
    hide(lbl_scan_progress_);
    hide(lbl_cleanable_size_);
    hide(listview_clean_);
    hide(listview_log_);
    hide(listview_trust_);
    hide(btn_add_trust_);
    hide(btn_remove_trust_);
    hide(chk_network_);
    hide(chk_game_mode_);
    hide(btn_check_update_);
    hide(lbl_version_);
}

void MainWindow::show_page(PageID page) {
    auto show = [](HWND h) { if (h) ShowWindow(h, SW_SHOW); };
    switch (page) {
    case PageID::HOME:
        show(lbl_security_status_);
        show(lbl_clean_status_);
        show(lbl_cpu_usage_);
        show(lbl_memory_usage_);
        show(lbl_protection_mode_);
        show(progress_bar_);
        break;
    case PageID::AI_CLEAN:
        show(btn_safe_clean_);
        show(btn_deep_clean_);
        show(btn_diagnosis_);
        show(lbl_scan_progress_);
        show(lbl_cleanable_size_);
        show(listview_clean_);
        break;
    case PageID::SECURITY_LOG:
        show(listview_log_);
        break;
    case PageID::TRUST_LIST:
        show(listview_trust_);
        show(btn_add_trust_);
        show(btn_remove_trust_);
        break;
    case PageID::SETTINGS:
        show(chk_network_);
        show(chk_game_mode_);
        show(btn_check_update_);
        show(lbl_version_);
        break;
    }
}

// ============================================================
// 创建首页
// ============================================================
void MainWindow::create_home_page(HWND parent) {
    int y = 20;

    lbl_security_status_ = CreateWindowW(L"STATIC", L"安全AI: 运行中",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        CONTENT_X + 10, y, 300, 24, parent, nullptr, hInstance_, nullptr);
    y += 35;

    lbl_clean_status_ = CreateWindowW(L"STATIC", L"清理AI: 待命",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        CONTENT_X + 10, y, 300, 24, parent, nullptr, hInstance_, nullptr);
    y += 35;

    lbl_protection_mode_ = CreateWindowW(L"STATIC", L"防护模式: 标准防护",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        CONTENT_X + 10, y, 300, 24, parent, nullptr, hInstance_, nullptr);
    y += 45;

    lbl_cpu_usage_ = CreateWindowW(L"STATIC", L"CPU占用: 0.0%",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        CONTENT_X + 10, y, 200, 24, parent, nullptr, hInstance_, nullptr);
    y += 30;

    lbl_memory_usage_ = CreateWindowW(L"STATIC", L"内存占用: 0 MB",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        CONTENT_X + 10, y, 200, 24, parent, nullptr, hInstance_, nullptr);
    y += 40;

    progress_bar_ = CreateWindowExW(0, PROGRESS_CLASSW, L"",
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        CONTENT_X + 10, y, 400, 20, parent, nullptr, hInstance_, nullptr);
    SendMessage(progress_bar_, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
}

// ============================================================
// 创建AI C盘瘦身页
// ============================================================
void MainWindow::create_clean_page(HWND parent) {
    int y = 20;

    btn_safe_clean_ = CreateWindowW(L"BUTTON", L"AI安全一键清理",
        WS_CHILD | BS_PUSHBUTTON,
        CONTENT_X + 10, y, 180, 40, parent,
        reinterpret_cast<HMENU>(IDC_BTN_SAFE_CLEAN), hInstance_, nullptr);
    y += 50;

    btn_deep_clean_ = CreateWindowW(L"BUTTON", L"AI深度智能瘦身",
        WS_CHILD | BS_PUSHBUTTON,
        CONTENT_X + 10, y, 180, 40, parent,
        reinterpret_cast<HMENU>(IDC_BTN_DEEP_CLEAN), hInstance_, nullptr);
    y += 50;

    btn_diagnosis_ = CreateWindowW(L"BUTTON", L"空间诊断报告",
        WS_CHILD | BS_PUSHBUTTON,
        CONTENT_X + 10, y, 180, 40, parent,
        reinterpret_cast<HMENU>(IDC_BTN_DIAGNOSIS), hInstance_, nullptr);
    y += 60;

    lbl_scan_progress_ = CreateWindowW(L"STATIC", L"扫描进度: 就绪",
        WS_CHILD | SS_LEFT,
        CONTENT_X + 10, y, 300, 24, parent, nullptr, hInstance_, nullptr);
    y += 30;

    lbl_cleanable_size_ = CreateWindowW(L"STATIC", L"可清理: 0 MB",
        WS_CHILD | SS_LEFT,
        CONTENT_X + 10, y, 300, 24, parent, nullptr, hInstance_, nullptr);
    y += 40;

    // 清理结果列表
    listview_clean_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        CONTENT_X + 10, y, CONTENT_WIDTH - 20, 250,
        parent, nullptr, hInstance_, nullptr);

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 300; col.pszText = const_cast<LPWSTR>(L"文件路径");
    ListView_InsertColumn(listview_clean_, 0, &col);
    col.cx = 80; col.pszText = const_cast<LPWSTR>(L"大小");
    ListView_InsertColumn(listview_clean_, 1, &col);
    col.cx = 100; col.pszText = const_cast<LPWSTR>(L"分类");
    ListView_InsertColumn(listview_clean_, 2, &col);
    col.cx = 100; col.pszText = const_cast<LPWSTR>(L"风险");
    ListView_InsertColumn(listview_clean_, 3, &col);
}

// ============================================================
// 创建安全日志页
// ============================================================
void MainWindow::create_log_page(HWND parent) {
    listview_log_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        CONTENT_X + 10, 20, CONTENT_WIDTH - 20, 450,
        parent, nullptr, hInstance_, nullptr);

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 140; col.pszText = const_cast<LPWSTR>(L"时间");
    ListView_InsertColumn(listview_log_, 0, &col);
    col.cx = 150; col.pszText = const_cast<LPWSTR>(L"进程");
    ListView_InsertColumn(listview_log_, 1, &col);
    col.cx = 160; col.pszText = const_cast<LPWSTR>(L"威胁类型");
    ListView_InsertColumn(listview_log_, 2, &col);
    col.cx = 100; col.pszText = const_cast<LPWSTR>(L"处置动作");
    ListView_InsertColumn(listview_log_, 3, &col);
}

// ============================================================
// 创建信任白名单页
// ============================================================
void MainWindow::create_trust_page(HWND parent) {
    listview_trust_ = CreateWindowExW(0, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
        CONTENT_X + 10, 20, CONTENT_WIDTH - 20, 380,
        parent, nullptr, hInstance_, nullptr);

    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;
    col.cx = 400; col.pszText = const_cast<LPWSTR>(L"路径");
    ListView_InsertColumn(listview_trust_, 0, &col);
    col.cx = 180; col.pszText = const_cast<LPWSTR>(L"信任原因");
    ListView_InsertColumn(listview_trust_, 1, &col);

    btn_add_trust_ = CreateWindowW(L"BUTTON", L"添加信任",
        WS_CHILD | BS_PUSHBUTTON,
        CONTENT_X + 10, 420, 120, 35, parent,
        reinterpret_cast<HMENU>(IDC_BTN_ADD_TRUST), hInstance_, nullptr);

    btn_remove_trust_ = CreateWindowW(L"BUTTON", L"移除信任",
        WS_CHILD | BS_PUSHBUTTON,
        CONTENT_X + 140, 420, 120, 35, parent,
        reinterpret_cast<HMENU>(IDC_BTN_REMOVE_TRUST), hInstance_, nullptr);
}

// ============================================================
// 创建设置中心
// ============================================================
void MainWindow::create_settings_page(HWND parent) {
    int y = 30;

    chk_network_ = CreateWindowW(L"BUTTON", L"允许联网更新（仅下行，不上传隐私）",
        WS_CHILD | BS_AUTOCHECKBOX,
        CONTENT_X + 10, y, 400, 24, parent,
        reinterpret_cast<HMENU>(IDC_CHK_NETWORK), hInstance_, nullptr);
    y += 40;

    chk_game_mode_ = CreateWindowW(L"BUTTON", L"游戏模式（高负载自动降载休眠）",
        WS_CHILD | BS_AUTOCHECKBOX,
        CONTENT_X + 10, y, 400, 24, parent,
        reinterpret_cast<HMENU>(IDC_CHK_GAME_MODE), hInstance_, nullptr);
    y += 50;

    btn_check_update_ = CreateWindowW(L"BUTTON", L"检查更新",
        WS_CHILD | BS_PUSHBUTTON,
        CONTENT_X + 10, y, 120, 35, parent,
        reinterpret_cast<HMENU>(IDC_BTN_UPDATE), hInstance_, nullptr);
    y += 50;

    lbl_version_ = CreateWindowW(L"STATIC", L"版本: V1.0.0 | 双AI智能安全体",
        WS_CHILD | SS_LEFT,
        CONTENT_X + 10, y, 400, 24, parent, nullptr, hInstance_, nullptr);
    y += 30;

    CreateWindowW(L"STATIC",
        L"版权声明: 本软件拥有完整自主知识产权\n"
        L"框架依赖: tiny-cnn(BSD3) / tiny-dnn(MIT)\n"
        L"双模型: 全部项目内从零训练，无第三方版权权重\n"
        L"零广告 | 零弹窗 | 零隐私上传 | 永久免费",
        WS_CHILD | SS_LEFT,
        CONTENT_X + 10, y, 500, 80, parent, nullptr, hInstance_, nullptr);
}

// ============================================================
// 数据更新方法
// ============================================================
void MainWindow::update_security_status(bool active, int threat_count) {
    std::wstring text = active ? L"安全AI: 运行中" : L"安全AI: 已暂停";
    if (threat_count > 0) {
        text += L" | 已拦截: " + std::to_wstring(threat_count);
    }
    SetWindowTextW(lbl_security_status_, text.c_str());
}

void MainWindow::update_clean_status(bool active, uint64_t cleanable_size) {
    std::wstring text = active ? L"清理AI: 扫描中" : L"清理AI: 待命";
    double mb = static_cast<double>(cleanable_size) / (1024 * 1024);
    if (cleanable_size > 0) {
        text += L" | 可清理: " + std::to_wstring(static_cast<int>(mb)) + L" MB";
    }
    SetWindowTextW(lbl_clean_status_, text.c_str());
}

void MainWindow::update_resource_usage(double cpu_percent, uint64_t memory_bytes) {
    std::wostringstream oss;
    oss << L"CPU占用: " << std::fixed << std::setprecision(1) << cpu_percent << L"%";
    SetWindowTextW(lbl_cpu_usage_, oss.str().c_str());

    double mem_mb = static_cast<double>(memory_bytes) / (1024 * 1024);
    oss.str(L"");
    oss << L"内存占用: " << std::fixed << std::setprecision(1) << mem_mb << L" MB";
    SetWindowTextW(lbl_memory_usage_, oss.str().c_str());
}

void MainWindow::update_protection_mode(const std::string& mode) {
    std::wstring wmode(mode.begin(), mode.end());
    SetWindowTextW(lbl_protection_mode_, (L"防护模式: " + wmode).c_str());
}

void MainWindow::update_scan_progress(int percent) {
    SendMessage(progress_bar_, PBM_SETPOS, percent, 0);
    std::wstring text = L"扫描进度: " + std::to_wstring(percent) + L"%";
    SetWindowTextW(lbl_scan_progress_, text.c_str());
}

void MainWindow::update_scan_result(uint64_t total_files,
                                     uint64_t cleanable_count,
                                     uint64_t cleanable_size) {
    double mb = static_cast<double>(cleanable_size) / (1024 * 1024);
    std::wstring text = L"可清理: " + std::to_wstring(static_cast<int>(mb)) + L" MB"
                      + L" (" + std::to_wstring(cleanable_count) + L" 个文件)";
    SetWindowTextW(lbl_cleanable_size_, text.c_str());
}

void MainWindow::update_clean_progress(int percent) {
    std::wstring text = L"清理进度: " + std::to_wstring(percent) + L"%";
    SetWindowTextW(lbl_scan_progress_, text.c_str());
}

void MainWindow::add_security_log_entry(const std::string& time,
                                         const std::string& process,
                                         const std::string& threat,
                                         const std::string& action) {
    LVITEMW item = {};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(listview_log_);

    std::wstring wtime(time.begin(), time.end());
    std::wstring wprocess(process.begin(), process.end());
    std::wstring wthreat(threat.begin(), threat.end());
    std::wstring waction(action.begin(), action.end());

    item.iSubItem = 0; item.pszText = const_cast<LPWSTR>(wtime.c_str());
    ListView_InsertItem(listview_log_, &item);
    ListView_SetItemText(listview_log_, item.iItem, 1, const_cast<LPWSTR>(wprocess.c_str()));
    ListView_SetItemText(listview_log_, item.iItem, 2, const_cast<LPWSTR>(wthreat.c_str()));
    ListView_SetItemText(listview_log_, item.iItem, 3, const_cast<LPWSTR>(waction.c_str()));
}

void MainWindow::add_trust_entry(const std::string& path, const std::string& reason) {
    LVITEMW item = {};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(listview_trust_);

    std::wstring wpath(path.begin(), path.end());
    std::wstring wreason(reason.begin(), reason.end());

    item.iSubItem = 0; item.pszText = const_cast<LPWSTR>(wpath.c_str());
    ListView_InsertItem(listview_trust_, &item);
    ListView_SetItemText(listview_trust_, item.iItem, 1, const_cast<LPWSTR>(wreason.c_str()));
}

void MainWindow::remove_trust_entry(int index) {
    ListView_DeleteItem(listview_trust_, index);
}

bool MainWindow::get_network_enabled() const {
    return SendMessage(chk_network_, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void MainWindow::set_network_enabled(bool enabled) {
    SendMessage(chk_network_, BM_SETCHECK, enabled ? BST_CHECKED : BST_UNCHECKED, 0);
}

bool MainWindow::get_game_mode() const {
    return SendMessage(chk_game_mode_, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void MainWindow::set_game_mode(bool enabled) {
    SendMessage(chk_game_mode_, BM_SETCHECK, enabled ? BST_CHECKED : BST_UNCHECKED, 0);
}

} // namespace UIApp
