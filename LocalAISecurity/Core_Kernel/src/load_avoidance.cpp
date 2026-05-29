/**
 * @file load_avoidance.cpp
 * @brief 智能避让调度器 - 实现
 * CPU>20%暂停AI、游戏模式全休眠、电池降频、高负载自动暂停
 */

#include "load_avoidance.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <powrprof.h>
#include <chrono>
#include <algorithm>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "powrprof.lib")

namespace LoadAvoidance {

// ============================================================
// 构造/析构
// ============================================================
LoadAvoidanceScheduler::LoadAvoidanceScheduler()
    : current_mode_(RunMode::NORMAL),
      engine_state_(AIEngineState::ACTIVE),
      running_(false) {}

LoadAvoidanceScheduler::~LoadAvoidanceScheduler() { stop(); }

// ============================================================
// 启动/停止
// ============================================================
bool LoadAvoidanceScheduler::start() {
    if (running_) return true;
    running_ = true;
    monitor_thread_ = std::thread(&LoadAvoidanceScheduler::monitor_loop, this);
    return true;
}

void LoadAvoidanceScheduler::stop() {
    running_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void LoadAvoidanceScheduler::set_mode(RunMode mode) {
    current_mode_ = mode;
}

// ============================================================
// 监控循环
// ============================================================
void LoadAvoidanceScheduler::monitor_loop() {
    while (running_) {
        // 1. 检测系统负载
        SystemLoad load = detect_system_load();

        // 2. 计算AI引擎状态
        AIEngineState new_state = calculate_engine_state(load);

        // 3. 状态变化时通知
        if (new_state != engine_state_) {
            engine_state_ = new_state;
            if (state_cb_) {
                state_cb_(new_state);
            }
        }

        // 4. 等待下次检测
        Sleep(CHECK_INTERVAL_MS);
    }
}

// ============================================================
// 检测系统负载
// ============================================================
SystemLoad LoadAvoidanceScheduler::detect_system_load() {
    SystemLoad load = {};
    load.cpu_usage_percent = get_cpu_usage();
    load.available_memory_mb = get_available_memory();
    load.is_game_running = detect_game_running();
    load.is_on_battery = detect_battery_power();
    load.is_fullscreen_app = false; // TODO: 检测全屏应用

    return load;
}

SystemLoad LoadAvoidanceScheduler::get_current_load() const {
    return const_cast<LoadAvoidanceScheduler*>(this)->detect_system_load();
}

// ============================================================
// 计算AI引擎状态
// ============================================================
AIEngineState LoadAvoidanceScheduler::calculate_engine_state(const SystemLoad& load) {
    // 游戏模式：全部AI休眠，仅保留最低防护
    if (current_mode_ == RunMode::GAME_MODE || load.is_game_running) {
        current_mode_ = RunMode::GAME_MODE;
        return AIEngineState::SUSPENDED;
    }

    // 电池模式：降频节能
    if (load.is_on_battery) {
        current_mode_ = RunMode::BATTERY_MODE;
        return AIEngineState::THROTTLED;
    }

    // CPU>20%：暂停所有AI运算
    if (load.cpu_usage_percent > CPU_PAUSE_THRESHOLD) {
        current_mode_ = RunMode::HIGH_LOAD;
        return AIEngineState::SUSPENDED;
    }

    // CPU在10%-20%之间：降频运行
    if (load.cpu_usage_percent > CPU_RESUME_THRESHOLD) {
        return AIEngineState::THROTTLED;
    }

    // 正常运行
    current_mode_ = RunMode::NORMAL;
    return AIEngineState::ACTIVE;
}

// ============================================================
// 运行许可判断
// ============================================================
bool LoadAvoidanceScheduler::can_run_ai() const {
    auto state = engine_state_.load();
    return state == AIEngineState::ACTIVE || state == AIEngineState::THROTTLED;
}

bool LoadAvoidanceScheduler::can_run_scan() const {
    auto state = engine_state_.load();
    // 扫描仅在正常模式下运行
    return state == AIEngineState::ACTIVE;
}

// ============================================================
// CPU使用率检测
// ============================================================
double LoadAvoidanceScheduler::get_cpu_usage() {
    static ULARGE_INTEGER prev_idle = {};
    static ULARGE_INTEGER prev_kernel = {};
    static ULARGE_INTEGER prev_user = {};

    FILETIME idle_time, kernel_time, user_time;
    if (!GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
        return 0.0;
    }

    ULARGE_INTEGER idle, kernel, user;
    idle.LowPart = idle_time.dwLowDateTime;
    idle.HighPart = idle_time.dwHighDateTime;
    kernel.LowPart = kernel_time.dwLowDateTime;
    kernel.HighPart = kernel_time.dwHighDateTime;
    user.LowPart = user_time.dwLowDateTime;
    user.HighPart = user_time.dwHighDateTime;

    ULARGE_INTEGER prev_total, total;
    prev_total.QuadPart = prev_idle.QuadPart + prev_kernel.QuadPart + prev_user.QuadPart;
    total.QuadPart = idle.QuadPart + kernel.QuadPart + user.QuadPart;

    ULARGE_INTEGER diff_idle, diff_total;
    diff_idle.QuadPart = idle.QuadPart - prev_idle.QuadPart;
    diff_total.QuadPart = total.QuadPart - prev_total.QuadPart;

    double cpu_usage = 0.0;
    if (diff_total.QuadPart > 0) {
        cpu_usage = 100.0 * (1.0 - static_cast<double>(diff_idle.QuadPart) / diff_total.QuadPart);
    }

    prev_idle = idle;
    prev_kernel = kernel;
    prev_user = user;

    return cpu_usage;
}

// ============================================================
// 可用内存检测
// ============================================================
uint64_t LoadAvoidanceScheduler::get_available_memory() {
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    GlobalMemoryStatusEx(&status);
    return status.ullAvailPhys / (1024 * 1024);
}

// ============================================================
// 游戏检测
// ============================================================
bool LoadAvoidanceScheduler::detect_game_running() {
    // 检测已知游戏进程
    static const char* game_processes[] = {
        "leagueclient.exe",     // 英雄联盟
        "csgo.exe",             // CS:GO
        "valorant.exe",         // Valorant
        "Overwatch.exe",        // 守望先锋
        "FortniteClient.exe",   // 堡垒之夜
        "dota2.exe",            // Dota2
        "GenshinImpact.exe",    // 原神
        "Yuanshen.exe",         // 原神(国服)
        "Minecraft.exe",        // 我的世界
        "steam.exe",            // Steam(游戏平台)
        "EpicGamesLauncher.exe",// Epic
        "WeGame.exe",           // WeGame
        "bg3.exe",              // 博德之门3
        "Cyberpunk2077.exe",    // 赛博朋克2077
    };

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            char name[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1,
                                name, MAX_PATH, nullptr, nullptr);

            for (auto game : game_processes) {
                if (_stricmp(name, game) == 0) {
                    found = true;
                    break;
                }
            }
            if (found) break;
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return found;
}

// ============================================================
// 电池检测
// ============================================================
bool LoadAvoidanceScheduler::detect_battery_power() {
    SYSTEM_POWER_STATUS status;
    if (GetSystemPowerStatus(&status)) {
        return status.ACLineStatus == 0; // 0=电池供电
    }
    return false;
}

} // namespace LoadAvoidance
