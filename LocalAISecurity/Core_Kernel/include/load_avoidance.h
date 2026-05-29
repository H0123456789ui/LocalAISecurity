/**
 * @file load_avoidance.h
 * @brief 智能避让调度器 - 头文件
 * CPU>20%暂停AI运算、游戏模式全休眠、电池模式降频
 */

#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <atomic>
#include <thread>

namespace LoadAvoidance {

// ============================================================
// 运行模式
// ============================================================
enum class RunMode : int {
    NORMAL = 0,         // 标准模式
    GAME_MODE = 1,      // 游戏模式 - 全部AI休眠，仅最低防护
    BATTERY_MODE = 2,   // 电池模式 - 降频节能
    HIGH_LOAD = 3       // 高负载模式 - 暂停所有AI运算
};

// ============================================================
// 系统负载信息
// ============================================================
struct SystemLoad {
    double cpu_usage_percent;        // CPU占用率
    uint64_t available_memory_mb;    // 可用内存
    double gpu_usage_percent;        // GPU占用率(如有)
    bool is_game_running;            // 是否有游戏运行
    bool is_on_battery;              // 是否使用电池
    bool is_fullscreen_app;          // 是否有全屏应用
    double disk_usage_percent;       // 磁盘IO占用
};

// ============================================================
// AI引擎调度控制
// ============================================================
enum class AIEngineState : int {
    ACTIVE = 0,         // 正常运行
    THROTTLED = 1,      // 降频运行
    SUSPENDED = 2       // 完全休眠
};

using StateCallback = std::function<void(AIEngineState)>;

// ============================================================
// 智能避让调度器
// ============================================================
class LoadAvoidanceScheduler {
public:
    LoadAvoidanceScheduler();
    ~LoadAvoidanceScheduler();

    /** 启动调度器 */
    bool start();

    /** 停止调度器 */
    void stop();

    /** 手动设置运行模式 */
    void set_mode(RunMode mode);
    RunMode get_mode() const { return current_mode_.load(); }

    /** 设置状态变化回调 */
    void set_state_callback(StateCallback callback) { state_cb_ = callback; }

    /** 获取当前系统负载 */
    SystemLoad get_current_load() const;

    /** 获取当前AI引擎状态 */
    AIEngineState get_engine_state() const { return engine_state_.load(); }

    /** 检查是否允许AI运算 */
    bool can_run_ai() const;

    /** 检查是否允许C盘扫描 */
    bool can_run_scan() const;

    // ---- 铁律参数 ----
    static constexpr double CPU_PAUSE_THRESHOLD = 20.0;    // CPU>20%暂停AI
    static constexpr double CPU_RESUME_THRESHOLD = 10.0;   // CPU<10%恢复AI
    static constexpr double CPU_PEAK_LIMIT = 8.0;          // 峰值CPU≤8%
    static constexpr uint64_t MEMORY_LIMIT_MB = 15;        // 常态内存≤15MB
    static constexpr int CHECK_INTERVAL_MS = 2000;         // 检测间隔2秒

private:
    std::atomic<RunMode> current_mode_;
    std::atomic<AIEngineState> engine_state_;
    std::atomic<bool> running_;
    std::thread monitor_thread_;
    StateCallback state_cb_;

    void monitor_loop();
    SystemLoad detect_system_load();
    AIEngineState calculate_engine_state(const SystemLoad& load);
    bool detect_game_running();
    bool detect_battery_power();
    double get_cpu_usage();
    uint64_t get_available_memory();
};

} // namespace LoadAvoidance
