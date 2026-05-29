/**
 * @file local_data.h
 * @brief 本地数据层 - 头文件
 * 本地日志、本地配置、本地规则库、模型缓存
 * 所有数据100%本地存储，零上传
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <mutex>

namespace LocalData {

// ============================================================
// 日志级别
// ============================================================
enum class LogLevel : int {
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    CRITICAL = 3
};

// ============================================================
// 安全日志条目
// ============================================================
struct SecurityLogEntry {
    uint64_t timestamp;         // 时间戳(毫秒)
    std::string time_str;       // 可读时间
    std::string process_name;   // 进程名
    std::string process_path;   // 进程路径
    std::string threat_type;    // 威胁类型
    std::string action;         // 处置动作
    int severity;               // 严重级别(1-5)
    std::string detail;         // 详细信息
};

// ============================================================
// 清理日志条目
// ============================================================
struct CleanLogEntry {
    uint64_t timestamp;
    std::string time_str;
    int clean_level;            // 清理级别
    uint64_t files_cleaned;     // 清理文件数
    uint64_t bytes_freed;       // 释放字节数
    std::string detail;
};

// ============================================================
// 应用配置
// ============================================================
struct AppConfig {
    // 网络
    bool network_enabled;       // 是否允许联网（默认false）
    bool silent_update;         // 静默更新

    // 防护
    bool security_ai_enabled;   // 安全AI开关
    bool clean_ai_enabled;      // 清理AI开关
    bool game_mode;             // 游戏模式
    bool battery_save;          // 电池节能

    // 清理
    bool auto_clean_temp;       // 自动清理临时文件
    int clean_schedule_days;    // 定期清理天数(0=手动)

    // 日志
    int log_retention_days;     // 日志保留天数（默认180天/6个月）

    // 版本
    std::string app_version;
    std::string security_model_version;
    std::string clean_model_version;
    std::string rule_db_version;
};

// ============================================================
// 本地数据管理器
// ============================================================
class LocalDataManager {
public:
    LocalDataManager();
    ~LocalDataManager();

    /** 初始化 */
    bool initialize(const std::string& data_dir);

    // ---- 日志操作 ----
    void write_log(LogLevel level, const std::string& module,
                   const std::string& message);
    void write_security_log(const SecurityLogEntry& entry);
    void write_clean_log(const CleanLogEntry& entry);

    std::vector<SecurityLogEntry> query_security_logs(
        int limit = 100, int severity_min = 0);
    std::vector<CleanLogEntry> query_clean_logs(int limit = 100);

    /** 清理过期日志（默认6个月） */
    void purge_expired_logs();

    // ---- 配置操作 ----
    AppConfig load_config();
    bool save_config(const AppConfig& config);

    // ---- 统计操作 ----
    uint64_t get_total_threats_blocked();
    uint64_t get_total_bytes_freed();
    uint64_t get_total_scans();
    void increment_threats_blocked();
    void add_bytes_freed(uint64_t bytes);
    void increment_scans();

private:
    std::string data_dir_;
    bool initialized_;

    std::string log_dir_;
    std::string config_path_;
    std::string stats_path_;
    mutable std::mutex stats_mutex_;

    bool ensure_directories();
    void rewrite_stats(uint64_t threats, uint64_t bytes, uint64_t scans);
    std::string get_timestamp_str() const;
    uint64_t get_timestamp_ms() const;
};

} // namespace LocalData
