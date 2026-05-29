/**
 * @file local_data.cpp
 * @brief 本地数据层 - 实现
 * 纯文件存储，CSV格式，零第三方数据库依赖
 * 日志留存6个月，所有操作本地可溯源
 */

#include "local_data.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <algorithm>

namespace LocalData {

// ============================================================
// 构造/析构
// ============================================================
LocalDataManager::LocalDataManager() : initialized_(false) {}
LocalDataManager::~LocalDataManager() = default;

// ============================================================
// 初始化
// ============================================================
bool LocalDataManager::initialize(const std::string& data_dir) {
    data_dir_ = data_dir;
    log_dir_ = data_dir + "/logs";
    config_path_ = data_dir + "/config/app_config.ini";
    stats_path_ = data_dir + "/config/stats.dat";

    if (!ensure_directories()) return false;

    initialized_ = true;
    return true;
}

bool LocalDataManager::ensure_directories() {
    try {
        std::filesystem::create_directories(data_dir_);
        std::filesystem::create_directories(log_dir_);
        std::filesystem::create_directories(data_dir_ + "/config");
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================
// 通用日志
// ============================================================
void LocalDataManager::write_log(LogLevel level, const std::string& module,
                                  const std::string& message) {
    if (!initialized_) return;

    std::string level_str[] = {"INFO", "WARN", "ERROR", "CRITICAL"};
    std::string filename = log_dir_ + "/app_" + get_timestamp_str().substr(0, 10) + ".log";

    std::ofstream file(filename, std::ios::app);
    if (!file.is_open()) return;

    file << get_timestamp_str() << " | "
         << level_str[static_cast<int>(level)] << " | "
         << module << " | "
         << message << "\n";
}

// ============================================================
// 安全日志
// ============================================================
void LocalDataManager::write_security_log(const SecurityLogEntry& entry) {
    if (!initialized_) return;

    std::string filename = log_dir_ + "/security.log";
    std::ofstream file(filename, std::ios::app);
    if (!file.is_open()) return;

    file << entry.timestamp << "|"
         << entry.time_str << "|"
         << entry.process_name << "|"
         << entry.process_path << "|"
         << entry.threat_type << "|"
         << entry.action << "|"
         << entry.severity << "|"
         << entry.detail << "\n";
}

// ============================================================
// 清理日志
// ============================================================
void LocalDataManager::write_clean_log(const CleanLogEntry& entry) {
    if (!initialized_) return;

    std::string filename = log_dir_ + "/clean.log";
    std::ofstream file(filename, std::ios::app);
    if (!file.is_open()) return;

    file << entry.timestamp << "|"
         << entry.time_str << "|"
         << entry.clean_level << "|"
         << entry.files_cleaned << "|"
         << entry.bytes_freed << "|"
         << entry.detail << "\n";
}

// ============================================================
// 查询安全日志
// ============================================================
std::vector<SecurityLogEntry> LocalDataManager::query_security_logs(
    int limit, int severity_min) {

    std::vector<SecurityLogEntry> results;
    std::string filename = log_dir_ + "/security.log";

    std::ifstream file(filename);
    if (!file.is_open()) return results;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::vector<std::string> tokens;
        std::istringstream iss(line);
        std::string token;
        while (std::getline(iss, token, '|')) {
            tokens.push_back(token);
        }

        if (tokens.size() >= 8) {
            SecurityLogEntry entry;
            entry.timestamp = std::stoull(tokens[0]);
            entry.time_str = tokens[1];
            entry.process_name = tokens[2];
            entry.process_path = tokens[3];
            entry.threat_type = tokens[4];
            entry.action = tokens[5];
            entry.severity = std::stoi(tokens[6]);
            entry.detail = tokens[7];

            if (entry.severity >= severity_min) {
                results.push_back(entry);
            }
        }
    }

    // 按时间倒序
    std::sort(results.begin(), results.end(),
        [](const SecurityLogEntry& a, const SecurityLogEntry& b) {
            return a.timestamp > b.timestamp;
        });

    if (static_cast<int>(results.size()) > limit) {
        results.resize(limit);
    }

    return results;
}

// ============================================================
// 查询清理日志
// ============================================================
std::vector<CleanLogEntry> LocalDataManager::query_clean_logs(int limit) {
    std::vector<CleanLogEntry> results;
    std::string filename = log_dir_ + "/clean.log";

    std::ifstream file(filename);
    if (!file.is_open()) return results;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::vector<std::string> tokens;
        std::istringstream iss(line);
        std::string token;
        while (std::getline(iss, token, '|')) {
            tokens.push_back(token);
        }

        if (tokens.size() >= 6) {
            CleanLogEntry entry;
            entry.timestamp = std::stoull(tokens[0]);
            entry.time_str = tokens[1];
            entry.clean_level = std::stoi(tokens[2]);
            entry.files_cleaned = std::stoull(tokens[3]);
            entry.bytes_freed = std::stoull(tokens[4]);
            entry.detail = tokens[5];
            results.push_back(entry);
        }
    }

    std::sort(results.begin(), results.end(),
        [](const CleanLogEntry& a, const CleanLogEntry& b) {
            return a.timestamp > b.timestamp;
        });

    if (static_cast<int>(results.size()) > limit) {
        results.resize(limit);
    }

    return results;
}

// ============================================================
// 清理过期日志
// ============================================================
void LocalDataManager::purge_expired_logs() {
    if (!initialized_) return;

    // 默认6个月 = 180天
    auto cutoff = std::chrono::system_clock::now() -
                  std::chrono::hours(180 * 24);
    auto cutoff_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        cutoff.time_since_epoch()).count();

    // 安全日志
    {
        std::string filename = log_dir_ + "/security.log";
        std::ifstream infile(filename);
        std::ofstream outfile(filename + ".tmp");

        std::string line;
        while (std::getline(infile, line)) {
            if (line.empty()) continue;
            size_t pos = line.find('|');
            if (pos != std::string::npos) {
                uint64_t ts = std::stoull(line.substr(0, pos));
                if (ts >= cutoff_ms) {
                    outfile << line << "\n";
                }
            }
        }

        infile.close();
        outfile.close();
        std::filesystem::rename(filename + ".tmp", filename);
    }

    // 清理日志
    {
        std::string filename = log_dir_ + "/clean.log";
        std::ifstream infile(filename);
        std::ofstream outfile(filename + ".tmp");

        std::string line;
        while (std::getline(infile, line)) {
            if (line.empty()) continue;
            size_t pos = line.find('|');
            if (pos != std::string::npos) {
                uint64_t ts = std::stoull(line.substr(0, pos));
                if (ts >= cutoff_ms) {
                    outfile << line << "\n";
                }
            }
        }

        infile.close();
        outfile.close();
        std::filesystem::rename(filename + ".tmp", filename);
    }
}

// ============================================================
// 配置操作
// ============================================================
AppConfig LocalDataManager::load_config() {
    AppConfig config = {};
    config.network_enabled = false;       // 默认离线
    config.silent_update = false;
    config.security_ai_enabled = true;
    config.clean_ai_enabled = true;
    config.game_mode = false;
    config.battery_save = true;
    config.auto_clean_temp = false;
    config.clean_schedule_days = 0;
    config.log_retention_days = 180;      // 6个月
    config.app_version = "1.0.0";
    config.security_model_version = "1.0.0";
    config.clean_model_version = "1.0.0";
    config.rule_db_version = "1.0.0";

    std::ifstream file(config_path_);
    if (!file.is_open()) return config;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        if (key == "network_enabled") config.network_enabled = (value == "1");
        else if (key == "silent_update") config.silent_update = (value == "1");
        else if (key == "security_ai_enabled") config.security_ai_enabled = (value == "1");
        else if (key == "clean_ai_enabled") config.clean_ai_enabled = (value == "1");
        else if (key == "game_mode") config.game_mode = (value == "1");
        else if (key == "battery_save") config.battery_save = (value == "1");
        else if (key == "auto_clean_temp") config.auto_clean_temp = (value == "1");
        else if (key == "clean_schedule_days") config.clean_schedule_days = std::stoi(value);
        else if (key == "log_retention_days") config.log_retention_days = std::stoi(value);
        else if (key == "app_version") config.app_version = value;
        else if (key == "security_model_version") config.security_model_version = value;
        else if (key == "clean_model_version") config.clean_model_version = value;
        else if (key == "rule_db_version") config.rule_db_version = value;
    }

    return config;
}

bool LocalDataManager::save_config(const AppConfig& config) {
    std::ofstream file(config_path_);
    if (!file.is_open()) return false;

    file << "# LocalAI Security Configuration\n";
    file << "# All data stored locally, zero upload\n\n";

    file << "network_enabled=" << (config.network_enabled ? "1" : "0") << "\n";
    file << "silent_update=" << (config.silent_update ? "1" : "0") << "\n";
    file << "security_ai_enabled=" << (config.security_ai_enabled ? "1" : "0") << "\n";
    file << "clean_ai_enabled=" << (config.clean_ai_enabled ? "1" : "0") << "\n";
    file << "game_mode=" << (config.game_mode ? "1" : "0") << "\n";
    file << "battery_save=" << (config.battery_save ? "1" : "0") << "\n";
    file << "auto_clean_temp=" << (config.auto_clean_temp ? "1" : "0") << "\n";
    file << "clean_schedule_days=" << config.clean_schedule_days << "\n";
    file << "log_retention_days=" << config.log_retention_days << "\n";
    file << "app_version=" << config.app_version << "\n";
    file << "security_model_version=" << config.security_model_version << "\n";
    file << "clean_model_version=" << config.clean_model_version << "\n";
    file << "rule_db_version=" << config.rule_db_version << "\n";

    return true;
}

// ============================================================
// 统计操作
// ============================================================
static void read_all_stats(const std::string& path,
                           uint64_t& threats, uint64_t& bytes, uint64_t& scans) {
    threats = bytes = scans = 0;
    std::ifstream file(path);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        if (line.find("threats_blocked=") == 0)
            threats = std::stoull(line.substr(16));
        else if (line.find("bytes_freed=") == 0)
            bytes = std::stoull(line.substr(12));
        else if (line.find("total_scans=") == 0)
            scans = std::stoull(line.substr(12));
    }
}

void LocalDataManager::rewrite_stats(uint64_t threats, uint64_t bytes, uint64_t scans) {
    std::ofstream file(stats_path_);
    if (file.is_open()) {
        file << "threats_blocked=" << threats << "\n";
        file << "bytes_freed=" << bytes << "\n";
        file << "total_scans=" << scans << "\n";
    }
}

uint64_t LocalDataManager::get_total_threats_blocked() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t threats, bytes, scans;
    read_all_stats(stats_path_, threats, bytes, scans);
    return threats;
}

uint64_t LocalDataManager::get_total_bytes_freed() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t threats, bytes, scans;
    read_all_stats(stats_path_, threats, bytes, scans);
    return bytes;
}

uint64_t LocalDataManager::get_total_scans() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t threats, bytes, scans;
    read_all_stats(stats_path_, threats, bytes, scans);
    return scans;
}

void LocalDataManager::increment_threats_blocked() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t threats, bytes, scans;
    read_all_stats(stats_path_, threats, bytes, scans);
    rewrite_stats(threats + 1, bytes, scans);
}

void LocalDataManager::add_bytes_freed(uint64_t val) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t threats, bytes, scans;
    read_all_stats(stats_path_, threats, bytes, scans);
    rewrite_stats(threats, bytes + val, scans);
}

void LocalDataManager::increment_scans() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t threats, bytes, scans;
    read_all_stats(stats_path_, threats, bytes, scans);
    rewrite_stats(threats, bytes, scans + 1);
}

// ============================================================
// 工具方法
// ============================================================
std::string LocalDataManager::get_timestamp_str() const {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
    localtime_s(&tm_buf, &time_t_now);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

uint64_t LocalDataManager::get_timestamp_ms() const {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
}

} // namespace LocalData
