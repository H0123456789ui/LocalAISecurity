/**
 * @file clean_ai_engine.h
 * @brief AI C盘文件智能分类推理引擎 - 头文件
 * 纯CPU推理，INT4量化模型，5级智能分类
 * 防误删三层机制：系统核心目录物理锁定 + AI文件热度模型 + 白名单双权重校验
 */

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <unordered_set>

namespace CleanAI {

// ============================================================
// 数据结构定义
// ============================================================

/** 18维文件特征向量 */
struct FileFeature {
    float path_depth;         // [0]   文件路径深度(目录层级数)
    float in_system_dir;      // [1]   是否在系统目录 (0/1)
    float in_program_files;   // [2]   是否在Program Files (0/1)
    float in_user_dir;        // [3]   是否在用户目录 (0/1)
    float in_appdata;         // [4]   是否在AppData (0/1)
    float in_temp;            // [5]   是否在Temp目录 (0/1)
    float file_size_log;      // [6]   文件大小 (MB, log归一化)
    float create_days_ago;    // [7]   创建时间距今天数
    float access_days_ago;    // [8]   最后访问时间距今天数
    float modify_days_ago;    // [9]   最后修改时间距今天数
    float modify_freq;        // [10]  修改频率 (次/月)
    float ext_weight;         // [11]  文件后缀权重 (0-1)
    float sys_dir_weight;     // [12]  系统目录权重 (0-1)
    float stack_level;        // [13]  堆叠层级特征(同目录文件数归一化)
    float is_hidden;          // [14]  是否为隐藏文件 (0/1)
    float is_readonly;        // [15]  是否为只读文件 (0/1)
    float is_system;          // [16]  是否为系统文件属性 (0/1)
    float ext_risk_score;     // [17]  扩展名风险评分 (0-1)

    std::vector<float> to_vector() const {
        return {
            path_depth, in_system_dir, in_program_files, in_user_dir,
            in_appdata, in_temp, file_size_log, create_days_ago,
            access_days_ago, modify_days_ago, modify_freq, ext_weight,
            sys_dir_weight, stack_level, is_hidden, is_readonly,
            is_system, ext_risk_score
        };
    }
};

/** 5级智能分类 */
enum class FileClass : int {
    SYSTEM_CORE = 0,         // 系统核心必需 - 绝对禁止删除
    SOFTWARE_CACHE = 1,      // 软件运行必需缓存 - 禁止删除
    SAFE_CLEANABLE = 2,      // 安全可删普通垃圾 - 一键清理区
    LARGE_REDUNDANT = 3,     // 大型冗余堆积 - 深度瘦身区
    USER_IMPORTANT = 4       // 用户个人重要文件 - 强制保护
};

struct CleanResult {
    FileClass classification;
    float confidence;
    std::vector<float> probabilities;
    uint64_t inference_time_us;
    bool can_delete;                // 是否可安全删除
    std::string risk_description;   // 风险描述
};

/** 扫描统计 */
struct ScanStats {
    uint64_t total_files;
    uint64_t system_core_count;
    uint64_t software_cache_count;
    uint64_t safe_cleanable_count;
    uint64_t large_redundant_count;
    uint64_t user_important_count;
    uint64_t total_cleanable_size;  // 可清理总大小(字节)
    uint64_t scan_time_ms;
};

/** 清理级别 */
enum class CleanLevel {
    SAFE_CLEAN,       // AI安全一键清理（零风险）- 仅清理SAFE_CLEANABLE
    DEEP_CLEAN,       // AI深度智能瘦身 - 清理SAFE_CLEANABLE + LARGE_REDUNDANT
    DIAGNOSIS_ONLY    // 仅诊断报告，不执行清理
};

// ============================================================
// 系统核心目录物理锁定表
// ============================================================
struct ProtectedPaths {
    static std::string system_root() {
        const char* v = std::getenv("SystemRoot");
        return v ? std::string(v) : std::string("C:\\Windows");
    }

    static std::string system_drive() {
        const char* v = std::getenv("SystemDrive");
        return v ? std::string(v) : std::string("C:");
    }

    static const std::vector<std::string>& get_locked_paths() {
        static std::vector<std::string> paths;
        static bool initialized = false;
        if (!initialized) {
            initialized = true;
            std::string root = system_root();
            std::string drive = system_drive();
            paths = {
                root + "\\System32",
                root + "\\SysWOW64",
                root + "\\System",
                root + "\\Fonts",
                root + "\\INF",
                root + "\\Driver Store",
                root + "\\WinSxS",
                root + "\\Boot",
                root + "\\Panther",
                root + "\\Registration",
                drive + "\\$Recycle.Bin",
                drive + "\\Boot",
                drive + "\\EFI",
                drive + "\\Recovery",
                drive + "\\ProgramData\\Microsoft\\Windows",
                drive + "\\Users\\All Users\\Microsoft\\Windows"
            };
        }
        return paths;
    }

    /** 检查路径是否在锁定目录内 */
    static bool is_protected(const std::string& path) {
        for (const auto& locked : get_locked_paths()) {
            if (path.size() >= locked.size() &&
                _strnicmp(path.c_str(), locked.c_str(), locked.size()) == 0) {
                return true;
            }
        }
        return false;
    }
};

// ============================================================
// 核心引擎类
// ============================================================
class CleanAIEngine {
public:
    CleanAIEngine();
    ~CleanAIEngine();

    /** 初始化引擎 */
    bool initialize(const std::string& model_path,
                    const std::string& whitelist_path);

    /** 单文件AI分类推理 */
    CleanResult classify_file(const FileFeature& feature,
                              const std::string& file_path);

    /** 批量文件分类（C盘扫描核心） */
    ScanStats scan_drive(char drive_letter, CleanLevel level);

    /** 执行清理（用户确认后） */
    uint64_t execute_clean(CleanLevel level,
                           const std::vector<std::string>& file_paths);

    /** 生成空间诊断报告 */
    std::string generate_diagnosis_report(char drive_letter);

    /** 获取引擎状态 */
    bool is_initialized() const { return initialized_; }

    void shutdown();

private:
    bool initialized_;
    std::string model_path_;
    std::string whitelist_path_;

    // 系统白名单
    std::unordered_set<std::string> system_whitelist_;

    // 模型参数（INT4量化）
    struct ModelParams {
        struct QuantizedLayer {
            std::vector<uint8_t> quant_weights;
            std::vector<float> scales;
            std::vector<float> zero_points;
            std::vector<int> original_shape;
            int group_size = 16;
        };

        QuantizedLayer conv1_weight, conv2_weight, conv3_weight;
        std::vector<float> conv1_bias, conv2_bias, conv3_bias;
        std::vector<float> bn1_gamma, bn1_beta, bn1_mean, bn1_var;
        std::vector<float> bn2_gamma, bn2_beta, bn2_mean, bn2_var;
        std::vector<float> bn3_gamma, bn3_beta, bn3_mean, bn3_var;
        QuantizedLayer fusion_weight;
        std::vector<float> fusion_bias;
        QuantizedLayer fc_weight;
        std::vector<float> fc_bias;
    } params_;

    // 内部方法
    bool load_quantized_model(const std::string& path);
    bool load_whitelist(const std::string& path);
    std::vector<float> dequantize(const ModelParams::QuantizedLayer& layer);
    std::vector<float> forward(const std::vector<float>& input);

    // 三层防误删校验
    bool check_path_locked(const std::string& path);        // 层1: 物理锁定
    bool check_whitelist(const std::string& path);          // 层3: 白名单校验
    bool check_file_heat(const FileFeature& feature);       // 层2: 热度模型
};

} // namespace CleanAI
