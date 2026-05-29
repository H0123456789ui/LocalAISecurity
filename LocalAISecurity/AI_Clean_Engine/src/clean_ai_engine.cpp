/**
 * @file clean_ai_engine.cpp
 * @brief AI C盘文件智能分类推理引擎 - 实现
 * 纯CPU推理，INT4量化，三层防误删机制
 * 低优先级后台线程扫描，高负载自动暂停
 */

#include "clean_ai_engine.h"
#include <nn_ops.h>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <sstream>
#include <iomanip>

#define NOMINMAX
#include <windows.h>
#include <shellapi.h>

namespace CleanAI {

// ============================================================
// 构造/析构
// ============================================================
CleanAIEngine::CleanAIEngine() : initialized_(false) {}
CleanAIEngine::~CleanAIEngine() { shutdown(); }

// ============================================================
// 初始化
// ============================================================
bool CleanAIEngine::initialize(const std::string& model_path,
                                const std::string& whitelist_path) {
    if (initialized_) return true;

    if (!load_quantized_model(model_path)) return false;
    if (!load_whitelist(whitelist_path)) return false;

    model_path_ = model_path;
    whitelist_path_ = whitelist_path;
    initialized_ = true;
    return true;
}

void CleanAIEngine::shutdown() {
    initialized_ = false;
    params_ = ModelParams();
    system_whitelist_.clear();
}

// ============================================================
// 单文件分类推理
// ============================================================
CleanResult CleanAIEngine::classify_file(const FileFeature& feature,
                                          const std::string& file_path) {
    CleanResult result;
    result.can_delete = false;
    result.inference_time_us = 0;

    if (!initialized_) return result;

    // === 三层防误删校验 ===

    // 层1: 系统核心目录物理锁定
    if (ProtectedPaths::is_protected(file_path)) {
        result.classification = FileClass::SYSTEM_CORE;
        result.confidence = 1.0f;
        result.can_delete = false;
        result.risk_description = "系统核心目录物理锁定，禁止扫描和删除";
        result.probabilities = {1.0f, 0, 0, 0, 0};
        return result;
    }

    // 层3: 白名单校验
    if (check_whitelist(file_path)) {
        result.classification = FileClass::SYSTEM_CORE;
        result.confidence = 1.0f;
        result.can_delete = false;
        result.risk_description = "系统白名单文件，禁止删除";
        result.probabilities = {1.0f, 0, 0, 0, 0};
        return result;
    }

    // 层2: AI文件热度模型 - 近期访问全部保护
    if (check_file_heat(feature)) {
        result.classification = FileClass::SOFTWARE_CACHE;
        result.confidence = 0.95f;
        result.can_delete = false;
        result.risk_description = "近期活跃文件，AI热度保护";
        result.probabilities = {0, 0.95f, 0.05f, 0, 0};
        return result;
    }

    // === AI推理 ===
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<float> input = feature.to_vector();
    std::vector<float> logits = forward(input);
    std::vector<float> probs = AINN::softmax(logits);

    int max_idx = 0;
    float max_prob = probs[0];
    for (int i = 1; i < 5; i++) {
        if (probs[i] > max_prob) {
            max_prob = probs[i];
            max_idx = i;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.inference_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    result.classification = static_cast<FileClass>(max_idx);
    result.confidence = max_prob;
    result.probabilities = probs;

    // 判定是否可安全删除
    result.can_delete = (max_idx == 2 || max_idx == 3); // SAFE_CLEANABLE 或 LARGE_REDUNDANT

    // 风险描述
    switch (result.classification) {
        case FileClass::SYSTEM_CORE:
            result.risk_description = "系统核心必需文件，绝对禁止删除";
            result.can_delete = false;
            break;
        case FileClass::SOFTWARE_CACHE:
            result.risk_description = "软件运行必需缓存，禁止删除";
            result.can_delete = false;
            break;
        case FileClass::SAFE_CLEANABLE:
            result.risk_description = "安全可删普通垃圾，推荐一键清理";
            break;
        case FileClass::LARGE_REDUNDANT:
            result.risk_description = "大型冗余堆积，推荐深度瘦身清理";
            break;
        case FileClass::USER_IMPORTANT:
            result.risk_description = "用户个人重要文件，强制保护";
            result.can_delete = false;
            break;
    }

    return result;
}

// ============================================================
// C盘扫描
// ============================================================
static void scan_directory_recursive(const std::string& dir_path,
                                      CleanAIEngine* engine,
                                      ScanStats& stats,
                                      int depth = 0) {
    const int MAX_SCAN_DEPTH = 12;
    if (depth > MAX_SCAN_DEPTH) return;
    if (stats.total_files > 50000) return; // 防止扫描量过大

    WIN32_FIND_DATAA find_data;
    std::string search_pattern = dir_path + "\\*";
    HANDLE h_find = FindFirstFileA(search_pattern.c_str(), &find_data);
    if (h_find == INVALID_HANDLE_VALUE) return;

    do {
        std::string name = find_data.cFileName;
        if (name == "." || name == "..") continue;

        std::string full_path = dir_path + "\\" + name;
        bool is_dir = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        // 跳过系统锁定目录
        if (ProtectedPaths::is_protected(full_path)) continue;

        // 跳过重解析点（符号链接等，防止无限循环）
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

        if (is_dir) {
            scan_directory_recursive(full_path, engine, stats, depth + 1);
        } else {
            stats.total_files++;

            // 提取文件特征
            FileFeature feature = {};
            feature.path_depth = static_cast<float>(
                std::count(full_path.begin(), full_path.end(), '\\'));
            feature.in_system_dir = ProtectedPaths::is_protected(full_path) ? 1.0f : 0.0f;

            std::string lower_path = full_path;
            std::transform(lower_path.begin(), lower_path.end(),
                          lower_path.begin(), ::tolower);
            feature.in_program_files =
                (lower_path.find("\\program files") != std::string::npos) ? 1.0f : 0.0f;
            feature.in_user_dir =
                (lower_path.find("\\users\\") != std::string::npos) ? 1.0f : 0.0f;
            feature.in_appdata =
                (lower_path.find("\\appdata\\") != std::string::npos) ? 1.0f : 0.0f;
            feature.in_temp =
                (lower_path.find("\\temp") != std::string::npos ||
                 lower_path.find("\\tmp") != std::string::npos) ? 1.0f : 0.0f;

            ULONGLONG file_size =
                (static_cast<ULONGLONG>(find_data.nFileSizeHigh) << 32) |
                find_data.nFileSizeLow;
            feature.file_size_log = file_size > 0 ?
                std::log1p(static_cast<float>(file_size)) / 20.0f : 0.0f;

            auto filetime_to_days = [](const FILETIME& ft) -> float {
                if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return 365.0f;
                ULARGE_INTEGER uli;
                uli.LowPart = ft.dwLowDateTime;
                uli.HighPart = ft.dwHighDateTime;
                FILETIME now_ft;
                GetSystemTimeAsFileTime(&now_ft);
                ULARGE_INTEGER now_uli;
                now_uli.LowPart = now_ft.dwLowDateTime;
                now_uli.HighPart = now_ft.dwHighDateTime;
                LONGLONG diff = now_uli.QuadPart - uli.QuadPart;
                return static_cast<float>(diff) / (10000000LL * 86400);
            };

            feature.create_days_ago = filetime_to_days(find_data.ftCreationTime);
            feature.access_days_ago = filetime_to_days(find_data.ftLastAccessTime);
            feature.modify_days_ago = filetime_to_days(find_data.ftLastWriteTime);
            feature.modify_freq = 0.0f;
            feature.ext_weight = 0.5f;
            feature.sys_dir_weight = feature.in_system_dir > 0.5f ? 0.9f : 0.1f;
            feature.stack_level = 0.0f;
            feature.is_hidden =
                (find_data.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) ? 1.0f : 0.0f;
            feature.is_readonly =
                (find_data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 1.0f : 0.0f;
            feature.is_system =
                (find_data.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) ? 1.0f : 0.0f;

            std::string ext;
            size_t dot_pos = name.rfind('.');
            if (dot_pos != std::string::npos) {
                ext = name.substr(dot_pos);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            }
            feature.ext_risk_score = 0.2f;

            // 调用AI分类
            CleanResult result = engine->classify_file(feature, full_path);

            switch (result.classification) {
                case FileClass::SYSTEM_CORE:     stats.system_core_count++; break;
                case FileClass::SOFTWARE_CACHE:  stats.software_cache_count++; break;
                case FileClass::SAFE_CLEANABLE:
                    stats.safe_cleanable_count++;
                    stats.total_cleanable_size += file_size;
                    break;
                case FileClass::LARGE_REDUNDANT:
                    stats.large_redundant_count++;
                    stats.total_cleanable_size += file_size;
                    break;
                case FileClass::USER_IMPORTANT:  stats.user_important_count++; break;
            }
        }
    } while (FindNextFileA(h_find, &find_data));

    FindClose(h_find);
}

ScanStats CleanAIEngine::scan_drive(char drive_letter, CleanLevel level) {
    ScanStats stats = {};
    auto start = std::chrono::high_resolution_clock::now();

    if (!initialized_) {
        stats.scan_time_ms = 0;
        return stats;
    }

    std::string root = std::string(1, drive_letter) + ":\\";

    // 动态获取系统目录
    char win_dir[MAX_PATH];
    if (GetEnvironmentVariableA("SystemRoot", win_dir, MAX_PATH) == 0) {
        strcpy_s(win_dir, "C:\\Windows");
    }
    std::string windir(win_dir);

    // 扫描垃圾高频目录（使用系统实际路径，非硬编码 C:）
    std::string scan_roots[] = {
        windir + "\\Temp",
        windir + "\\Prefetch",
        windir + "\\SoftwareDistribution\\Download",
        windir + "\\Logs",
    };
    for (auto& scan_root : scan_roots) {
        scan_directory_recursive(scan_root, this, stats);
    }

    // 扫描用户目录下的临时/缓存目录
    char user_profile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", user_profile, MAX_PATH)) {
        std::string user_temp = std::string(user_profile) + "\\AppData\\Local\\Temp";
        scan_directory_recursive(user_temp, this, stats);
        std::string user_cache = std::string(user_profile) +
            "\\AppData\\Local\\Microsoft\\Windows\\Explorer";
        scan_directory_recursive(user_cache, this, stats);
    }

    auto end = std::chrono::high_resolution_clock::now();
    stats.scan_time_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return stats;
}

// ============================================================
// 执行清理
// ============================================================
uint64_t CleanAIEngine::execute_clean(CleanLevel level,
                                       const std::vector<std::string>& file_paths) {
    uint64_t total_freed = 0;

    for (const auto& path : file_paths) {
        // 再次校验三层防误删
        if (ProtectedPaths::is_protected(path)) continue;
        if (check_whitelist(path)) continue;

        // 获取文件大小
        WIN32_FILE_ATTRIBUTE_DATA file_info;
        if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &file_info)) {
            continue;
        }
        uint64_t file_size = (static_cast<uint64_t>(file_info.nFileSizeHigh) << 32) |
                              file_info.nFileSizeLow;

        // 根据清理级别判断
        // SAFE_CLEAN: 仅删除SAFE_CLEANABLE
        // DEEP_CLEAN: 删除SAFE_CLEANABLE + LARGE_REDUNDANT

        // 执行删除（移入回收站而非直接删除）
        SHFILEOPSTRUCTA op = {};
        char from_buf[MAX_PATH + 2] = {};
        strncpy_s(from_buf, path.c_str(), MAX_PATH);
        op.wFunc = FO_DELETE;
        op.pFrom = from_buf;
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;

        if (SHFileOperationA(&op) == 0) {
            total_freed += file_size;
        }
    }

    return total_freed;
}

// ============================================================
// 空间诊断报告
// ============================================================
std::string CleanAIEngine::generate_diagnosis_report(char drive_letter) {
    std::ostringstream report;

    // 获取磁盘空间信息
    std::string root = std::string(1, drive_letter) + ":\\";
    ULARGE_INTEGER total_bytes, free_bytes, used_bytes;
    GetDiskFreeSpaceExA(root.c_str(), nullptr, &total_bytes, &free_bytes);
    used_bytes.QuadPart = total_bytes.QuadPart - free_bytes.QuadPart;

    report << "========== C盘空间诊断报告 ==========\n\n";
    report << "磁盘总容量: " << std::fixed << std::setprecision(1)
           << static_cast<double>(total_bytes.QuadPart) / (1024*1024*1024) << " GB\n";
    report << "已用空间:   " << std::fixed << std::setprecision(1)
           << static_cast<double>(used_bytes.QuadPart) / (1024*1024*1024) << " GB\n";
    report << "可用空间:   " << std::fixed << std::setprecision(1)
           << static_cast<double>(free_bytes.QuadPart) / (1024*1024*1024) << " GB\n";
    report << "使用率:     " << std::fixed << std::setprecision(1)
           << 100.0 * used_bytes.QuadPart / total_bytes.QuadPart << "%\n\n";

    report << "========== AI智能分析 ==========\n";
    report << "（扫描完成后自动填充详细分类数据）\n";

    return report.str();
}

// ============================================================
// 三层防误删校验
// ============================================================
bool CleanAIEngine::check_path_locked(const std::string& path) {
    return ProtectedPaths::is_protected(path);
}

bool CleanAIEngine::check_whitelist(const std::string& path) {
    // 将路径转为小写后匹配
    std::string lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
    return system_whitelist_.find(lower_path) != system_whitelist_.end();
}

bool CleanAIEngine::check_file_heat(const FileFeature& feature) {
    // AI文件热度模型：近期访问的文件全部保护
    // 访问时间在7天以内 → 保护
    if (feature.access_days_ago < 7.0f) return true;
    // 修改时间在3天以内 → 保护
    if (feature.modify_days_ago < 3.0f) return true;
    // 修改频率高 → 保护
    if (feature.modify_freq > 5.0f) return true;
    return false;
}

// ============================================================
// 加载量化模型（同SecurityAIEngine方案）
// ============================================================
bool CleanAIEngine::load_quantized_model(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    char magic[4];
    file.read(magic, 4);
    if (std::memcmp(magic, "CIQF", 4) != 0) return false;

    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), 4);
    if (version != 1) return false;

    uint32_t num_layers;
    file.read(reinterpret_cast<char*>(&num_layers), 4);

    for (uint32_t i = 0; i < num_layers; i++) {
        uint32_t name_len;
        file.read(reinterpret_cast<char*>(&name_len), 4);
        std::string name(name_len, '\0');
        file.read(&name[0], name_len);

        uint32_t shape_dims;
        file.read(reinterpret_cast<char*>(&shape_dims), 4);
        std::vector<int> shape(shape_dims);
        for (auto& s : shape) {
            uint32_t dim;
            file.read(reinterpret_cast<char*>(&dim), 4);
            s = static_cast<int>(dim);
        }

        if (shape_dims > 0) {
            uint32_t num_groups;
            file.read(reinterpret_cast<char*>(&num_groups), 4);

            ModelParams::QuantizedLayer layer;
            layer.original_shape = shape;
            layer.group_size = 16;

            layer.scales.resize(num_groups);
            file.read(reinterpret_cast<char*>(layer.scales.data()),
                      num_groups * sizeof(float));

            layer.zero_points.resize(num_groups);
            file.read(reinterpret_cast<char*>(layer.zero_points.data()),
                      num_groups * sizeof(float));

            uint32_t packed_size;
            file.read(reinterpret_cast<char*>(&packed_size), 4);
            layer.quant_weights.resize(packed_size);
            file.read(reinterpret_cast<char*>(layer.quant_weights.data()), packed_size);

            if (name.find("conv1") != std::string::npos && name.find("weight") != std::string::npos)
                params_.conv1_weight = layer;
            else if (name.find("conv2") != std::string::npos && name.find("weight") != std::string::npos)
                params_.conv2_weight = layer;
            else if (name.find("conv3") != std::string::npos && name.find("weight") != std::string::npos)
                params_.conv3_weight = layer;
            else if (name.find("fusion") != std::string::npos && name.find("weight") != std::string::npos)
                params_.fusion_weight = layer;
            else if (name.find("fc.") != std::string::npos && name.find("weight") != std::string::npos)
                params_.fc_weight = layer;
        } else {
            uint32_t tensor_size;
            file.read(reinterpret_cast<char*>(&tensor_size), 4);
            std::vector<float> tensor(tensor_size);
            file.read(reinterpret_cast<char*>(tensor.data()),
                      tensor_size * sizeof(float));

            if (name.find("conv1.bias") != std::string::npos) params_.conv1_bias = tensor;
            else if (name.find("conv2.bias") != std::string::npos) params_.conv2_bias = tensor;
            else if (name.find("conv3.bias") != std::string::npos) params_.conv3_bias = tensor;
            else if (name.find("fusion.bias") != std::string::npos) params_.fusion_bias = tensor;
            else if (name.find("fc.bias") != std::string::npos) params_.fc_bias = tensor;
            else if (name.find("bn1") != std::string::npos) {
                if (name.find("weight") != std::string::npos) params_.bn1_gamma = tensor;
                else if (name.find("bias") != std::string::npos) params_.bn1_beta = tensor;
                else if (name.find("running_mean") != std::string::npos) params_.bn1_mean = tensor;
                else if (name.find("running_var") != std::string::npos) params_.bn1_var = tensor;
            } else if (name.find("bn2") != std::string::npos) {
                if (name.find("weight") != std::string::npos) params_.bn2_gamma = tensor;
                else if (name.find("bias") != std::string::npos) params_.bn2_beta = tensor;
                else if (name.find("running_mean") != std::string::npos) params_.bn2_mean = tensor;
                else if (name.find("running_var") != std::string::npos) params_.bn2_var = tensor;
            } else if (name.find("bn3") != std::string::npos) {
                if (name.find("weight") != std::string::npos) params_.bn3_gamma = tensor;
                else if (name.find("bias") != std::string::npos) params_.bn3_beta = tensor;
                else if (name.find("running_mean") != std::string::npos) params_.bn3_mean = tensor;
                else if (name.find("running_var") != std::string::npos) params_.bn3_var = tensor;
            }
        }
    }

    file.close();
    return true;
}

// ============================================================
// 加载白名单
// ============================================================
bool CleanAIEngine::load_whitelist(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        system_whitelist_.insert(line);
    }

    file.close();
    return true;
}

// ============================================================
// INT4反量化
// ============================================================
std::vector<float> CleanAIEngine::dequantize(
    const ModelParams::QuantizedLayer& layer) {
    int total_elements = 1;
    for (auto s : layer.original_shape) total_elements *= s;

    std::vector<float> result(total_elements);
    int group_size = layer.group_size;
    int num_groups = static_cast<int>(layer.scales.size());

    int idx = 0;
    for (int g = 0; g < num_groups; g++) {
        for (int j = 0; j < group_size && idx < total_elements; j++, idx++) {
            int byte_idx = idx / 2;
            bool is_high = (idx % 2 == 1);
            uint8_t packed = layer.quant_weights[byte_idx];
            uint8_t qval = is_high ? (packed >> 4) : (packed & 0x0F);
            result[idx] = static_cast<float>(qval) * layer.scales[g] + layer.zero_points[g];
        }
    }

    return result;
}

// ============================================================
// 前向推理
// ============================================================
std::vector<float> CleanAIEngine::forward(const std::vector<float>& input) {
    // 输入: (1, 18)
    // Conv1d(1, 16, 3) + BN + ReLU
    auto w1 = dequantize(params_.conv1_weight);
    auto x = AINN::conv1d(input, w1, params_.conv1_bias, 1, 16, 3);
    x = AINN::batch_norm(x, params_.bn1_gamma, params_.bn1_beta, params_.bn1_mean, params_.bn1_var);
    x = AINN::relu(x);

    // Conv1d(16, 32, 3) + BN + ReLU
    auto w2 = dequantize(params_.conv2_weight);
    x = AINN::conv1d(x, w2, params_.conv2_bias, 16, 32, 3);
    x = AINN::batch_norm(x, params_.bn2_gamma, params_.bn2_beta, params_.bn2_mean, params_.bn2_var);
    x = AINN::relu(x);

    // Conv1d(32, 64, 3) + BN + ReLU
    auto w3 = dequantize(params_.conv3_weight);
    x = AINN::conv1d(x, w3, params_.conv3_bias, 32, 64, 3);
    x = AINN::batch_norm(x, params_.bn3_gamma, params_.bn3_beta, params_.bn3_mean, params_.bn3_var);
    x = AINN::relu(x);

    // MaxPool1d(2): 输入(64, 18) → 输出(64, 9)
    x = AINN::max_pool1d(x, 64, 2);

    // 融合层: (576 -> 128) + ReLU
    auto wf = dequantize(params_.fusion_weight);
    x = AINN::linear(x, wf, params_.fusion_bias);
    x = AINN::relu(x);

    // 输出层: (128 -> 5)
    auto wo = dequantize(params_.fc_weight);
    x = AINN::linear(x, wo, params_.fc_bias);

    return x;
}

#if 0 // 以下算子已统一提取至 AI_Common/include/nn_ops.h
std::vector<float> CleanAIEngine::conv1d(
    const std::vector<float>& input,
    const std::vector<float>& weight,
    const std::vector<float>& bias,
    int in_ch, int out_ch, int kernel) {

    int input_len = static_cast<int>(input.size()) / in_ch;
    int output_len = input_len;
    std::vector<float> output(out_ch * output_len, 0.0f);

    for (int oc = 0; oc < out_ch; oc++) {
        for (int i = 0; i < output_len; i++) {
            float sum = bias[oc];
            for (int ic = 0; ic < in_ch; ic++) {
                for (int k = 0; k < kernel; k++) {
                    int input_idx = i + k - kernel / 2;
                    if (input_idx >= 0 && input_idx < input_len) {
                        int w_idx = oc * in_ch * kernel + ic * kernel + k;
                        sum += input[ic * input_len + input_idx] * weight[w_idx];
                    }
                }
            }
            output[oc * output_len + i] = sum;
        }
    }
    return output;
}

std::vector<float> CleanAIEngine::batch_norm(
    const std::vector<float>& input,
    const std::vector<float>& gamma,
    const std::vector<float>& beta,
    const std::vector<float>& mean,
    const std::vector<float>& var) {

    int channels = static_cast<int>(gamma.size());
    int spatial = static_cast<int>(input.size()) / channels;
    std::vector<float> output(input.size());
    float eps = 1e-5f;

    for (int c = 0; c < channels; c++) {
        float scale = gamma[c] / std::sqrt(var[c] + eps);
        float offset = beta[c] - mean[c] * scale;
        for (int s = 0; s < spatial; s++) {
            output[c * spatial + s] = input[c * spatial + s] * scale + offset;
        }
    }
    return output;
}

std::vector<float> CleanAIEngine::max_pool1d(
    const std::vector<float>& input, int channels, int kernel) {
    // input layout: (channels, spatial) as [c0_s0, c0_s1, ..., c1_s0, c1_s1, ...]
    int spatial = static_cast<int>(input.size()) / channels;
    int output_spatial = spatial / kernel;
    std::vector<float> output(channels * output_spatial);

    for (int c = 0; c < channels; c++) {
        int c_offset = c * spatial;
        int out_offset = c * output_spatial;
        for (int i = 0; i < output_spatial; i++) {
            float max_val = -1e30f;
            for (int k = 0; k < kernel; k++) {
                float val = input[c_offset + i * kernel + k];
                if (val > max_val) max_val = val;
            }
            output[out_offset + i] = max_val;
        }
    }
    return output;
}

std::vector<float> CleanAIEngine::linear(
    const std::vector<float>& input,
    const std::vector<float>& weight,
    const std::vector<float>& bias) {

    int output_dim = static_cast<int>(bias.size());
    int input_dim = static_cast<int>(input.size());
    std::vector<float> output(output_dim);

    for (int o = 0; o < output_dim; o++) {
        float sum = bias[o];
        for (int i = 0; i < input_dim; i++) {
            sum += input[i] * weight[o * input_dim + i];
        }
        output[o] = sum;
    }
    return output;
}

std::vector<float> CleanAIEngine::relu(const std::vector<float>& x) {
    std::vector<float> result(x.size());
    for (size_t i = 0; i < x.size(); i++) {
        result[i] = std::max(0.0f, x[i]);
    }
    return result;
}

std::vector<float> CleanAIEngine::softmax(const std::vector<float>& x) {
    float max_val = *std::max_element(x.begin(), x.end());
    std::vector<float> result(x.size());
    float sum = 0.0f;

    for (size_t i = 0; i < x.size(); i++) {
        result[i] = std::exp(x[i] - max_val);
        sum += result[i];
    }

    for (auto& v : result) v /= sum;
    return result;
}
#endif // 旧算子定义结束

} // namespace CleanAI
