/**
 * @file security_ai_engine.cpp
 * @brief AI安全行为识别推理引擎 - 实现
 * 纯CPU推理，INT4量化模型，5-10ms单次推理
 * 事件触发机制：非轮询，仅进程启动/文件改写/网络连接/注册表修改时触发
 */

#include "security_ai_engine.h"
#include <nn_ops.h>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")

namespace SecurityAI {

// ============================================================
// 静态方法：从Windows进程快照提取32维行为特征
// 对应 BehaviorFeature 结构体，使用 WinAPI 采集进程指标
// 行为频率特征(文件/注册表/网络速率)需内核事件监控器填充
// ============================================================
BehaviorFeature SecurityAIEngine::extract_features(uint32_t pid) {
    BehaviorFeature f = {};

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, static_cast<DWORD>(pid));
    if (!hProcess) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    }
    if (!hProcess) return f;

    char exePath[MAX_PATH] = {};
    DWORD pathLen = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, exePath, &pathLen)) {
        std::string path(exePath);
        std::string pathLower = path;
        std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);

        // [25] 自启动路径检测
        f.auto_start = (pathLower.find("\\run") != std::string::npos ||
                        pathLower.find("\\startup") != std::string::npos ||
                        pathLower.find("\\services") != std::string::npos)
                           ? 0.8f
                           : 0.0f;

        // [29] 诱导点击: 可疑目录+可疑名称组合
        bool inTemp = (pathLower.find("\\temp\\") != std::string::npos ||
                       pathLower.find("\\tmp\\") != std::string::npos ||
                       pathLower.find("\\downloads\\") != std::string::npos);
        bool hasSuspiciousName =
            (pathLower.find("setup") != std::string::npos ||
             pathLower.find("install") != std::string::npos ||
             pathLower.find("update") != std::string::npos ||
             pathLower.find("patch") != std::string::npos);
        f.deceptive_click = (inTemp && hasSuspiciousName) ? 0.7f : (inTemp ? 0.3f : 0.0f);

        // [30] 浏览器劫持: 修改浏览器目录
        f.browser_hijack = (pathLower.find("\\google\\chrome\\") != std::string::npos ||
                            pathLower.find("\\mozilla\\firefox\\") != std::string::npos ||
                            pathLower.find("\\microsoft\\edge\\") != std::string::npos)
                               ? 0.6f
                               : 0.0f;

        // [31] 权限提升: system32下非系统签名进程
        f.privilege_escalate =
            (pathLower.find("\\system32\\") != std::string::npos && inTemp) ? 0.9f : 0.0f;

        // [16] 进程注入: 可疑路径+新创建的进程 (由调用者根据事件类型判断)
        f.proc_inject = inTemp ? 0.4f : 0.0f;
    }

    // [0] CPU占用: 进程生命周期平均CPU使用率（线程安全，无状态）
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER c, k, u, n;
        c.LowPart  = createTime.dwLowDateTime;
        c.HighPart = createTime.dwHighDateTime;
        k.LowPart  = kernelTime.dwLowDateTime;
        k.HighPart = kernelTime.dwHighDateTime;
        u.LowPart  = userTime.dwLowDateTime;
        u.HighPart = userTime.dwHighDateTime;
        FILETIME nowFt;
        GetSystemTimeAsFileTime(&nowFt);
        n.LowPart  = nowFt.dwLowDateTime;
        n.HighPart = nowFt.dwHighDateTime;

        ULONGLONG processCpuTime = k.QuadPart + u.QuadPart;
        ULONGLONG processWallTime = n.QuadPart - c.QuadPart;

        if (processWallTime > 0) {
            f.cpu_usage = static_cast<float>(
                (static_cast<double>(processCpuTime) / processWallTime) * 100.0);
            if (f.cpu_usage > 100.0f) f.cpu_usage = 100.0f;
        }
    }

    // [1] 内存占用 (WorkingSet MB → 归一化)
    PROCESS_MEMORY_COUNTERS_EX pmc = {};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(hProcess, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        f.memory_usage = static_cast<float>(pmc.WorkingSetSize) / (1024.0f * 1024.0f); // MB
        f.memory_usage = std::min(f.memory_usage / 1024.0f, 1.0f); // 归一化到 0-1 (1024MB=1GB上限)
    }

    // [2] 线程数 (通过 toolhelp 快照)
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(te32);
        float threadCount = 0.0f;
        if (Thread32First(snapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) threadCount += 1.0f;
            } while (Thread32Next(snapshot, &te32));
        }
        CloseHandle(snapshot);
        f.thread_count = std::min(threadCount / 200.0f, 1.0f);
    }

    // [3] 句柄数
    DWORD handleCount = 0;
    if (GetProcessHandleCount(hProcess, &handleCount)) {
        f.handle_count = std::min(static_cast<float>(handleCount) / 10000.0f, 1.0f);
    }

    // [4-7] 文件操作频率由内核 FileMonitor 事件统计填充（此处为零）
    // [8-11] 注册表操作频率由内核 RegistryMonitor 事件统计填充（此处为零）
    // [12-15] 网络特征由内核 NetworkMonitor 事件统计填充（此处为零）

    // [17] DLL注入: 加载了来自临时目录的DLL
    // [18-20] 高级行为特征需EDR级别检测
    // [21-24] 键盘记录/截屏/摄像头/静默安装需行为分析

    // [26] 服务注册: 路径包含服务相关关键词
    f.service_reg = f.auto_start > 0.5f ? 0.7f : 0.0f;

    // [27] 驱动加载: system32\drivers 路径
    std::string pathLower(exePath);
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::tolower);
    f.driver_load = (pathLower.find("\\drivers\\") != std::string::npos) ? 0.9f : 0.0f;

    // [28] 弹窗频率: 暂不可检测，设为0

    CloseHandle(hProcess);
    return f;
}

// ============================================================
// 构造/析构
// ============================================================
SecurityAIEngine::SecurityAIEngine() : initialized_(false) {}

SecurityAIEngine::~SecurityAIEngine() { shutdown(); }

// ============================================================
// 初始化 - 加载INT4量化模型
// ============================================================
bool SecurityAIEngine::initialize(const std::string& model_path) {
    if (initialized_) return true;

    if (!load_quantized_model(model_path)) {
        return false;
    }

    model_path_ = model_path;
    initialized_ = true;
    return true;
}

void SecurityAIEngine::shutdown() {
    initialized_ = false;
    params_ = ModelParams();
}

// ============================================================
// 主推理接口
// ============================================================
SecurityResult SecurityAIEngine::predict(const BehaviorFeature& feature) {
    SecurityResult result;
    result.is_threat = false;
    result.inference_time_us = 0;

    if (!initialized_) return result;
    if (params_.conv1_weight.quant_weights.empty()) return result; // 模型未加载

    auto start = std::chrono::high_resolution_clock::now();

    // 特征向量化
    std::vector<float> input = feature.to_vector();

    // 前向推理
    std::vector<float> logits = forward(input);

    if (logits.empty() || logits.size() < 4) return result;

    // Softmax得到概率
    std::vector<float> probs = AINN::softmax(logits);

    // 找最大概率类别
    int max_idx = 0;
    float max_prob = probs[0];
    for (int i = 1; i < 4; i++) {
        if (probs[i] > max_prob) {
            max_prob = probs[i];
            max_idx = i;
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.inference_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    result.classification = static_cast<SecurityClass>(max_idx);
    result.confidence = max_prob;
    result.probabilities = probs;
    result.is_threat = (max_idx >= 1); // 非正常即为威胁

    return result;
}

std::vector<SecurityResult> SecurityAIEngine::predict_batch(
    const std::vector<BehaviorFeature>& features) {
    std::vector<SecurityResult> results;
    results.reserve(features.size());
    for (const auto& f : features) {
        results.push_back(predict(f));
    }
    return results;
}

// ============================================================
// 加载INT4量化模型
// ============================================================
bool SecurityAIEngine::load_quantized_model(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    // 读取魔数
    char magic[4];
    file.read(magic, 4);
    if (std::memcmp(magic, "SAIQ", 4) != 0) return false;

    // 读取版本
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), 4);
    if (version != 1) return false;

    // 读取层数
    uint32_t num_layers;
    file.read(reinterpret_cast<char*>(&num_layers), 4);

    // 逐层读取
    for (uint32_t i = 0; i < num_layers; i++) {
        // 层名
        uint32_t name_len;
        file.read(reinterpret_cast<char*>(&name_len), 4);
        std::string name(name_len, '\0');
        file.read(&name[0], name_len);

        // 形状
        uint32_t shape_dims;
        file.read(reinterpret_cast<char*>(&shape_dims), 4);
        std::vector<int> shape(shape_dims);
        for (auto& s : shape) {
            uint32_t dim;
            file.read(reinterpret_cast<char*>(&dim), 4);
            s = static_cast<int>(dim);
        }

        // 判断是否为量化层
        if (shape_dims > 0) {
            // 量化层
            uint32_t num_groups;
            file.read(reinterpret_cast<char*>(&num_groups), 4);

            QuantizedLayer layer;
            layer.original_shape = shape;
            layer.group_size = 16;

            // scales
            layer.scales.resize(num_groups);
            file.read(reinterpret_cast<char*>(layer.scales.data()),
                      num_groups * sizeof(float));

            // zero_points
            layer.zero_points.resize(num_groups);
            file.read(reinterpret_cast<char*>(layer.zero_points.data()),
                      num_groups * sizeof(float));

            // 量化权重
            uint32_t packed_size;
            file.read(reinterpret_cast<char*>(&packed_size), 4);
            layer.quant_weights.resize(packed_size);
            file.read(reinterpret_cast<char*>(layer.quant_weights.data()), packed_size);

            {
                // 验证 packed_size 与 shape 的一致性
                int total_elems = 1;
                for (auto s : shape) total_elems *= s;
                int expected_packed = (total_elems + 1) / 2;
                if (packed_size != static_cast<uint32_t>(expected_packed)) {
                    file.close();
                    return false;
                }
            }

            // 根据层名分配到模型参数
            if (name.find("conv1") != std::string::npos && name.find("weight") != std::string::npos)
                params_.conv1_weight = layer;
            else if (name.find("conv2") != std::string::npos && name.find("weight") != std::string::npos)
                params_.conv2_weight = layer;
            else if (name.find("fc1") != std::string::npos && name.find("weight") != std::string::npos)
                params_.fc1_weight = layer;
            else if (name.find("fc2") != std::string::npos && name.find("weight") != std::string::npos)
                params_.fc2_weight = layer;
        } else {
            // 非量化层 (bias, BN参数等)
            uint32_t tensor_size;
            file.read(reinterpret_cast<char*>(&tensor_size), 4);
            std::vector<float> tensor(tensor_size);
            file.read(reinterpret_cast<char*>(tensor.data()),
                      tensor_size * sizeof(float));

            if (name.find("conv1.bias") != std::string::npos)
                params_.conv1_bias = tensor;
            else if (name.find("conv2.bias") != std::string::npos)
                params_.conv2_bias = tensor;
            else if (name.find("fc1.bias") != std::string::npos)
                params_.fc1_bias = tensor;
            else if (name.find("fc2.bias") != std::string::npos)
                params_.fc2_bias = tensor;
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
            }
        }
    }

    file.close();
    return true;
}

// ============================================================
// INT4反量化
// ============================================================
std::vector<float> SecurityAIEngine::dequantize(const QuantizedLayer& layer) {
    int total_elements = 1;
    for (auto s : layer.original_shape) total_elements *= s;

    std::vector<float> result(total_elements, 0.0f);

    int group_size = layer.group_size;
    int num_groups = static_cast<int>(layer.scales.size());

    // 防御: 检查有无有效数据
    if (num_groups == 0 || layer.quant_weights.empty()) return result;

    int packed_bytes = static_cast<int>(layer.quant_weights.size());
    int required_bytes = (total_elements + 1) / 2;
    if (packed_bytes < required_bytes) return result; // 数据不足

    int idx = 0;
    for (int g = 0; g < num_groups && idx < total_elements; g++) {
        for (int j = 0; j < group_size && idx < total_elements; j++, idx++) {
            int byte_idx = idx / 2;
            if (byte_idx >= packed_bytes) return result; // 越界保护

            bool is_high = (idx % 2 == 1);
            uint8_t packed = layer.quant_weights[byte_idx];
            uint8_t qval = is_high ? (packed >> 4) : (packed & 0x0F);

            float scale = (g < num_groups) ? layer.scales[g] : 1.0f;
            float zp = (g < static_cast<int>(layer.zero_points.size()))
                           ? layer.zero_points[g] : 0.0f;
            result[idx] = static_cast<float>(qval) * scale + zp;
        }
    }

    return result;
}

// ============================================================
// 前向推理
// ============================================================
std::vector<float> SecurityAIEngine::forward(const std::vector<float>& input) {
    // 输入: (1, 32) -> reshape为 (1, 1, 32)
    // 卷积层1: Conv1d(1, 16, 3) + BN + ReLU
    auto w1 = dequantize(params_.conv1_weight);
    auto x = AINN::conv1d(input, w1, params_.conv1_bias, 1, 16, 3);
    x = AINN::batch_norm(x, params_.bn1_gamma, params_.bn1_beta, params_.bn1_mean, params_.bn1_var);
    x = AINN::relu(x);

    // 卷积层2: Conv1d(16, 32, 3) + BN + ReLU
    auto w2 = dequantize(params_.conv2_weight);
    x = AINN::conv1d(x, w2, params_.conv2_bias, 16, 32, 3);
    x = AINN::batch_norm(x, params_.bn2_gamma, params_.bn2_beta, params_.bn2_mean, params_.bn2_var);
    x = AINN::relu(x);

    // 池化: MaxPool1d(2), 输入(32, 32) → 输出(32, 16)
    x = AINN::max_pool1d(x, 32, 2);

    // 全连接层1: (512 -> 64) + ReLU + Dropout(推理时跳过)
    auto w3 = dequantize(params_.fc1_weight);
    x = AINN::linear(x, w3, params_.fc1_bias);
    x = AINN::relu(x);

    // 输出层: (64 -> 4)
    auto w4 = dequantize(params_.fc2_weight);
    x = AINN::linear(x, w4, params_.fc2_bias);

    return x; // 4维logits
}

#if 0 // 以下算子已统一提取至 AI_Common/include/nn_ops.h
std::vector<float> SecurityAIEngine::conv1d(
    const std::vector<float>& input,
    const std::vector<float>& weight,
    const std::vector<float>& bias,
    int in_channels, int out_channels, int kernel_size) {

    int input_len = static_cast<int>(input.size()) / in_channels;
    int output_len = input_len; // padding=1, stride=1
    std::vector<float> output(out_channels * output_len, 0.0f);

    for (int oc = 0; oc < out_channels; oc++) {
        for (int i = 0; i < output_len; i++) {
            float sum = bias[oc];
            for (int ic = 0; ic < in_channels; ic++) {
                for (int k = 0; k < kernel_size; k++) {
                    int input_idx = i + k - kernel_size / 2;
                    if (input_idx >= 0 && input_idx < input_len) {
                        int w_idx = oc * in_channels * kernel_size + ic * kernel_size + k;
                        sum += input[ic * input_len + input_idx] * weight[w_idx];
                    }
                }
            }
            output[oc * output_len + i] = sum;
        }
    }

    return output;
}

std::vector<float> SecurityAIEngine::batch_norm(
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

std::vector<float> SecurityAIEngine::max_pool1d(
    const std::vector<float>& input, int channels, int kernel_size) {
    // input layout: (channels, spatial) interleaved as [c0_s0, c0_s1, ..., c1_s0, c1_s1, ...]
    int spatial = static_cast<int>(input.size()) / channels;
    int output_spatial = spatial / kernel_size;
    std::vector<float> output(channels * output_spatial);

    for (int c = 0; c < channels; c++) {
        int c_offset = c * spatial;
        int out_offset = c * output_spatial;
        for (int i = 0; i < output_spatial; i++) {
            float max_val = -1e30f;
            for (int k = 0; k < kernel_size; k++) {
                float val = input[c_offset + i * kernel_size + k];
                if (val > max_val) max_val = val;
            }
            output[out_offset + i] = max_val;
        }
    }
    return output;
}

std::vector<float> SecurityAIEngine::linear(
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

std::vector<float> SecurityAIEngine::relu(const std::vector<float>& x) {
    std::vector<float> result(x.size());
    for (size_t i = 0; i < x.size(); i++) {
        result[i] = std::max(0.0f, x[i]);
    }
    return result;
}

std::vector<float> SecurityAIEngine::softmax(const std::vector<float>& x) {
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

} // namespace SecurityAI
