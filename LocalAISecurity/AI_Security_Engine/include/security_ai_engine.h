/**
 * @file security_ai_engine.h
 * @brief AI安全行为识别推理引擎 - 头文件
 * 纯CPU推理，INT4量化模型，5-10ms单次推理
 */

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

namespace SecurityAI {

// ============================================================
// 数据结构定义
// ============================================================

/** 32维进程行为特征向量 */
struct BehaviorFeature {
    float cpu_usage;          // [0]   CPU占用率 (%)
    float memory_usage;       // [1]   内存占用率 (MB)
    float thread_count;       // [2]   线程数
    float handle_count;       // [3]   句柄数
    float file_create_rate;   // [4]   文件创建频率 (次/秒)
    float file_modify_rate;   // [5]   文件修改频率 (次/秒)
    float file_delete_rate;   // [6]   文件删除频率 (次/秒)
    float file_rename_rate;   // [7]   文件重命名频率 (次/秒)
    float reg_read_rate;      // [8]   注册表读取频率 (次/秒)
    float reg_write_rate;     // [9]   注册表写入频率 (次/秒)
    float reg_delete_rate;    // [10]  注册表删除频率 (次/秒)
    float reg_monitor_rate;   // [11]  注册表监控频率 (次/秒)
    float net_conn_rate;      // [12]  网络连接频率 (次/秒)
    float net_send_bytes;     // [13]  网络发送字节数 (B/s)
    float net_recv_bytes;     // [14]  网络接收字节数 (B/s)
    float abnormal_ports;     // [15]  异常端口连接数
    float proc_inject;        // [16]  进程注入行为 (0-1概率)
    float dll_inject;         // [17]  DLL注入行为 (0-1概率)
    float proc_hide;          // [18]  进程隐藏行为 (0-1概率)
    float proc_revive;        // [19]  进程复活行为 (0-1概率)
    float batch_encrypt;      // [20]  批量文件加密行为 (0-1概率)
    float keylog;             // [21]  键盘记录行为 (0-1概率)
    float screenshot;         // [22]  截屏行为 (0-1概率)
    float camera_access;      // [23]  摄像头访问行为 (0-1概率)
    float silent_install;     // [24]  静默安装行为 (0-1概率)
    float auto_start;         // [25]  后台自启动 (0-1概率)
    float service_reg;        // [26]  服务注册行为 (0-1概率)
    float driver_load;        // [27]  驱动加载行为 (0-1概率)
    float popup_freq;         // [28]  弹窗频率 (次/分钟)
    float deceptive_click;    // [29]  诱导点击行为 (0-1概率)
    float browser_hijack;     // [30]  浏览器劫持行为 (0-1概率)
    float privilege_escalate; // [31]  权限提升行为 (0-1概率)

    /** 转换为32维float数组用于模型输入 */
    std::vector<float> to_vector() const {
        return {
            cpu_usage, memory_usage, thread_count, handle_count,
            file_create_rate, file_modify_rate, file_delete_rate, file_rename_rate,
            reg_read_rate, reg_write_rate, reg_delete_rate, reg_monitor_rate,
            net_conn_rate, net_send_bytes, net_recv_bytes, abnormal_ports,
            proc_inject, dll_inject, proc_hide, proc_revive,
            batch_encrypt, keylog, screenshot, camera_access,
            silent_install, auto_start, service_reg, driver_load,
            popup_freq, deceptive_click, browser_hijack, privilege_escalate
        };
    }
};

/** 安全分类结果 */
enum class SecurityClass : int {
    NORMAL = 0,              // 正常程序
    SUSPICIOUS = 1,          // 可疑流氓行为
    HIGH_RISK = 2,           // 高危木马/注入行为
    RANSOMWARE = 3           // 勒索病毒加密行为
};

struct SecurityResult {
    SecurityClass classification;
    float confidence;        // 置信度 0.0-1.0
    std::vector<float> probabilities; // 各类别概率
    uint64_t inference_time_us;       // 推理耗时(微秒)
    bool is_threat;                  // 是否判定为威胁
};

// ============================================================
// INT4量化层定义
// ============================================================
struct QuantizedLayer {
    std::vector<uint8_t> quant_weights;  // 4bit打包权重
    std::vector<float> scales;           // 缩放因子
    std::vector<float> zero_points;      // 零点
    std::vector<int> original_shape;     // 原始形状
    int group_size = 16;
};

// ============================================================
// 核心引擎类
// ============================================================
class SecurityAIEngine {
public:
    SecurityAIEngine();
    ~SecurityAIEngine();

    /** 初始化引擎，加载INT4量化模型 */
    bool initialize(const std::string& model_path);

    /** 执行安全行为推理（主接口） */
    SecurityResult predict(const BehaviorFeature& feature);

    /** 批量推理（支持多进程同时分析） */
    std::vector<SecurityResult> predict_batch(
        const std::vector<BehaviorFeature>& features);

    /** 从Windows进程快照提取32维行为特征（静态方法，无需初始化引擎） */
    static BehaviorFeature extract_features(uint32_t pid);

    /** 获取引擎状态信息 */
    bool is_initialized() const { return initialized_; }

    /** 释放资源 */
    void shutdown();

private:
    bool initialized_;
    std::string model_path_;

    // 模型参数（INT4量化）
    struct ModelParams {
        // 卷积层1
        QuantizedLayer conv1_weight;
        std::vector<float> conv1_bias;
        std::vector<float> bn1_gamma, bn1_beta, bn1_mean, bn1_var;

        // 卷积层2
        QuantizedLayer conv2_weight;
        std::vector<float> conv2_bias;
        std::vector<float> bn2_gamma, bn2_beta, bn2_mean, bn2_var;

        // 全连接层1
        QuantizedLayer fc1_weight;
        std::vector<float> fc1_bias;

        // 输出层
        QuantizedLayer fc2_weight;
        std::vector<float> fc2_bias;
    } params_;

    // 内部方法
    bool load_quantized_model(const std::string& path);
    std::vector<float> dequantize(const QuantizedLayer& layer);
    std::vector<float> forward(const std::vector<float>& input);
};

} // namespace SecurityAI
