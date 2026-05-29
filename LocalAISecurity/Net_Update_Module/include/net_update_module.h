/**
 * @file net_update_module.h
 * @brief 双模联网升级模块 - 头文件
 * 仅下行联网，禁止任何数据上传
 * 支持离线模式 + 授权模式
 */

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace NetUpdate {

// ============================================================
// 升级内容类型
// ============================================================
enum class UpdateType : int {
    SECURITY_MODEL = 1,      // AI安全模型增量补丁
    CLEAN_MODEL = 2,         // AI C盘分类模型增量补丁
    JUNK_SIGNATURES = 3,     // 系统垃圾最新特征库
    VIRUS_SIGNATURES = 4     // 病毒行为特征库
};

// ============================================================
// 升级状态
// ============================================================
enum class UpdateStatus : int {
    IDLE = 0,
    CHECKING = 1,
    DOWNLOADING = 2,
    VERIFYING = 3,
    APPLYING = 4,
    COMPLETED = 5,
    FAILED = 6,
    ROLLED_BACK = 7          // 回滚成功
};

struct UpdateInfo {
    UpdateType type;
    std::string version;        // 新版本号
    std::string description;    // 更新描述
    uint64_t size_bytes;        // 文件大小
    std::string download_url;   // 下载地址(仅下行)
    std::string hash;           // SHA256校验哈希
};

struct UpdateProgress {
    UpdateStatus status;
    uint64_t downloaded_bytes;
    uint64_t total_bytes;
    float percent;
    std::string current_file;
};

using ProgressCallback = std::function<void(const UpdateProgress&)>;

// ============================================================
// 联网升级管理器
// ============================================================
class UpdateManager {
public:
    UpdateManager();
    ~UpdateManager();

    /** 初始化 */
    bool initialize(const std::string& data_dir);

    /** 设置网络模式 */
    void set_network_enabled(bool enabled);
    bool is_network_enabled() const { return network_enabled_; }

    /** 手动检查更新 */
    std::vector<UpdateInfo> check_for_updates();

    /** 执行更新（单向下行下载） */
    bool execute_update(UpdateType type, const std::string& url,
                        const std::string& expected_hash,
                        ProgressCallback callback = nullptr);

    /** 静默后台更新（空闲时自动执行） */
    void start_silent_update();
    void stop_silent_update();

    /** 获取当前版本信息 */
    std::string get_current_version() const;

    /** 获取上次更新时间 */
    uint64_t get_last_update_time() const;

    /** 回滚到上一版本（更新失败时自动触发） */
    bool rollback(UpdateType type);

    /** 设置进度回调 */
    void set_progress_callback(ProgressCallback callback) { progress_cb_ = callback; }

private:
    bool initialized_;
    bool network_enabled_;
    std::string data_dir_;
    ProgressCallback progress_cb_;
    bool silent_running_;

    // 内部方法
    std::string get_version_path(UpdateType type) const;
    std::string get_backup_path(UpdateType type) const;
    bool verify_hash(const std::string& file_path, const std::string& expected_hash);
    std::string compute_sha256(const std::string& file_path) const;
    bool backup_current(UpdateType type);
    bool apply_patch(UpdateType type, const std::string& patch_path);
};

} // namespace NetUpdate
