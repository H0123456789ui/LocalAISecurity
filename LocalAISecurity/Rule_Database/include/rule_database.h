/**
 * @file rule_database.h
 * @brief 规则数据库 - 头文件
 * 系统白名单 + 安全规则库 + 垃圾特征库
 * 本地存储，纯文件数据库，无第三方依赖
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <cstdint>

namespace RuleDatabase {

// ============================================================
// 白名单条目
// ============================================================
struct WhitelistEntry {
    std::string path;           // 文件/目录路径(小写)
    std::string hash;           // SHA256哈希
    std::string description;    // 描述
    int trust_level;            // 信任级别 (0-100)
    bool is_system_critical;    // 是否系统关键文件
};

// ============================================================
// 安全规则
// ============================================================
struct SecurityRule {
    std::string rule_id;        // 规则ID
    std::string name;           // 规则名称
    std::string description;    // 规则描述
    int severity;               // 严重级别 (1-5)
    std::string target_type;    // 目标类型: process/registry/file/network
    std::string pattern;        // 匹配模式(路径/键名/端口等)
    std::string action;         // 处置动作: block/warn/allow
};

// ============================================================
// 垃圾特征
// ============================================================
struct JunkSignature {
    std::string path_pattern;   // 路径匹配模式(支持通配符)
    std::string extension;      // 文件扩展名
    std::string category;       // 分类: temp/cache/log/update/driver/thumbnail
    int risk_level;             // 删除风险级别 (0=安全, 1=低风险, 2=需确认)
    std::string description;    // 描述
    int64_t max_age_days;       // 最大安全保留天数(超过可删)
};

// ============================================================
// 规则数据库管理器
// ============================================================
class RuleDBManager {
public:
    RuleDBManager();
    ~RuleDBManager();

    /** 初始化，加载所有规则文件 */
    bool initialize(const std::string& db_path);

    // ---- 白名单操作 ----
    bool is_whitelisted(const std::string& path) const;
    bool is_system_critical(const std::string& path) const;
    const WhitelistEntry* get_whitelist_entry(const std::string& path) const;

    // ---- 安全规则操作 ----
    const SecurityRule* match_security_rule(
        const std::string& target_type,
        const std::string& target) const;
    std::vector<SecurityRule> get_all_security_rules() const;

    // ---- 垃圾特征操作 ----
    const JunkSignature* match_junk_signature(const std::string& path) const;
    std::vector<JunkSignature> get_junk_by_category(const std::string& category) const;
    bool is_junk_extension(const std::string& extension) const;

    // ---- 更新操作 ----
    /** 增量更新白名单 */
    bool update_whitelist(const std::vector<WhitelistEntry>& entries);

    /** 增量更新安全规则 */
    bool update_security_rules(const std::vector<SecurityRule>& rules);

    /** 增量更新垃圾特征库 */
    bool update_junk_signatures(const std::vector<JunkSignature>& signatures);

    /** 保存所有数据到磁盘 */
    bool save_all();

    bool is_initialized() const { return initialized_; }

private:
    bool initialized_;
    std::string db_path_;

    // 白名单 (路径小写 -> 条目)
    std::unordered_map<std::string, WhitelistEntry> whitelist_;

    // 安全规则 (规则ID -> 规则)
    std::unordered_map<std::string, SecurityRule> security_rules_;

    // 垃圾特征库
    std::vector<JunkSignature> junk_signatures_;

    // 可删扩展名集合
    std::unordered_set<std::string> junk_extensions_;

    // 加载方法
    bool load_whitelist(const std::string& path);
    bool load_security_rules(const std::string& path);
    bool load_junk_signatures(const std::string& path);

    // 保存方法
    bool save_whitelist(const std::string& path);
    bool save_security_rules(const std::string& path);
    bool save_junk_signatures(const std::string& path);

    // 默认数据创建
    bool create_default_whitelist(const std::string& path);
    bool create_default_security_rules(const std::string& path);
    bool create_default_junk_signatures(const std::string& path);

    mutable std::mutex mtx_;
};

} // namespace RuleDatabase
