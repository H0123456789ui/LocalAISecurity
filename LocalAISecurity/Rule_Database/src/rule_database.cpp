/**
 * @file rule_database.cpp
 * @brief 规则数据库 - 实现
 * 纯文件数据库，JSON格式存储，无第三方依赖
 */

#include "rule_database.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <windows.h>
#include <shlobj.h>

// 简易JSON解析（无第三方依赖，控制体积）
// 实际生产可替换为轻量JSON库如nlohmann/json（MIT协议）

namespace RuleDatabase {

// ============================================================
// 简易CSV/INI格式解析（替代JSON，更轻量）
// ============================================================
static std::vector<std::string> split_line(const std::string& line, char delim) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string token;
    while (std::getline(iss, token, delim)) {
        tokens.push_back(token);
    }
    return tokens;
}

static std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// ============================================================
// 构造/析构
// ============================================================
RuleDBManager::RuleDBManager() : initialized_(false) {}
RuleDBManager::~RuleDBManager() = default;

// ============================================================
// 初始化
// ============================================================
bool RuleDBManager::initialize(const std::string& db_path) {
    db_path_ = db_path;

    bool success = true;
    success &= load_whitelist(db_path + "/whitelist.dat");
    success &= load_security_rules(db_path + "/security_rules.dat");
    success &= load_junk_signatures(db_path + "/junk_signatures.dat");

    initialized_ = success;
    return success;
}

// ============================================================
// 白名单操作
// ============================================================
bool RuleDBManager::is_whitelisted(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string lower_path = to_lower(path);
    return whitelist_.find(lower_path) != whitelist_.end();
}

bool RuleDBManager::is_system_critical(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::string lower_path = to_lower(path);
    auto it = whitelist_.find(lower_path);
    if (it != whitelist_.end()) {
        return it->second.is_system_critical;
    }
    return false;
}

const WhitelistEntry* RuleDBManager::get_whitelist_entry(const std::string& path) const {
    auto it = whitelist_.find(to_lower(path));
    return it != whitelist_.end() ? &it->second : nullptr;
}

// ============================================================
// 路径分段匹配 — 按路径分隔符匹配，避免子串误匹配
// ============================================================
static bool path_match(const std::string& path, const std::string& pattern) {
    std::string p = to_lower(path);
    std::string pat = to_lower(pattern);

    auto split = [](const std::string& s) -> std::vector<std::string> {
        std::vector<std::string> parts;
        std::istringstream iss(s);
        std::string token;
        while (std::getline(iss, token, '\\')) {
            if (!token.empty()) parts.push_back(token);
        }
        return parts;
    };

    auto segments = split(p);
    auto pat_segments = split(pat);

    if (pat_segments.empty()) return false;

    // 在路径的所有偏移位置尝试匹配模式
    size_t max_start = (segments.size() >= pat_segments.size())
                       ? segments.size() - pat_segments.size() : 0;

    for (size_t start = 0; start <= max_start; start++) {
        bool matched = true;
        for (size_t i = 0; i < pat_segments.size(); i++) {
            const auto& pat_seg = pat_segments[i];
            const auto& path_seg = segments[start + i];
            // * 通配符匹配任意段
            if (pat_seg == "*" || pat_seg == "**") continue;
            // 精确匹配（含尾部匹配：pattern 是路径段的前缀不匹配，
            // 但路径段包含 pattern 作为子串时仅在相等时才算匹配）
            if (path_seg != pat_seg) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }

    // 回退：如果模式没有反斜杠分隔符，做精确 token 匹配
    if (pat.find('\\') == std::string::npos) {
        for (const auto& seg : segments) {
            if (seg == pat) return true;
        }
    }

    return false;
}

// ============================================================
// 安全规则操作
// ============================================================
const SecurityRule* RuleDBManager::match_security_rule(
    const std::string& target_type,
    const std::string& target) const {

    for (const auto& [id, rule] : security_rules_) {
        if (rule.target_type == target_type) {
            if (path_match(target, rule.pattern)) {
                return &rule;
            }
        }
    }
    return nullptr;
}

std::vector<SecurityRule> RuleDBManager::get_all_security_rules() const {
    std::vector<SecurityRule> result;
    for (const auto& [id, rule] : security_rules_) {
        result.push_back(rule);
    }
    return result;
}

// ============================================================
// 垃圾特征操作
// ============================================================
const JunkSignature* RuleDBManager::match_junk_signature(const std::string& path) const {
    for (const auto& sig : junk_signatures_) {
        if (!sig.path_pattern.empty() && path_match(path, sig.path_pattern)) {
            return &sig;
        }
    }

    // 检查扩展名
    size_t dot_pos = path.rfind('.');
    if (dot_pos != std::string::npos) {
        std::string ext = to_lower(path.substr(dot_pos));
        if (junk_extensions_.find(ext) != junk_extensions_.end()) {
            // 返回通用垃圾特征
            for (const auto& sig : junk_signatures_) {
                if (sig.extension == ext) return &sig;
            }
        }
    }

    return nullptr;
}

std::vector<JunkSignature> RuleDBManager::get_junk_by_category(const std::string& category) const {
    std::vector<JunkSignature> result;
    for (const auto& sig : junk_signatures_) {
        if (sig.category == category) {
            result.push_back(sig);
        }
    }
    return result;
}

bool RuleDBManager::is_junk_extension(const std::string& extension) const {
    return junk_extensions_.find(to_lower(extension)) != junk_extensions_.end();
}

// ============================================================
// 更新操作
// ============================================================
bool RuleDBManager::update_whitelist(const std::vector<WhitelistEntry>& entries) {
    for (const auto& entry : entries) {
        whitelist_[to_lower(entry.path)] = entry;
    }
    return save_whitelist(db_path_ + "/whitelist.dat");
}

bool RuleDBManager::update_security_rules(const std::vector<SecurityRule>& rules) {
    for (const auto& rule : rules) {
        security_rules_[rule.rule_id] = rule;
    }
    return save_security_rules(db_path_ + "/security_rules.dat");
}

bool RuleDBManager::update_junk_signatures(const std::vector<JunkSignature>& signatures) {
    for (const auto& sig : signatures) {
        junk_signatures_.push_back(sig);
        if (!sig.extension.empty()) {
            junk_extensions_.insert(to_lower(sig.extension));
        }
    }
    return save_junk_signatures(db_path_ + "/junk_signatures.dat");
}

bool RuleDBManager::save_all() {
    bool success = true;
    success &= save_whitelist(db_path_ + "/whitelist.dat");
    success &= save_security_rules(db_path_ + "/security_rules.dat");
    success &= save_junk_signatures(db_path_ + "/junk_signatures.dat");
    return success;
}

// ============================================================
// 加载方法 - CSV格式（轻量、快速）
// ============================================================
bool RuleDBManager::load_whitelist(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        // 首次运行，创建默认白名单
        return create_default_whitelist(path);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        auto tokens = split_line(line, '|');
        if (tokens.size() >= 5) {
            WhitelistEntry entry;
            entry.path = to_lower(tokens[0]);
            entry.hash = tokens[1];
            entry.description = tokens[2];
            entry.trust_level = std::stoi(tokens[3]);
            entry.is_system_critical = (tokens[4] == "1");
            whitelist_[entry.path] = entry;
        }
    }

    file.close();
    return true;
}

bool RuleDBManager::load_security_rules(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return create_default_security_rules(path);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        auto tokens = split_line(line, '|');
        if (tokens.size() >= 7) {
            SecurityRule rule;
            rule.rule_id = tokens[0];
            rule.name = tokens[1];
            rule.description = tokens[2];
            rule.severity = std::stoi(tokens[3]);
            rule.target_type = tokens[4];
            rule.pattern = tokens[5];
            rule.action = tokens[6];
            security_rules_[rule.rule_id] = rule;
        }
    }

    file.close();
    return true;
}

bool RuleDBManager::load_junk_signatures(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return create_default_junk_signatures(path);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        auto tokens = split_line(line, '|');
        if (tokens.size() >= 6) {
            JunkSignature sig;
            sig.path_pattern = tokens[0];
            sig.extension = to_lower(tokens[1]);
            sig.category = tokens[2];
            sig.risk_level = std::stoi(tokens[3]);
            sig.description = tokens[4];
            sig.max_age_days = std::stoll(tokens[5]);
            junk_signatures_.push_back(sig);

            if (!sig.extension.empty()) {
                junk_extensions_.insert(to_lower(sig.extension));
            }
        }
    }

    file.close();
    return true;
}

// ============================================================
// 保存方法
// ============================================================
bool RuleDBManager::save_whitelist(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# path|hash|description|trust_level|is_system_critical\n";
    for (const auto& [key, entry] : whitelist_) {
        file << entry.path << "|"
             << entry.hash << "|"
             << entry.description << "|"
             << entry.trust_level << "|"
             << (entry.is_system_critical ? "1" : "0") << "\n";
    }

    file.close();
    return true;
}

bool RuleDBManager::save_security_rules(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# rule_id|name|description|severity|target_type|pattern|action\n";
    for (const auto& [id, rule] : security_rules_) {
        file << rule.rule_id << "|"
             << rule.name << "|"
             << rule.description << "|"
             << rule.severity << "|"
             << rule.target_type << "|"
             << rule.pattern << "|"
             << rule.action << "\n";
    }

    file.close();
    return true;
}

bool RuleDBManager::save_junk_signatures(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# path_pattern|extension|category|risk_level|description|max_age_days\n";
    for (const auto& sig : junk_signatures_) {
        file << sig.path_pattern << "|"
             << sig.extension << "|"
             << sig.category << "|"
             << sig.risk_level << "|"
             << sig.description << "|"
             << sig.max_age_days << "\n";
    }

    file.close();
    return true;
}

// ============================================================
// 默认数据创建
// ============================================================
bool RuleDBManager::create_default_whitelist(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# Windows系统核心文件白名单\n";
    file << "# path|hash|description|trust_level|is_system_critical\n";

    // 动态获取系统路径
    WCHAR winDir[MAX_PATH] = {}, sysDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    GetSystemDirectoryW(sysDir, MAX_PATH);
    char winDirA[MAX_PATH] = {}, sysDirA[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, winDir, -1, winDirA, MAX_PATH, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, sysDir, -1, sysDirA, MAX_PATH, nullptr, nullptr);
    std::string windir(winDirA), sysdir(sysDirA);
    for (auto& c : windir) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    for (auto& c : sysdir) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));

    // Windows核心系统文件 — 路径动态生成
    struct SysEntry { const char* rel; const char* desc; };
    const SysEntry entries[] = {
        {"\\ntdll.dll", "Windows NT核心库"},
        {"\\kernel32.dll", "Windows内核API"},
        {"\\user32.dll", "Windows用户界面"},
        {"\\advapi32.dll", "Windows高级API"},
        {"\\gdi32.dll", "Windows图形设备接口"},
        {"\\shell32.dll", "Windows Shell"},
        {"\\msvcrt.dll", "C运行时库"},
        {"\\ole32.dll", "OLE库"},
        {"\\oleaut32.dll", "OLE自动化"},
        {"\\winsock.dll", "Windows套接字"},
        {"\\ws2_32.dll", "Windows套接字2"},
        {"\\crypt32.dll", "加密API"},
        {"\\wintrust.dll", "信任验证"},
        {"\\svchost.exe", "服务宿主进程"},
        {"\\lsass.exe", "本地安全认证"},
        {"\\csrss.exe", "客户端/服务器运行时"},
        {"\\services.exe", "服务控制管理器"},
        {"\\winlogon.exe", "Windows登录"},
        {"\\smss.exe", "会话管理器"},
        {"\\dwm.exe", "桌面窗口管理器"},
        {"\\taskhostw.exe", "任务宿主"},
    };

    for (const auto& e : entries) {
        std::string full = sysdir + e.rel;
        file << full << "||" << e.desc << "|100|1\n";
    }

    // 目录级别白名单
    file << sysdir << "\\drivers\\||系统驱动目录|100|1\n";
    file << sysdir << "\\config\\||注册表配置|100|1\n";
    file << windir << "\\explorer.exe||Windows资源管理器|100|1\n";

    file.close();
    return load_whitelist(path);
}

bool RuleDBManager::create_default_security_rules(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# rule_id|name|description|severity|target_type|pattern|action\n";

    const char* rules[] = {
        // 高危 - 立即拦截
        "SR001|自启动项注入|检测注册表自启动项被恶意修改|5|registry|\\Run\\|block",
        "SR002|系统服务篡改|检测系统服务被非法修改|5|registry|\\Services\\|block",
        "SR003|可疑进程注入|检测跨进程内存写入/CreateRemoteThread|4|process|inject|block",
        "SR004|批量文件加密|检测勒索病毒批量修改文件扩展名|5|process|encrypt|block",
        "SR005|异常端口外连|检测已知C2/矿池端口连接|4|network|connect|block",
        "SR006|可疑驱动加载|检测非签名驱动加载行为|4|process|driver|warn",
        "SR007|键盘记录行为|检测SetWindowsHookEx/GetAsyncKeyState滥用|5|process|keylog|block",
        "SR008|截屏行为|检测高频GDI截屏调用|3|process|screenshot|warn",
        "SR009|静默安装|检测后台静默安装软件包行为|3|process|install|warn",
        "SR010|浏览器劫持|检测浏览器主页/搜索引擎注册表篡改|4|registry|browser|block",
        "SR011|DNS劫持|检测hosts文件/网络配置篡改|4|network|dns|block",
        "SR012|凭证窃取|检测lsass.exe内存读取/mimikatz行为|5|process|credential|block",
        "SR013|Powershell混淆|检测base64编码/无文件攻击|4|process|powershell|block",
        "SR014|计划任务持久化|检测schtasks非法注册计划任务|4|registry|\\Schedule\\|warn",
        "SR015|WMI持久化|检测WMI事件订阅后门|4|registry|\\WBEM\\|warn",
        "SR016|AppInit_DLLs劫持|检测AppInit_DLLs注册表键值|5|registry|\\AppInit_DLLs\\|block",
        "SR017|IFEO映像劫持|检测Image File Execution Options劫持|5|registry|\\IFEO\\|block",
        "SR018|浏览器扩展恶意|检测恶意浏览器插件注册|3|registry|\\Extensions\\|warn",
        "SR019|RDP配置篡改|检测远程桌面fDenyTSConnections被修改|3|registry|\\Terminal Server\\|warn",
        "SR020|UAC绕过|检测注册表EnableLUA/PromptOnSecureDesktop被修改|4|registry|\\EnableLUA\\|warn",
    };

    for (auto rule : rules) {
        file << rule << "\n";
    }

    file.close();
    return load_security_rules(path);
}

bool RuleDBManager::create_default_junk_signatures(const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "# path_pattern|extension|category|risk_level|description|max_age_days\n";

    const char* signatures[] = {
        // 临时文件
        "\\temp\\|.tmp|temp|0|临时文件|1",
        "\\tmp\\|.tmp|temp|0|临时文件|1",
        "\\temp\\|.temp|temp|0|临时文件|1",
        "\\temp\\|.bak|temp|0|临时备份|7",
        // 日志文件
        "\\logs\\|.log|log|0|应用日志|30",
        "\\log\\|.log|log|0|应用日志|30",
        "\\windows\\logs\\|.log|log|0|系统日志|60",
        "\\windows\\debug\\|.log|log|0|调试日志|30",
        // 缓存文件
        "\\cache\\||cache|0|应用缓存|7",
        "\\cachedata\\||cache|0|缓存数据|7",
        "\\windows\\temp\\||temp|0|Windows临时目录|1",
        // 缩略图缓存
        "\\thumbcache_||thumbnail|0|缩略图缓存|30",
        "\\iconcache_||thumbnail|0|图标缓存|30",
        // Windows Update残留
        "\\windows\\softwaredistribution\\download\\||update|0|更新下载缓存|30",
        "\\windows\\installer\\$patchcache$\\||update|1|更新补丁缓存|90",
        // 浏览器缓存
        "\\google\\chrome\\user data\\default\\cache\\||cache|0|Chrome缓存|7",
        "\\mozilla\\firefox\\profiles\\||cache|0|Firefox缓存|7",
        "\\microsoftedge\\user data\\default\\cache\\||cache|0|Edge缓存|7",
        // 微信/QQ缓存
        "\\wechat\\files\\||cache|1|微信缓存|30",
        "\\tencent\\qq\\||cache|1|QQ缓存|30",
        // 过期驱动
        "\\windows\\system32\\driverstore\\filerepository\\||driver|1|驱动存储|180",
        // 更多常见垃圾路径
        "\\recent\\||cache|0|最近文档快捷方式|7",
        "\\prefetch\\|.pf|prefetch|1|预读取文件|30",
        "\\crashdumps\\|.dmp|crash|0|崩溃转储|7",
        "\\wer\\||crash|0|Windows错误报告|14",
        "\\downloads\\||downloads|1|下载目录|30",
        "\\download\\||downloads|1|下载目录|30",
        "\\desktop\\.||desktop|1|桌面临时文件|7",
        "\\appdata\\local\\discord\\cache\\||cache|0|Discord缓存|7",
        "\\appdata\\local\\spotify\\||cache|0|Spotify缓存|7",
        "\\appdata\\roaming\\telegram desktop\\||cache|0|Telegram缓存|14",
        "\\appdata\\local\\nvidia\\||cache|1|NVIDIA驱动缓存|30",
        "\\appdata\\roaming\\baidu\\||cache|1|百度系缓存|30",
        // 常见可删扩展名
        "|.tmp|temp|0|临时文件|1",
        "|.temp|temp|0|临时文件|1",
        "|.log|log|0|日志文件|30",
        "|.old|temp|0|旧备份文件|30",
        "|.chk|temp|0|磁盘检查文件|7",
        "|.gid|temp|0|帮助索引|30",
        "|.dmp|crash|1|内存转储|7",
        "|.err|log|0|错误日志|14",
        "|.etl|log|0|事件跟踪日志|30",
        "|.wer|crash|0|Windows错误报告|14",
        "|.hdmp|crash|1|堆转储文件|7",
        "|.mdmp|crash|1|MiniDump文件|7",
    };

    for (auto sig : signatures) {
        file << sig << "\n";
    }

    file.close();
    return load_junk_signatures(path);
}

} // namespace RuleDatabase
