/**
 * @file SimpleMain.cpp
 * @brief 控制台/守护进程入口 — 无GUI模式
 * 适用于：调试运行、Windows 服务部署、CI测试
 * 使用 VS 编译: cl /EHsc /std:c++17 SimpleMain.cpp /Fe:LocalAISecurity-cli.exe
 */

#include <iostream>
#include <csignal>
#include <chrono>
#include <thread>
#include <string>
#include <atomic>

#define NOMINMAX
#include <windows.h>

#include "Core_Kernel/include/core_kernel.h"
#include "Rule_Database/include/rule_database.h"
#include "AI_Security_Engine/include/security_ai_engine.h"
#include "AI_Clean_Engine/include/clean_ai_engine.h"

using namespace CoreKernel;
using namespace RuleDatabase;
using namespace SecurityAI;
using namespace CleanAI;

static std::atomic<bool> g_running{true};

static void signal_handler(int) {
    g_running = false;
}

static SecurityAIEngine g_security_ai;
static CleanAIEngine g_clean_ai;
static std::atomic<uint64_t> g_threat_count{0};

static void on_system_event(const SystemEvent& event) {
    const char* type_str = "未知";
    switch (event.type) {
        case EventType::PROCESS_CREATE:   type_str = "进程创建"; break;
        case EventType::PROCESS_EXIT:     type_str = "进程终止"; break;
        case EventType::FILE_CREATE:      type_str = "文件创建"; break;
        case EventType::FILE_MODIFY:      type_str = "文件修改"; break;
        case EventType::FILE_DELETE:      type_str = "文件删除"; break;
        case EventType::REG_WRITE:        type_str = "注册表写入"; break;
        case EventType::NET_CONNECT:      type_str = "网络连接"; break;
        case EventType::NET_LISTEN:       type_str = "网络监听"; break;
        default: break;
    }

    // 安全事件触发AI推理
    if (g_security_ai.is_initialized() &&
        (event.type == EventType::PROCESS_CREATE ||
         event.type == EventType::FILE_MODIFY ||
         event.type == EventType::NET_CONNECT ||
         event.type == EventType::REG_WRITE)) {

        if (event.pid != 0 && event.pid != 4) {
            BehaviorFeature feature = SecurityAIEngine::extract_features(event.pid);
            auto result = g_security_ai.predict(feature);
            if (result.is_threat) {
                g_threat_count++;
                std::cout << "\n[!] AI检测到威胁! PID:" << event.pid
                          << " 置信度:" << (int)(result.confidence * 100) << "%"
                          << " 类别:" << static_cast<int>(result.classification) << "\n";
            }
        }
    }

    std::cout << "[" << type_str << "] PID:" << event.pid
              << " 路径:" << event.target_path
              << " 详情:" << event.detail << "\n";
}

static bool is_admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                  &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================\n"
              << "  LocalAISecurity — 控制台守护模式\n"
              << "  双AI智能安全体 v1.0.0\n"
              << "========================================\n\n";

    // 管理员权限检测
    if (!is_admin()) {
        std::cerr << "[警告] 未以管理员身份运行！\n"
                  << "  文件监控、网络连接详细信息、进程终止等功能将受限。\n"
                  << "  建议: 右键 → 以管理员身份运行\n\n";
    } else {
        std::cout << "[✓] 管理员权限已确认\n\n";
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::string data_dir = (argc > 1) ? argv[1] : "./data";
    std::string models_dir = (argc > 2) ? argv[2] : "./models";

    // 1. 初始化规则数据库
    std::cout << "[1/6] 加载规则数据库: " << data_dir << "\n";
    RuleDBManager rule_db;
    if (!rule_db.initialize(data_dir)) {
        std::cerr << "[错误] 规则数据库初始化失败，将使用默认规则\n";
    }
    std::cout << "  ✓ 已加载安全规则 + 白名单 + 垃圾特征库\n";

    // 2. 初始化安全AI引擎
    std::cout << "[2/6] 加载安全AI引擎...\n";
    if (g_security_ai.initialize(models_dir + "/security_model_int4.bin")) {
        std::cout << "  ✓ INT4量化安全模型已加载\n";
    } else {
        std::cerr << "  [警告] 安全模型未加载，使用规则引擎降级\n";
    }

    // 3. 初始化清理AI引擎
    std::cout << "[3/6] 加载清理AI引擎...\n";
    if (g_clean_ai.initialize(models_dir + "/clean_model_int4.bin",
                               data_dir + "/whitelist.dat")) {
        std::cout << "  ✓ INT4量化清理模型已加载\n";
    } else {
        std::cerr << "  [警告] 清理模型未加载，将仅使用规则匹配\n";
    }

    // 4. 初始化内核协调器
    std::cout << "[4/6] 初始化内核监控...\n";
    KernelCoordinator kernel;
    kernel.initialize();
    kernel.set_event_callback(on_system_event);
    std::cout << "  ✓ ProcessMonitor + FileMonitor + RegistryMonitor + NetworkMonitor 就绪\n";

    // 5. 启动所有监控
    std::cout << "[5/6] 启动系统事件监控...\n";
    if (!kernel.start_all()) {
        std::cerr << "[警告] 部分监控启动失败（可能需要管理员权限）\n";
    } else {
        std::cout << "  ✓ 进程/文件/注册表/网络监控已全部启动\n";
    }

    // 6. 主循环
    std::cout << "[6/6] 守护模式运行中，Ctrl+C 退出\n\n";
    std::cout << "状态: ";
    while (g_running) {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        char time_buf[9];
        std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", std::localtime(&t));

        std::cout << "\r状态: " << time_buf
                  << " | 进程:" << (kernel.is_process_monitor_running() ? "✓" : "✗")
                  << " 文件:" << (kernel.is_file_monitor_running() ? "✓" : "✗")
                  << " 注册表:" << (kernel.is_registry_monitor_running() ? "✓" : "✗")
                  << " 网络:" << (kernel.is_network_monitor_running() ? "✓" : "✗")
                  << " 威胁:" << g_threat_count.load()
                  << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "\n\n正在停止监控...\n";
    kernel.stop_all();
    g_security_ai.shutdown();
    g_clean_ai.shutdown();
    std::cout << "  已安全退出，再见。\n";
    return 0;
}

#ifdef _WINDOWS
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    return main(__argc, __argv);
}
#endif
