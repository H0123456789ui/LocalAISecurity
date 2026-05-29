/**
 * @file main.cpp
 * @brief 应用程序入口
 * 初始化双AI引擎 + 内核防护 + UI
 */

#include "main_window.h"
#include "../AI_Security_Engine/include/security_ai_engine.h"
#include "../AI_Clean_Engine/include/clean_ai_engine.h"
#include "../Core_Kernel/include/core_kernel.h"
#include "../Rule_Database/include/rule_database.h"

using namespace UIApp;
using namespace SecurityAI;
using namespace CleanAI;
using namespace CoreKernel;
using namespace RuleDatabase;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine, int nCmdShow) {
    // 1. 初始化规则数据库
    RuleDBManager rule_db;
    rule_db.initialize("./data");

    // 2. 初始化安全AI引擎
    SecurityAIEngine security_ai;
    security_ai.initialize("./models/security_model_int4.bin");

    // 3. 初始化C盘清理AI引擎
    CleanAIEngine clean_ai;
    clean_ai.initialize("./models/clean_model_int4.bin", "./data/whitelist.dat");

    // 4. 初始化内核防护协调器
    KernelCoordinator kernel;
    kernel.initialize();

    // 设置事件回调：系统事件触发AI推理
    kernel.set_event_callback([&security_ai](const SystemEvent& event) {
        // 仅在进程创建/文件改写/网络连接/注册表修改时触发AI推理
        if (event.type == EventType::PROCESS_CREATE ||
            event.type == EventType::FILE_MODIFY ||
            event.type == EventType::NET_CONNECT ||
            event.type == EventType::REG_WRITE) {

            // 从Windows进程快照提取32维行为特征
            BehaviorFeature feature = SecurityAIEngine::extract_features(event.pid);
            if (event.pid == 0 || event.pid == 4) return; // 跳过系统空闲和System进程

            // AI推理
            auto result = security_ai.predict(feature);
            if (result.is_threat) {
                // 记录安全日志
                // 通知UI更新
            }
        }
    });

    // 5. 启动内核防护
    kernel.start_all();

    // 6. 创建并运行UI
    MainWindow main_window;
    if (!main_window.create(hInstance, nCmdShow)) {
        return -1;
    }

    int ret = main_window.run();

    // 7. 清理
    kernel.stop_all();
    security_ai.shutdown();
    clean_ai.shutdown();

    return ret;
}
