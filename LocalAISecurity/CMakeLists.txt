# CMakeLists.txt - LocalAISecurity 完整构建配置
# 目标：安装包 ≤30MB，纯静态链接，无第三方运行时依赖

cmake_minimum_required(VERSION 3.20)
project(LocalAISecurity VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 静态链接运行时，减少体积和依赖
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

# 优化选项：最小体积
if(MSVC)
    add_compile_options(/O2 /utf-8)
    add_link_options(/OPT:REF /OPT:ICF)
endif()

# ============================================================
# 源文件
# ============================================================

# AI安全行为推理引擎
set(SECURITY_AI_SOURCES
    AI_Security_Engine/src/security_ai_engine.cpp
)

# AI C盘清理推理引擎
set(CLEAN_AI_SOURCES
    AI_Clean_Engine/src/clean_ai_engine.cpp
)

# 系统内核防护层
set(CORE_KERNEL_SOURCES
    Core_Kernel/src/core_kernel.cpp
    Core_Kernel/src/load_avoidance.cpp
)

# 规则数据库
set(RULE_DB_SOURCES
    Rule_Database/src/rule_database.cpp
)

# 联网升级模块
set(NET_UPDATE_SOURCES
    Net_Update_Module/src/net_update_module.cpp
)

# 本地数据层
set(LOCAL_DATA_SOURCES
    Local_Data/src/local_data.cpp
)

# UI层
set(UI_SOURCES
    UI_App/main_window.cpp
    UI_App/main.cpp
)

# ============================================================
# 主程序
# ============================================================
add_executable(LocalAISecurity WIN32
    ${SECURITY_AI_SOURCES}
    ${CLEAN_AI_SOURCES}
    ${CORE_KERNEL_SOURCES}
    ${RULE_DB_SOURCES}
    ${NET_UPDATE_SOURCES}
    ${LOCAL_DATA_SOURCES}
    ${UI_SOURCES}
)

# 包含目录
target_include_directories(LocalAISecurity PRIVATE
    AI_Common/include
    AI_Security_Engine/include
    AI_Clean_Engine/include
    Core_Kernel/include
    Rule_Database/include
    Net_Update_Module/include
    Local_Data/include
)

# 链接库
target_link_libraries(LocalAISecurity PRIVATE
    comctl32
    psapi
    winhttp
    bcrypt
    powrprof
    shell32
    advapi32
    ws2_32
    wintrust
    iphlpapi
)

# ============================================================
# 安装规则
# ============================================================
install(TARGETS LocalAISecurity RUNTIME DESTINATION .)

# 安装模型文件
install(FILES
    ${CMAKE_SOURCE_DIR}/models/security_model_int4.bin
    ${CMAKE_SOURCE_DIR}/models/clean_model_int4.bin
    DESTINATION models)

# 安装数据文件
install(FILES
    ${CMAKE_SOURCE_DIR}/Rule_Database/data/whitelist.dat
    ${CMAKE_SOURCE_DIR}/Rule_Database/data/security_rules.dat
    ${CMAKE_SOURCE_DIR}/Rule_Database/data/junk_signatures.dat
    DESTINATION data)

# ============================================================
# 体积控制 - 自定义目标
# ============================================================
add_custom_target(size_report
    COMMAND ${CMAKE_COMMAND} -E echo "=== 安装包体积报告 ==="
    COMMAND ${CMAKE_COMMAND} -E echo "主程序:"
    COMMAND powershell -Command "(Get-Item $<TARGET_FILE:LocalAISecurity>).Length / 1MB"
    COMMAND ${CMAKE_COMMAND} -E echo "MB"
    COMMAND ${CMAKE_COMMAND} -E echo "目标: ≤29MB (主程序12MB + 模型10MB + 数据4MB + 其他3MB)"
)
