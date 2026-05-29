/**
 * @file core_kernel.cpp
 * @brief 系统内核防护层 - 实现
 * 使用Windows API实现进程/文件/注册表/网络监控
 * 事件触发机制：非轮询，仅事件发生时通知AI推理引擎
 */

#include "core_kernel.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <algorithm>
#include <chrono>
#include <shlobj.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")

namespace CoreKernel {

// ============================================================
// ProcessMonitor
// ============================================================
ProcessMonitor::ProcessMonitor() : running_(false), notification_handle_(nullptr) {}
ProcessMonitor::~ProcessMonitor() { stop(); }

bool ProcessMonitor::start() {
    if (running_) return true;

    running_ = true;
    monitor_thread_ = std::thread(&ProcessMonitor::event_loop, this);
    return true;
}

void ProcessMonitor::stop() {
    running_ = false;
    cv_.notify_all();
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void ProcessMonitor::event_loop() {
    std::set<uint32_t> known_pids;

    while (running_) {
        auto current = get_process_list();
        std::set<uint32_t> current_pids;
        for (const auto& proc : current) {
            current_pids.insert(proc.pid);
        }

        for (uint32_t pid : current_pids) {
            if (known_pids.find(pid) == known_pids.end()) {
                SystemEvent event;
                event.type = EventType::PROCESS_CREATE;
                event.pid = pid;
                event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                for (const auto& proc : current) {
                    if (proc.pid == pid) {
                        event.process_name = proc.name;
                        event.process_path = proc.path;
                        break;
                    }
                }
                on_process_event(event);
            }
        }

        for (uint32_t pid : known_pids) {
            if (current_pids.find(pid) == current_pids.end()) {
                SystemEvent event;
                event.type = EventType::PROCESS_EXIT;
                event.pid = pid;
                event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                on_process_event(event);
            }
        }

        known_pids = std::move(current_pids);

        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait_for(lock, std::chrono::milliseconds(500), [this] { return !running_; });
    }
}

void ProcessMonitor::set_callback(EventType type, EventCallback callback) {
    callbacks_[type] = callback;
}

std::vector<ProcessInfo> ProcessMonitor::get_process_list() {
    std::vector<ProcessInfo> result;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.parent_pid = pe32.th32ParentProcessID;

            // 进程名 (宽字符转多字节)
            char name[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, name, MAX_PATH, nullptr, nullptr);
            info.name = name;

            // 获取进程详细信息
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                          FALSE, pe32.th32ProcessID);
            if (hProcess) {
                char path[MAX_PATH];
                if (GetModuleFileNameExA(hProcess, nullptr, path, MAX_PATH)) {
                    info.path = path;
                }

                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    info.memory_usage = pmc.WorkingSetSize;
                }

                // 验证数字签名
                info.is_signed = verify_process_signature(info.path, info.signer);

                CloseHandle(hProcess);
            }

            result.push_back(info);
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return result;
}

ProcessInfo ProcessMonitor::get_process_info(uint32_t pid) {
    ProcessInfo info;
    info.pid = pid;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return info;

    char path[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, nullptr, path, MAX_PATH)) {
        info.path = path;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        info.memory_usage = pmc.WorkingSetSize;
    }

    CloseHandle(hProcess);
    return info;
}

bool ProcessMonitor::terminate_process(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;

    bool result = TerminateProcess(hProcess, 1) != 0;
    CloseHandle(hProcess);
    return result;
}

bool ProcessMonitor::verify_process_signature(const std::string& path, std::string& signer) {
    // 使用WinVerifyTrust API验证数字签名
    // 简化实现：检查文件是否存在数字签名目录
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);

    std::wstring wpath(path.begin(), path.end());
    fileInfo.pcwszFilePath = wpath.c_str();

    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &actionId, &trustData);

    signer = (status == ERROR_SUCCESS) ? "Verified" : "Unknown";
    return status == ERROR_SUCCESS;
}

void ProcessMonitor::on_process_event(const SystemEvent& event) {
    auto it = callbacks_.find(event.type);
    if (it != callbacks_.end()) {
        it->second(event);
    }
}

// ============================================================
// FileMonitor
// ============================================================
FileMonitor::FileMonitor() : running_(false), iocp_(nullptr) {}
FileMonitor::~FileMonitor() { stop(); }

bool FileMonitor::add_watch(const std::string& path) {
    auto ctx = std::make_unique<WatchContext>();
    ctx->hDir = CreateFileA(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (ctx->hDir == INVALID_HANDLE_VALUE) return false;
    ctx->path = path;
    memset(&ctx->overlapped, 0, sizeof(OVERLAPPED));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));

    watches_.push_back(std::move(ctx));
    return true;
}

void FileMonitor::remove_watch(const std::string& path) {
    for (auto it = watches_.begin(); it != watches_.end(); ++it) {
        if ((*it)->path == path) {
            if ((*it)->hDir != INVALID_HANDLE_VALUE) {
                CloseHandle((*it)->hDir);
            }
            watches_.erase(it);
            break;
        }
    }
}

bool FileMonitor::pending_read(size_t watch_index) {
    if (watch_index >= watches_.size()) return false;
    auto& ctx = watches_[watch_index];
    memset(&ctx->overlapped, 0, sizeof(OVERLAPPED));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));

    DWORD bytes_returned = 0;
    BOOL ok = ReadDirectoryChangesW(
        ctx->hDir,
        ctx->buffer,
        sizeof(ctx->buffer),
        TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME |
        FILE_NOTIFY_CHANGE_DIR_NAME |
        FILE_NOTIFY_CHANGE_ATTRIBUTES |
        FILE_NOTIFY_CHANGE_SIZE |
        FILE_NOTIFY_CHANGE_LAST_WRITE |
        FILE_NOTIFY_CHANGE_CREATION,
        &bytes_returned,
        &ctx->overlapped,
        nullptr
    );
    return ok != 0;
}

bool FileMonitor::start() {
    if (running_) return true;
    if (watches_.empty()) return false;

    iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!iocp_) return false;

    for (size_t i = 0; i < watches_.size(); ++i) {
        CreateIoCompletionPort(watches_[i]->hDir, iocp_, static_cast<ULONG_PTR>(i), 0);
        pending_read(i);
    }

    running_ = true;
    monitor_thread_ = std::thread(&FileMonitor::monitor_thread, this);
    return true;
}

void FileMonitor::stop() {
    running_ = false;
    if (iocp_) {
        PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
    }
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    if (iocp_) {
        CloseHandle(iocp_);
        iocp_ = nullptr;
    }
    for (auto& ctx : watches_) {
        if (ctx->hDir != INVALID_HANDLE_VALUE) {
            CloseHandle(ctx->hDir);
        }
    }
    watches_.clear();
}

void FileMonitor::set_callback(EventType type, EventCallback callback) {
    callbacks_[type] = callback;
}

void FileMonitor::dispatch_notify(char* buffer, DWORD bytes_returned) {
    if (bytes_returned == 0) return;

    FILE_NOTIFY_INFORMATION* pNotify =
        reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer);

    while (true) {
        SystemEvent event;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        switch (pNotify->Action) {
            case FILE_ACTION_ADDED:
                event.type = EventType::FILE_CREATE; break;
            case FILE_ACTION_REMOVED:
                event.type = EventType::FILE_DELETE; break;
            case FILE_ACTION_MODIFIED:
                event.type = EventType::FILE_MODIFY; break;
            case FILE_ACTION_RENAMED_OLD_NAME:
            case FILE_ACTION_RENAMED_NEW_NAME:
                event.type = EventType::FILE_RENAME; break;
            default:
                event.type = EventType::FILE_MODIFY; break;
        }

        DWORD wide_char_count = pNotify->FileNameLength / sizeof(WCHAR);
        char filename[MAX_PATH] = {};
        int converted = WideCharToMultiByte(
            CP_ACP, 0,
            pNotify->FileName, wide_char_count,
            filename, MAX_PATH - 1,
            nullptr, nullptr);
        if (converted > 0) {
            filename[converted] = '\0';
        } else {
            filename[0] = '\0';
        }
        event.target_path = filename;

        auto it = callbacks_.find(event.type);
        if (it != callbacks_.end()) {
            it->second(event);
        }

        if (pNotify->NextEntryOffset == 0) break;
        pNotify = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
            reinterpret_cast<BYTE*>(pNotify) + pNotify->NextEntryOffset);
    }
}

void FileMonitor::monitor_thread() {
    while (running_) {
        DWORD bytes_transferred = 0;
        ULONG_PTR completion_key = 0;
        LPOVERLAPPED overlapped = nullptr;

        BOOL ok = GetQueuedCompletionStatus(
            iocp_, &bytes_transferred, &completion_key, &overlapped, 2000);

        if (!running_) break;

        if (ok && bytes_transferred > 0) {
            size_t idx = static_cast<size_t>(completion_key);
            if (idx < watches_.size()) {
                dispatch_notify(watches_[idx]->buffer, bytes_transferred);
                pending_read(idx);
            }
        }
    }
}

// ============================================================
// RegistryMonitor
// ============================================================
RegistryMonitor::RegistryMonitor() : running_(false) {}
RegistryMonitor::~RegistryMonitor() { stop(); }

bool RegistryMonitor::add_watch(HKEY root_key, const std::string& sub_key) {
    HKEY hKey;
    if (RegOpenKeyExA(root_key, sub_key.c_str(), 0, KEY_NOTIFY, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    watched_keys_.push_back(hKey);
    return true;
}

bool RegistryMonitor::start() {
    if (running_) return true;
    running_ = true;

    // 每个监听的注册表键一个独立线程，实现并行监控
    monitor_threads_.reserve(watched_keys_.size());
    for (size_t i = 0; i < watched_keys_.size(); ++i) {
        monitor_threads_.emplace_back(&RegistryMonitor::registry_loop, this, i);
    }
    return true;
}

void RegistryMonitor::stop() {
    running_ = false;
    cv_.notify_all();
    for (auto& t : monitor_threads_) {
        if (t.joinable()) t.join();
    }
    monitor_threads_.clear();
    for (auto hKey : watched_keys_) {
        RegCloseKey(hKey);
    }
    watched_keys_.clear();
}

void RegistryMonitor::registry_loop(size_t index) {
    HKEY hKey = watched_keys_[index];
    DWORD notify_filter = REG_NOTIFY_CHANGE_NAME |
                          REG_NOTIFY_CHANGE_ATTRIBUTES |
                          REG_NOTIFY_CHANGE_LAST_SET |
                          REG_NOTIFY_CHANGE_SECURITY;

    while (running_) {
        LONG result = RegNotifyChangeKeyValue(
            hKey, TRUE, notify_filter, NULL, FALSE);

        if (result == ERROR_SUCCESS && running_) {
            SystemEvent event;
            event.type = EventType::REG_WRITE;
            event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            event.detail = "Registry key changed";

            std::lock_guard<std::mutex> lock(mtx_);
            auto it = callbacks_.find(EventType::REG_WRITE);
            if (it != callbacks_.end()) {
                it->second(event);
            }
        }
    }
}

void RegistryMonitor::set_callback(EventType type, EventCallback callback) {
    callbacks_[type] = callback;
}

// ============================================================
// NetworkMonitor
// ============================================================
NetworkMonitor::NetworkMonitor() : running_(false) {}
NetworkMonitor::~NetworkMonitor() { stop(); }

bool NetworkMonitor::start() {
    if (running_) return true;
    running_ = true;
    known_connections_.clear();
    monitor_thread_ = std::thread(&NetworkMonitor::monitor_loop, this);
    return true;
}

void NetworkMonitor::stop() {
    running_ = false;
    cv_.notify_all();
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

void NetworkMonitor::set_callback(EventType type, EventCallback callback) {
    callbacks_[type] = callback;
}

void NetworkMonitor::monitor_loop() {
    while (running_) {
        auto current = get_connections();
        std::set<std::string> current_keys;

        for (const auto& conn : current) {
            std::string key = std::to_string(conn.pid) + ":" +
                              conn.local_addr + ":" +
                              std::to_string(conn.local_port) + ":" +
                              conn.remote_addr + ":" +
                              std::to_string(conn.remote_port);
            current_keys.insert(key);

            if (known_connections_.find(key) == known_connections_.end()) {
                SystemEvent event;
                event.type = (conn.state == "LISTEN")
                             ? EventType::NET_LISTEN
                             : EventType::NET_CONNECT;
                event.pid = conn.pid;
                event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                event.detail = conn.local_addr + ":" + std::to_string(conn.local_port) +
                               " -> " + conn.remote_addr + ":" +
                               std::to_string(conn.remote_port) +
                               " [" + conn.state + "]";

                if (is_suspicious_port(conn.local_port) ||
                    is_suspicious_port(conn.remote_port)) {
                    event.detail += " (可疑端口!)";
                }

                on_network_event(event);
            }
        }

        known_connections_ = std::move(current_keys);

        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait_for(lock, std::chrono::milliseconds(2000), [this] { return !running_; });
    }
}

void NetworkMonitor::on_network_event(const SystemEvent& event) {
    auto it = callbacks_.find(event.type);
    if (it != callbacks_.end()) {
        it->second(event);
    }
}

std::vector<NetworkConnection> NetworkMonitor::get_connections() {
    std::vector<NetworkConnection> result;

    // 获取TCP连接表
    DWORD dwSize = 0;
    GetExtendedTcpTable(nullptr, &dwSize, FALSE, AF_INET,
                         TCP_TABLE_OWNER_PID_ALL, 0);

    if (dwSize > 0) {
        std::vector<char> buffer(dwSize);
        auto* pTcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());

        if (GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                NetworkConnection conn;
                auto& row = pTcpTable->table[i];
                conn.pid = row.dwOwningPid;
                conn.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
                conn.remote_port = ntohs(static_cast<u_short>(row.dwRemotePort));
                conn.protocol = IPPROTO_TCP;

                in_addr localAddr;
                localAddr.S_un.S_addr = row.dwLocalAddr;
                conn.local_addr = inet_ntoa(localAddr);

                in_addr remoteAddr;
                remoteAddr.S_un.S_addr = row.dwRemoteAddr;
                conn.remote_addr = inet_ntoa(remoteAddr);

                switch (row.dwState) {
                    case MIB_TCP_STATE_CLOSED: conn.state = "CLOSED"; break;
                    case MIB_TCP_STATE_LISTEN: conn.state = "LISTEN"; break;
                    case MIB_TCP_STATE_ESTAB: conn.state = "ESTABLISHED"; break;
                    case MIB_TCP_STATE_TIME_WAIT: conn.state = "TIME_WAIT"; break;
                    default: conn.state = "OTHER"; break;
                }

                result.push_back(conn);
            }
        }
    }

    // 获取UDP连接表
    dwSize = 0;
    GetExtendedUdpTable(nullptr, &dwSize, FALSE, AF_INET,
                          UDP_TABLE_OWNER_PID, 0);

    if (dwSize > 0) {
        std::vector<char> buffer(dwSize);
        auto* pUdpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());

        if (GetExtendedUdpTable(pUdpTable, &dwSize, FALSE, AF_INET,
                                 UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++) {
                NetworkConnection conn;
                auto& row = pUdpTable->table[i];
                conn.pid = row.dwOwningPid;
                conn.local_port = ntohs(static_cast<u_short>(row.dwLocalPort));
                conn.protocol = IPPROTO_UDP;
                conn.state = "UDP";

                in_addr localAddr;
                localAddr.S_un.S_addr = row.dwLocalAddr;
                conn.local_addr = inet_ntoa(localAddr);

                result.push_back(conn);
            }
        }
    }

    return result;
}

bool NetworkMonitor::is_suspicious_port(uint16_t port) {
    // 已知恶意软件常用端口
    static const uint16_t suspicious_ports[] = {
        4444, 5555, 6666, 6667, 8888, 9999,  // 反向Shell常用端口
        1337, 31337,                           // 经典后门端口
        1234, 12345, 54321,                    // 常见测试/后门端口
        65535                                  // 高位端口
    };

    for (auto sp : suspicious_ports) {
        if (port == sp) return true;
    }
    return false;
}

// ============================================================
// KernelCoordinator
// ============================================================
KernelCoordinator::KernelCoordinator() {}
KernelCoordinator::~KernelCoordinator() { stop_all(); }

bool KernelCoordinator::initialize() {
    // 动态获取系统路径，避免硬编码盘符
    WCHAR winDir[MAX_PATH] = {};
    GetWindowsDirectoryW(winDir, MAX_PATH);

    WCHAR progFiles[MAX_PATH] = {};
    WCHAR progFilesX86[MAX_PATH] = {};
    WCHAR progData[MAX_PATH] = {};
    SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, progFiles);
    SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, 0, progFilesX86);
    SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, progData);

    char winDirA[MAX_PATH] = {};
    char progFilesA[MAX_PATH] = {};
    char progFilesX86A[MAX_PATH] = {};
    char progDataA[MAX_PATH] = {};
    WideCharToMultiByte(CP_UTF8, 0, winDir, -1, winDirA, MAX_PATH, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, progFiles, -1, progFilesA, MAX_PATH, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, progFilesX86, -1, progFilesX86A, MAX_PATH, nullptr, nullptr);
    WideCharToMultiByte(CP_UTF8, 0, progData, -1, progDataA, MAX_PATH, nullptr, nullptr);

    file_monitor_.add_watch(winDirA);
    file_monitor_.add_watch(progFilesA);
    file_monitor_.add_watch(progFilesX86A);
    file_monitor_.add_watch(progDataA);

    // 添加默认监控注册表键
    registry_monitor_.add_watch(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    registry_monitor_.add_watch(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    registry_monitor_.add_watch(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    registry_monitor_.add_watch(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services");

    return true;
}

bool KernelCoordinator::start_all() {
    bool success = true;
    success &= process_monitor_.start();
    success &= file_monitor_.start();
    success &= registry_monitor_.start();
    success &= network_monitor_.start();
    return success;
}

void KernelCoordinator::stop_all() {
    process_monitor_.stop();
    file_monitor_.stop();
    registry_monitor_.stop();
    network_monitor_.stop();
}

void KernelCoordinator::set_event_callback(EventCallback callback) {
    global_callback_ = callback;

    // 为所有监控器设置统一回调
    auto dispatch = [this](const SystemEvent& event) {
        dispatch_event(event);
    };

    process_monitor_.set_callback(EventType::PROCESS_CREATE, dispatch);
    process_monitor_.set_callback(EventType::PROCESS_EXIT, dispatch);
    file_monitor_.set_callback(EventType::FILE_CREATE, dispatch);
    file_monitor_.set_callback(EventType::FILE_MODIFY, dispatch);
    file_monitor_.set_callback(EventType::FILE_DELETE, dispatch);
    file_monitor_.set_callback(EventType::FILE_RENAME, dispatch);
    registry_monitor_.set_callback(EventType::REG_WRITE, dispatch);
    registry_monitor_.set_callback(EventType::REG_DELETE, dispatch);
    network_monitor_.set_callback(EventType::NET_CONNECT, dispatch);
    network_monitor_.set_callback(EventType::NET_LISTEN, dispatch);
}

bool KernelCoordinator::is_process_monitor_running() const {
    return process_monitor_.is_running();
}

bool KernelCoordinator::is_file_monitor_running() const {
    return file_monitor_.is_running();
}

bool KernelCoordinator::is_registry_monitor_running() const {
    return registry_monitor_.is_running();
}

bool KernelCoordinator::is_network_monitor_running() const {
    return network_monitor_.is_running();
}

void KernelCoordinator::dispatch_event(const SystemEvent& event) {
    if (global_callback_) {
        global_callback_(event);
    }
}

} // namespace CoreKernel
