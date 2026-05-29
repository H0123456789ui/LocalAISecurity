#pragma once

#include <string>
#include <vector>
#include <set>
#include <memory>
#include <unordered_map>
#include <functional>
#include <cstdint>
#include <mutex>
#include <condition_variable>
#include <thread>

#include <windows.h>

namespace CoreKernel {

enum class EventType : int {
    PROCESS_CREATE = 1,
    PROCESS_EXIT = 2,
    FILE_CREATE = 3,
    FILE_MODIFY = 4,
    FILE_DELETE = 5,
    FILE_RENAME = 6,
    REG_READ = 7,
    REG_WRITE = 8,
    REG_DELETE = 9,
    NET_CONNECT = 10,
    NET_LISTEN = 11,
    NET_SEND = 12,
    NET_RECV = 13
};

struct SystemEvent {
    EventType type;
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    std::string process_name;
    std::string process_path;
    std::string target_path;
    std::string detail;
};

struct ProcessInfo {
    uint32_t pid;
    uint32_t parent_pid;
    std::string name;
    std::string path;
    std::string command_line;
    std::string user;
    bool is_signed;
    std::string signer;
    double cpu_usage;
    uint64_t memory_usage;
    uint32_t thread_count;
    uint32_t handle_count;
};

using EventCallback = std::function<void(const SystemEvent&)>;

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    bool start();
    void stop();
    void set_callback(EventType type, EventCallback callback);
    std::vector<ProcessInfo> get_process_list();
    ProcessInfo get_process_info(uint32_t pid);
    bool terminate_process(uint32_t pid);
    static bool verify_process_signature(const std::string& path, std::string& signer);
    bool is_running() const { return running_; }
private:
    void event_loop();
    void on_process_event(const SystemEvent& event);
    bool running_;
    HANDLE notification_handle_;
    std::unordered_map<EventType, EventCallback> callbacks_;
    std::thread monitor_thread_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

class FileMonitor {
public:
    FileMonitor();
    ~FileMonitor();
    bool add_watch(const std::string& path);
    void remove_watch(const std::string& path);
    bool start();
    void stop();
    void set_callback(EventType type, EventCallback callback);
    bool is_running() const { return running_; }
private:
    void monitor_thread();
    void dispatch_notify(char* buffer, DWORD bytes_returned);
    bool pending_read(size_t watch_index);
    struct WatchContext {
        HANDLE hDir;
        std::string path;
        OVERLAPPED overlapped;
        alignas(DWORD) char buffer[4096];
    };
    bool running_;
    HANDLE iocp_;
    std::vector<std::unique_ptr<WatchContext>> watches_;
    std::unordered_map<EventType, EventCallback> callbacks_;
    std::thread monitor_thread_;
};

class RegistryMonitor {
public:
    RegistryMonitor();
    ~RegistryMonitor();
    bool add_watch(HKEY root_key, const std::string& sub_key);
    bool start();
    void stop();
    void set_callback(EventType type, EventCallback callback);
    bool is_running() const { return running_; }
private:
    void registry_loop(size_t index);  // 每个watch key独立线程
    bool running_;
    std::vector<HKEY> watched_keys_;
    std::unordered_map<EventType, EventCallback> callbacks_;
    std::vector<std::thread> monitor_threads_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

struct NetworkConnection {
    uint32_t pid;
    std::string process_name;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    int protocol;
    std::string state;
};

class NetworkMonitor {
public:
    NetworkMonitor();
    ~NetworkMonitor();
    bool start();
    void stop();
    std::vector<NetworkConnection> get_connections();
    void set_callback(EventType type, EventCallback callback);
    static bool is_suspicious_port(uint16_t port);
    bool is_running() const { return running_; }
private:
    void monitor_loop();
    void on_network_event(const SystemEvent& event);
    bool running_;
    std::thread monitor_thread_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::set<std::string> known_connections_;  // "pid:local:remote" key
    std::unordered_map<EventType, EventCallback> callbacks_;
};

class KernelCoordinator {
public:
    KernelCoordinator();
    ~KernelCoordinator();
    bool initialize();
    bool start_all();
    void stop_all();
    void set_event_callback(EventCallback callback);
    bool is_process_monitor_running() const;
    bool is_file_monitor_running() const;
    bool is_registry_monitor_running() const;
    bool is_network_monitor_running() const;
private:
    ProcessMonitor process_monitor_;
    FileMonitor file_monitor_;
    RegistryMonitor registry_monitor_;
    NetworkMonitor network_monitor_;
    EventCallback global_callback_;
    void dispatch_event(const SystemEvent& event);
};

}
