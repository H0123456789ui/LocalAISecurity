# 🔒 LocalAISecurity — 双AI智能安全体

[![Platform](https://img.shields.io/badge/platform-Windows%2010%2B-blue)](https://www.microsoft.com/windows)
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://www.python.org/)
[![C++](https://img.shields.io/badge/C%2B%2B-17-blueviolet)](https://isocpp.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

基于**双AI引擎**的 Windows 本地安全防护 + 磁盘清理工具。**零数据上传**，所有 AI 推理完全在本地完成。

---

## ✨ 功能特性

### 🛡 安全防护 AI
- **4 分类 CNN 模型**实时识别进程行为：正常 / 流氓软件 / 木马 / 勒索软件
- **全盘杀毒扫描**— 一键扫描所有进程、网络连接、启动项、可疑文件
- **结果分类展示**：病毒 / 疑似病毒 / 安全问题 / 其他风险，支持选择性和一键处理
- **32 维进程特征**多模态行为分析（CPU、内存、网络、IO、路径可疑度）
- **WMI 事件驱动**进程创建实时监控 + psutil 轮询降级
- **数字签名验证**ctypes 调用 WinVerifyTrust，零进程开销

### 💿 C盘清理 AI
- **5 分类 CNN 模型**文件智能分级：系统核心 / 软件缓存 / 安全可删 / 大型冗余 / 用户重要
- **C盘空间总览**— 彩色空间占用条 + 系统/软件/用户/其他文件分项统计
- **分类详情**— 点击任意分类进入文件列表，显示每个文件的重要性等级和可删性
- **超大文件扫描**— 自动发现 >100MB 的大文件，标注是否可安全删除
- **进度条反馈**— 扫描全程显示确定进度条和实时文件计数
- **文件重要性分级**— 18 个等级（系统核心→可清理），彩色标签直观展示
- **一键清理安全项**— 仅清理 AI 确认安全的文件，零误删风险
- **18 维文件特征**路径深度、时间衰减、扩展名风险、隐藏/系统属性
- **规则引擎降级**PyTorch 加载失败时自动切换规则引擎

### 🏗 架构亮点
- **纯本地推理**— 所有数据不上传，隐私绝对安全
- **双前端**— C++ Win32 原生 UI（轻量）+ Python Tkinter Apple 风格 UI（美观）
- **C++ 推理引擎**— 手写 INT4 量化推理，零框架依赖
- **双语言协作**— Python 原型+训练 / C++ 生产部署

---

## 🚀 快速开始

### 环境要求
- Windows 10 或更高版本
- Python 3.8+

### 安装 & 运行

```bash
# 1. 克隆项目
git clone https://github.com/your-username/LocalAISecurity.git
cd LocalAISecurity

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动应用
python start_app.py

# 开机最小化启动
python start_app.py --minimized
```

### C++ 引擎编译（可选）

C++ 引擎提供更高性能的本地推理，Python 版可独立运行。

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### 训练 AI 模型

```bash
cd Model_Train_Script
python train_both_models.py
```

---

## 📖 使用指南

### 主界面

| 按钮 | 功能 |
|------|------|
| **启动防护** | 开启实时进程行为监控，AI 自动检测威胁 |
| **停止防护** | 暂停所有监控，系统进入待机状态 |
| **C盘扫描** | AI 分析 C 盘文件 + 空间占用总览 + 分类详情 |
| **全盘杀毒** | 全盘安全扫描：进程 + 网络 + 启动项 + 可疑文件 |

### C盘扫描流程

1. 点击「C盘扫描」→ AI 垃圾分类扫描（约 1 分钟）
2. 弹出「C盘智能分析报告」窗口，三个标签页：
   - **📊 C盘总览**— 彩色进度条显示各分类占用 + 点击分类查看详情
   - **🗑 可清理文件**— AI 分类的可清理文件列表，勾选后清理
   - **📦 超大文件**— >100MB 的文件列表，标注可删性
3. 在总览中**点击任意分类**进入详细文件列表，可筛选「可清理」/「重要」文件
4. 勾选文件后点击「执行清理」→ 文件移入回收站（可恢复）

### 全盘杀毒流程

1. 点击「全盘杀毒」→ 自动扫描（约 2-5 分钟）
2. 结果分 4 类标签页展示，每项标注风险等级和 AI 置信度
3. 支持「处理选中项」和「一键处理所有问题」

---

## 📁 项目结构

```
LocalAISecurity/
├── start_app.py              # Python 入口 — Tkinter 双 AI 主程序
├── ai_engine.py              # AI 推理引擎 + 安全监控 + 进程特征采集
├── classifier.py             # AI 文件分类器 + 规则引擎降级
├── scanner.py                # 磁盘扫描 + 全盘安全扫描 + C盘空间分析
├── ui_components.py          # Apple 风格 UI 组件库 + 结果窗口
├── models.py                 # PyTorch CNN 模型定义
├── models/                   # 训练好的 INT4 量化模型文件 (.bin)
│
├── AI_Security_Engine/       # C++ 安全 AI 推理引擎 (INT4)
├── AI_Clean_Engine/          # C++ 清理 AI 推理引擎 (INT4)
├── AI_Common/                # C++ 共享算子库 (nn_ops.h)
├── Core_Kernel/              # C++ 内核监控 (IOCP文件/注册表/网络/进程)
├── Rule_Database/            # C++ 规则数据库 (白名单/病毒特征/垃圾签名)
├── Net_Update_Module/        # C++ 单向升级模块 (HTTP + SHA256)
├── Local_Data/               # C++ 本地数据持久化
├── UI_App/                   # C++ Win32 原生 UI
│
├── Model_Train_Script/       # 模型训练脚本 (PyTorch CNN → INT4量化)
├── tests/                    # Python 单元测试 (37项)
├── requirements.txt          # Python 依赖
├── CMakeLists.txt            # C++ CMake 构建配置
└── SimpleMain.cpp            # C++ 入口
```

---

## 🔧 技术栈

| 层级 | 技术 |
|------|------|
| AI 框架 | PyTorch CNN（训练）→ INT4 量化（部署） |
| Python 推理 | PyTorch（GPU/CPU），不可用时降级规则引擎 |
| C++ 推理 | 手写推理引擎（纯 C++17，零依赖） |
| Python UI | Tkinter + Pillow + pystray 系统托盘 |
| C++ UI | Win32 API（纯原生） |
| 进程监控 | WMI 事件驱动 + psutil 轮询降级 |
| 签名验证 | ctypes 调用 WinVerifyTrust（零进程开销） |
| 文件删除 | SHFileOperation 移入回收站（可恢复） |
| 数据存储 | JSON 配置文件 + CSV 规则库 |
| 构建系统 | CMake + MSVC |

---

## 🧪 测试

```bash
# 运行全部测试（37 项）
python -m pytest tests/ -v
```

---

## ⚠️ 免责声明

本项目仅供学习和研究使用。AI 模型判断可能存在误判，清理文件前请仔细确认。使用者需自行承担因误删文件导致的一切后果。

---

## 📄 许可证

MIT License — 详见 [LICENSE](LICENSE) 文件。
