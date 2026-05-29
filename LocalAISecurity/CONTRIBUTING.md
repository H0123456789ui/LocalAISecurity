# 贡献指南

感谢你对 LocalAISecurity 的关注！欢迎任何形式的贡献。

## 环境搭建

```bash
git clone https://github.com/your-username/LocalAISecurity.git
cd LocalAISecurity
pip install -r requirements.txt
```

## 开发规范

### Python 代码
- 遵循 PEP 8 风格
- 函数命名使用 `snake_case`，类名使用 `PascalCase`
- 所有新增功能需包含单元测试（`tests/` 目录）
- 运行 `python -m pytest tests/ -v` 确保全部通过后再提交

### C++ 代码
- 标准：C++17，MSVC 编译器
- `#define NOMINMAX` 必须在 `#include <windows.h>` 之前
- 头文件关键字标识符使用 ASCII（MSVC 代码页 936 不支持中文标识符）
- 禁止在头文件中内联实现有副作用的函数（ODR 违规风险）
- 编译命令：`cmake -G "Visual Studio 17 2022" -A x64 .. && cmake --build . --config Release`

### 提交信息
- 使用中文描述变更
- 格式：`类型: 简短描述`
- 类型：`新增` `修复` `优化` `文档` `重构` `测试`

示例：
```
新增: 全盘杀毒扫描功能
修复: C盘分析器递归扫描死循环
文档: 更新README项目结构
```

## 分支策略

- `main` — 稳定版本
- `dev` — 开发分支
- 功能分支命名：`feature/功能名`（如 `feature/full-scan`）
- 修复分支命名：`fix/问题描述`（如 `fix/junction-loop`）

## 项目架构

项目采用**双语言协作**架构：
- **Python 层**：Tkinter UI + PyTorch 推理（训练/原型/fallback）
- **C++ 层**：INT4 量化推理引擎 + Windows 内核监控（生产路径）

AI 引擎不可用时降级为规则引擎，规则引擎不可用时返回安全默认值。所有网络通信仅下行，不上传数据。

## 测试

```bash
# Python 单元测试
python -m pytest tests/ -v

# 代码风格检查
python -m pytest tests/ -v --tb=short
```

新增功能请同步添加测试用例。现有测试 37 项，提交前需全部通过。
