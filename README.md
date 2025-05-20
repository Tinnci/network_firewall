# 简易网络防火墙

一个基于PyDivert和PyQt6的简易网络防火墙，可以过滤TCP/UDP数据包、设置IP和端口黑白名单以及进行内容过滤。

## 功能特点

1. 基于网络通信，实现简单防火墙功能
2. 支持按协议类型(TCP/UDP)过滤数据包
3. 支持按IP地址和端口过滤数据包
4. 支持设置IP地址和端口的白名单和黑名单
5. 支持基于内容的数据包过滤
6. 提供直观的用户界面

## 环境要求

- Windows 操作系统 (7/8/10/11)
- Python 3.8+
- 管理员权限 (需要管理员权限才能捕获和修改网络数据包)

## 安装指南

### 使用 uv 安装

```bash
# 克隆仓库
git clone <repository-url>
cd network-firewall

# 使用 uv 安装依赖
uv sync
```

## 运行方法

由于需要管理员权限才能访问网络数据包，建议以管理员身份运行命令提示符或PowerShell，然后执行：

```bash
python main.py
```

程序会自动检查权限，如果没有足够的权限，会提示你以管理员身份重新启动。

## 使用说明

### 基本操作

1. 点击"启动防火墙"按钮开始监控网络数据包
2. 在各标签页中设置过滤规则：
   - IP过滤：添加IP地址到黑名单或白名单
   - 端口过滤：添加端口到黑名单或白名单
   - 内容过滤：添加内容过滤规则

### 规则优先级

1. 白名单优先于黑名单
2. 规则匹配顺序：协议 -> IP地址 -> 端口 -> 内容

### 注意事项

- 添加过多的内容过滤规则可能会影响性能
- 某些核心系统服务的数据包可能无法被过滤
- 规则保存在程序目录下的rules.yaml文件中

## 项目结构

```
FIREWALL
│  config.py              # 配置文件，定义了防火墙的日志、规则、性能、拦截器和UI的默认配置，并提供从YAML文件加载配置的功能
│  constants.py          # 常量文件，定义了防火墙应用中使用的各种常量，如操作类型、协议类型、规则类型、日志类型等
│  __init__.py           # 初始化文件，使firewall目录成为Python包
│
├─core                   # 核心功能模块，包含防火墙的主要逻辑和处理组件
│  │  firewall.py        # 防火墙主类，负责整体协调和控制
│  │  packet_analyzer.py # 数据包分析器，检查数据包是否符合规则
│  │  packet_interceptor.py # 数据包拦截器，负责捕获网络数据包
│  │  packet_processor.py # 数据包处理器，处理拦截到的数据包
│  │  rule_manager.py    # 规则管理器，负责加载和管理防火墙规则
│  │  __init__.py        # 初始化文件，使core目录成为Python包
│
├─ui                     # 用户界面模块，包含GUI相关代码
│  │  main_window.py     # 主窗口文件，定义防火墙应用的主界面
│  │  ui_utils.py        # UI工具函数，提供界面相关的辅助功能
│  │  __init__.py        # 初始化文件，使ui目录成为Python包
│  │
│  └─tabs                # UI标签页，包含不同功能的界面标签
│     │  advanced_settings_tab.py # 高级设置标签页，允许用户配置高级选项
│     │  content_filter_tab.py    # 内容过滤标签页，用于设置内容过滤规则
│     │  ip_filter_tab.py         # IP过滤标签页，用于配置IP黑白名单
│     │  log_tab.py               # 日志标签页，显示防火墙日志信息
│     │  performance_tab.py       # 性能标签页，显示性能统计和配置选项
│     │  port_filter_tab.py       # 端口过滤标签页，用于配置端口规则
│     │  traffic_monitor_tab.py   # 流量监控标签页，显示网络流量统计
│     │  __init__.py              # 初始化文件，使tabs目录成为Python包
│
└─utils                  # 工具模块，包含辅助功能和工具函数
   │  logging_utils.py   # 日志工具，提供日志记录相关功能
   │  network_utils.py   # 网络工具，提供网络相关辅助函数
   │  performance_utils.py # 性能工具，提供性能优化相关功能
   │  __init__.py        # 初始化文件，使utils目录成为Python包
```

## 许可证

MIT
