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
network_firewall/
├── firewall/
│   ├── __init__.py
│   ├── config.py              # 配置加载与管理
│   ├── core/
│   │   ├── __init__.py
│   │   ├── firewall.py        # 防火墙核心逻辑类
│   │   ├── packet_analyzer.py   # 数据包分析与解码
│   │   ├── packet_filter.py   # 数据包过滤逻辑
│   │   ├── packet_interceptor.py# 数据包捕获与拦截 (基于PyDivert)
│   │   ├── packet_processor.py  # 数据包处理流程协调
│   │   ├── rule_manager.py    # 规则加载与管理
│   │   └── rules/             # 规则定义、存储与验证
│   │       ├── __init__.py
│   │       ├── rule_storage.py  # 规则文件读写
│   │       └── rule_validator.py# 规则格式验证
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── main_window.py     # 主窗口UI界面
│   │   └── tabs/              # UI中的各个标签页
│   │       ├── __init__.py
│   │       ├── advanced_settings_tab.py
│   │       ├── content_filter_tab.py
│   │       ├── ip_filter_tab.py
│   │       ├── log_tab.py
│   │       ├── performance_tab.py
│   │       └── port_filter_tab.py
│   └── utils/                 # 工具模块
│       ├── __init__.py
│       ├── logging_utils.py   # 日志记录相关工具
│       ├── network_utils.py   # 网络相关工具
│       └── performance_utils.py # 性能相关工具
├── logs/                      # 日志文件目录
├── main.py                    # 程序主入口
├── pyproject.toml             # 项目构建与依赖配置 (PDM)
├── README.md                  # 项目说明文档
├── rules.yaml                 # 防火墙规则配置文件
└── ...                        # 其他配置文件和环境文件 (.gitignore, .venv, etc.)
```

## 许可证

MIT
