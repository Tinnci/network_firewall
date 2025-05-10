# 自动化测试操作手册

本文档指导您如何运行本项目的自动化测试套件。

## 1. 环境准备

在运行测试之前，请确保满足以下条件：

### 1.1. Python 环境
- **Python 版本**: 确保您已安装 Python 3.8 或更高版本。
- **检查 Python 版本**:
  ```bash
  python --version
  ```

### 1.2. 安装项目依赖
- 项目的依赖项在 `pyproject.toml` 文件中定义。您可以使用 `pip` 来安装它们。
- 建议在虚拟环境中安装依赖，以避免与系统全局Python包冲突。

  **创建并激活虚拟环境 (可选但推荐):**
  ```bash
  # 在项目根目录
  python -m venv .venv
  # Windows
  .\.venv\Scripts\activate
  # macOS/Linux
  # source ./.venv/bin/activate
  ```

  **安装依赖:**
  ```bash
  pip install -e .[test]
  # 或者如果您有 requirements.txt (通常通过 pdm export -f requirements.txt --without-hashes 生成)
  # pip install -r requirements.txt
  # 或者直接使用 pip install pytest pytest-qt requests pyyaml mss Pillow psutil pydivert
  # 如果您使用 PDM (根据 pyproject.toml 和 uv.lock):
  # pdm install
  ```
  注意：`-e .[test]` 会根据 `pyproject.toml` 安装项目本身（可编辑模式）以及 `pytest` 和 `pytest-qt` 等测试相关的依赖（如果已在 `project.optional-dependencies`中定义 `test` 分组并包含它们）。如果您的 `pyproject.toml` 中没有 `[project.optional-dependencies.test]`，则需要手动安装 `pytest` 和 `pytest-qt`：
  ```bash
  pip install pytest pytest-qt
  ```
  根据您提供的 `pyproject.toml`，依赖项已在 `dependencies` 中列出，其中包括 `pytest` 和 `pytest-qt`。所以 `pip install -e .` 可能就足够了。

### 1.3. 防火墙状态
- 为确保测试环境的纯净，**在运行自动化测试前，请确保您的防火墙应用程序没有在手动运行状态**。测试脚本（通过 `manage_rules` fixture）会管理规则文件，并假设防火墙会在后台（如果已作为服务或通过某种方式启动）或在测试框架内（如果适用）对规则变化做出响应。
- 有些测试可能需要防火墙核心逻辑能够被测试脚本间接触发或已在运行。目前的设计是通过修改 `rules.yaml` 并期望运行中的防火墙（如果独立运行）能够重载规则。

### 1.4. 管理员权限
- **重要**: 防火墙的许多核心功能（尤其是网络包的拦截和处理，如使用 PyDivert）以及测试的正确执行**需要管理员权限**。

## 2. 执行测试

完成环境准备后，按照以下步骤执行测试：

### 2.1. 启动防火墙应用程序 (以管理员权限)
- **这是运行测试前非常关键的一步。**
- 打开一个命令行终端 (例如 PowerShell 或 CMD)。
- **以管理员身份运行此终端。** (Windows: 右键点击程序图标，选择 "以管理员身份运行")。
- 在此管理员终端中，使用 `cd` 命令导航到项目的根目录。
- 运行防火墙主程序：
  ```bash
  python main.py
  ```
- 防火墙的UI应该会启动并处于活动状态。**在测试期间保持此防火墙程序运行。**

### 2.2. 运行 Pytest (在另一个管理员终端中)
- 打开**第二个**命令行终端。
- **同样以管理员身份运行此终端。**
- 使用 `cd` 命令导航到项目的根目录。
- 在此管理员终端中，执行以下命令来运行所有测试：
  ```bash
  pytest
  ```
  或者，如果您确认 Windows 11 的 `sudo` 命令配置为在当前窗口提权并且对您的环境有效：
  ```bash
  sudo pytest
  ```
  但为确保一致性和避免 `sudo` 配置问题，直接在管理员终端中运行 `pytest` 更为推荐。

- **运行特定测试文件**:
  ```bash
  pytest tests/test_ip_filtering.py
  ```
- **运行特定测试用例 (按名称)**:
  ```bash
  pytest -k test_ip_blacklist
  ```
- **详细输出 (-v)**:
  ```bash
  pytest -v
  ```
- **捕获标准输出 (-s)** (如果您想看到测试函数中的 `print` 语句):
  ```bash
  pytest -s
  ```

## 3. 查看结果与产物

### 3.1. Pytest 输出
- 测试的执行结果（通过、失败、跳过、错误）会直接显示在第二个（Pytest）终端中。
- 如果有测试失败，Pytest 会提供详细的错误信息和回溯。

### 3.2. 截图
- 测试过程中生成的UI截图（如果相关测试被执行且成功截图）将保存在以下目录：
  `tests/screenshots/captured/`
- 文件名通常会包含测试的名称和时间戳。

### 3.3. 防火墙日志
- 防火墙应用程序 (`main.py` 运行的实例) 会将其日志记录到：
  `logs/firewall.log`
- 测试脚本 (`log_parser.py`) 会尝试从此路径读取日志进行断言。确保防火墙实际的日志输出路径与 `tests/helpers/log_parser.py` 中定义的 `LOG_FILE_PATH` 一致。
- **如果测试失败，请检查此日志文件的内容。** 它是否为空？是否包含任何拦截/放行条目？这些信息对于调试至关重要。

## 4. 注意事项
- **防火墙实例**: 测试的成功运行**高度依赖**于一个通过 `python main.py` 以管理员权限正确启动并正在运行的防火墙实例。
- **UI 测试**: `test_ui_interaction.py` 中的基础UI测试使用了 `pytest-qt` 的 `qtbot` fixture。确保 `pytest-qt` 已正确安装。
- **网络环境**: 某些测试用例依赖于对外部网络（如 `example.com`, `8.8.8.8`）的访问。确保测试机器的网络连接正常。
- **规则文件路径**: 所有测试辅助脚本（如 `rule_helper.py`）都依赖于 `rules.yaml` 文件在项目根目录。请确认路径配置正确。

按照这些步骤，您应该能够成功运行并分析自动化测试的结果。 