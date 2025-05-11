# tests/conftest.py
import pytest
import subprocess
import sys
import os
import time
import ctypes
import re
from .helpers import rule_helper, log_parser
import tempfile
import shutil # Added for directory cleanup if needed, though for logs it might be fine to keep

# --- 常量定义 ---
LOG_DIR = "logs"
# 将 LOG_FILE_PATH 和 MAIN_LOG_FILE 统一
MAIN_LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
SUMMARY_LOG_FILE = os.path.join(LOG_DIR, "test_session_block_summary.log")
DEFAULT_TEST_CSV_EXPORT_DIR = os.path.join(LOG_DIR, "test_csv_exports") # New constant for CSV export path

# 根据 main.py 中新的、明确的启动完成标志
FIREWALL_READY_MESSAGE = r"防火墙应用已完全初始化并准备好进行交互。"
FIREWALL_START_TIMEOUT_SECONDS = 45 # 增加超时时间

# Global or session-scoped storage for test results
# This dictionary will store results for each test.
_session_test_results = {}

FIREWALL_START_TIMEOUT = 10 # seconds

def is_admin():
    """检查当前进程是否以管理员权限运行 (仅限Windows)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        # ctypes.windll.shell32 is not available on non-Windows platforms
        # Assume not admin or handle as per non-Windows requirements
        # For this project, admin is critical on Windows.
        print("警告: 无法确定管理员状态 (可能不是Windows环境)。")
        return False

def clear_log_file_for_startup():
    """清空日志文件，以便检测新的启动消息"""
    try:
        if os.path.exists(MAIN_LOG_FILE): # 使用统一的常量
            with open(MAIN_LOG_FILE, 'w') as f:
                f.write("")
            print(f"启动前已清空日志文件: {MAIN_LOG_FILE}")
        # 确保日志目录存在
        log_dir = os.path.dirname(MAIN_LOG_FILE) # 使用统一的常量
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
            print(f"启动前已创建日志目录: {log_dir}")
    except Exception as e:
        print(f"启动前清空或创建日志文件/目录失败: {e}")


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    """在测试会话开始时检查管理员权限"""
    if sys.platform == "win32" and not is_admin():
        pytest.exit("错误：必须以管理员权限运行 Pytest 以进行防火墙测试。请以管理员身份重新启动您的终端/命令提示符，然后再次运行 pytest。", returncode=1)
    print("\nPytest 正在以管理员权限运行 (或非Windows环境)。")

    if sys.platform == "win32":
        print("\n--- 输出 ipconfig /all ---")
        try:
            result_ipconfig = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, check=False, encoding='gbk', errors='replace')
            print(result_ipconfig.stdout)
            if result_ipconfig.stderr:
                print("--- ipconfig stderr ---")
                print(result_ipconfig.stderr)
        except Exception as e:
            print(f"执行 ipconfig /all 失败: {e}")
        print("--- 完成 ipconfig /all ---\n")

        print("\n--- 输出 route print ---")
        try:
            result_route = subprocess.run(["route", "print"], capture_output=True, text=True, check=False, encoding='gbk', errors='replace')
            print(result_route.stdout)
            if result_route.stderr:
                print("--- route print stderr ---")
                print(result_route.stderr)
        except Exception as e:
            print(f"执行 route print 失败: {e}")
        print("--- 完成 route print ---\n")

    # 清理日志文件，为防火墙启动的就绪检测做准备
    clear_log_file_for_startup()

    # Initialize session results
    global _session_test_results
    _session_test_results = {}
    print(f"Main log file {MAIN_LOG_FILE} will be cleared by clear_log_file_for_startup if it exists.")
    print(f"Session block summary will be written to: {SUMMARY_LOG_FILE}")


@pytest.fixture(scope="session", autouse=True)
def firewall_service(request, monkeypatch_session): # monkeypatch_session for session-scoped env var changes
    """会话级别的fixture，用于启动和停止防火墙主程序 (main.py)"""
    print("\n启动防火墙服务 (main.py)...")
    firewall_process = None
    
    # 使用 monkeypatch_session 来管理会话级别的环境变量
    monkeypatch_session.setenv('FIREWALL_EFFECTIVE_SKIP_LOCAL', "0")
    print("Conftest: Set FIREWALL_EFFECTIVE_SKIP_LOCAL=0 for testing session.")
    monkeypatch_session.setenv('AUTO_START_FIREWALL_FOR_TESTING', "1")
    print("Conftest: Set AUTO_START_FIREWALL_FOR_TESTING=1 for testing session.")

    # --- 新增：默认启用并设置CSV自动导出路径 ---
    try:
        os.makedirs(DEFAULT_TEST_CSV_EXPORT_DIR, exist_ok=True)
        monkeypatch_session.setenv('FIREWALL_AUTO_EXPORT_CSV_PATH', DEFAULT_TEST_CSV_EXPORT_DIR)
        print(f"Conftest: Set FIREWALL_AUTO_EXPORT_CSV_PATH={DEFAULT_TEST_CSV_EXPORT_DIR} for automated CSV exports during testing session.")
    except Exception as e:
        print(f"Conftest: Warning - Failed to create or set FIREWALL_AUTO_EXPORT_CSV_PATH: {e}")
    # --- 完成新增 ---

    # 如果需要在测试期间禁用CSV导出，也可以在这里全局设置 (这将覆盖上面的设置，但通常我们希望默认启用)
    # monkeypatch_session.setenv('FIREWALL_TESTING_NO_CSV_EXPORT', '1')
    # print("Conftest: Set FIREWALL_TESTING_NO_CSV_EXPORT=1 for testing session (globally).")


    # 确保在启动防火墙前日志是干净的，以便准确检测启动消息
    clear_log_file_for_startup()

    try:
        # 为测试设置环境变量，以禁用 skip_local_packets
        # 使用 sys.executable 确保使用的是与 pytest 相同的 Python 解释器
        # CREATE_NEW_CONSOLE 可以在新窗口中显示防火墙UI和日志，方便调试
        # 若不希望新窗口，可以移除 creationflags 或使用 subprocess.DEVNULL
        cmd = [sys.executable, "main.py"]
        print(f"执行命令: {' '.join(cmd)}")
        firewall_process = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
        print(f"防火墙进程已启动 (PID: {firewall_process.pid}). 等待就绪...")

        start_time = time.time()
        ready = False
        log_lines_checked_for_ready = set()

        while time.time() - start_time < FIREWALL_START_TIMEOUT_SECONDS:
            if firewall_process.poll() is not None: # 进程意外退出
                pytest.fail(f"防火墙进程在等待就绪期间意外终止，返回码: {firewall_process.returncode}。请检查防火墙自身日志或错误输出。")
            
            if os.path.exists(MAIN_LOG_FILE): # 使用统一的常量
                try:
                    with open(MAIN_LOG_FILE, 'r', encoding='utf-8') as f: # 使用统一的常量
                        current_log_content = f.readlines()
                        # 只检查新行，避免重复处理大型日志
                        new_lines = [line for i, line in enumerate(current_log_content) if (MAIN_LOG_FILE, i) not in log_lines_checked_for_ready]
                        
                        for line_num_original, line_content in enumerate(current_log_content):
                            log_lines_checked_for_ready.add((MAIN_LOG_FILE, line_num_original))

                        for line in new_lines:
                            if re.search(FIREWALL_READY_MESSAGE, line):
                                print(f"防火墙已就绪！(在日志中找到: '{FIREWALL_READY_MESSAGE}')")
                                ready = True
                                break
                        if ready:
                            break
                except Exception as e:
                    print(f"读取日志文件以检查就绪状态时出错: {e}")
            time.sleep(1) # 等待1秒再检查

        if not ready:
            # 如果超时，尝试终止进程以防万一
            if firewall_process and firewall_process.poll() is None:
                firewall_process.terminate()
                try:
                    firewall_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    firewall_process.kill()
            pytest.fail(f"防火墙应用未在 {FIREWALL_START_TIMEOUT_SECONDS} 秒内发出就绪信号 ('{FIREWALL_READY_MESSAGE}' 未在 {MAIN_LOG_FILE} 中找到)。")
        
        yield firewall_process # 测试会话期间防火墙保持运行

    finally:
        print("\n停止防火墙服务...")
        if firewall_process and firewall_process.poll() is None: # 如果进程仍在运行
            try:
                # 尝试正常终止。main.py中的 remove_signal_handler 应能处理 PyQt 的清理。
                firewall_process.terminate() 
                firewall_process.wait(timeout=10) # 等待进程结束
                print("防火墙进程已终止。")
            except subprocess.TimeoutExpired:
                print("防火墙进程终止超时，尝试强制关闭...")
                firewall_process.kill()
                firewall_process.wait()
                print("防火墙进程已被强制关闭。")
            except Exception as e:
                print(f"停止防火墙进程时出错: {e}")
        elif firewall_process:
             print(f"防火墙进程已自行停止，返回码: {firewall_process.returncode}")
        else:
            print("防火墙进程未成功启动或已被处理。")

        # monkeypatch_session 会自动处理环境变量的恢复，无需手动清理
        print("Conftest: Environment variables managed by monkeypatch_session will be restored automatically.")

    # Teardown: Log final stats and write summary
    if _session_test_results:
        print("\n--- Test Session Block Summary ---")
        with open(SUMMARY_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("Test Session Block Summary:\n")
            f.write("=============================\n")
            for test_name, stats in _session_test_results.items():
                summary_line = f"{test_name}: {stats.get('blocked_packets', 0)} blocked_packets"
                print(summary_line)
                f.write(summary_line + "\n")
            f.write("=============================\n")
        print(f"Block summary saved to {SUMMARY_LOG_FILE}")
    else:
        print("No block stats recorded for this session.")
        with open(SUMMARY_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("No block stats recorded for this session.\n")

    print("--- Pytest Session Finish ---")


@pytest.fixture(scope="function", autouse=True)
def record_test_stats(request):
    """自动使用的fixture，在每个测试函数运行前后记录拦截的日志数量。"""
    global _session_test_results
    test_name = request.node.name
    
    # 为当前测试在日志中写入一个唯一的开始标记
    test_start_marker = f"--- TEST START: {test_name} ---"
    log_parser.log_marker(test_start_marker)
    
    yield # 测试函数在此运行
    
    # 新方法：计算自此测试的开始标记以来新增的拦截数量
    blocks_this_test = log_parser.count_log_entries_after_last_marker(
        pattern_to_count=r"拦截动作:", 
        marker_pattern=re.escape(test_start_marker) #确保特殊字符被转义
    )

    if test_name not in _session_test_results:
        _session_test_results[test_name] = {}
    _session_test_results[test_name]['blocked_packets'] = blocks_this_test
    # print(f"Stats for {test_name}: {blocks_this_test} blocked.") # Optional: print per-test immediate feedback

# 现有的 manage_rules fixture 保持不变，它会在每个测试函数级别运行
@pytest.fixture(scope="function")
def manage_rules():
    """Pytest fixture来管理rules.yaml文件"""
    rule_helper.backup_rules()
    # 开始测试前，可以应用一个干净的默认规则状态
    default_rules = rule_helper.get_default_rules()
    rule_helper.apply_rules(default_rules)
    yield # 测试将在此处运行
    rule_helper.restore_rules()
    print("规则文件已在测试后恢复。")

@pytest.fixture(scope="session")
def monkeypatch_session():
    """会话级别的 monkeypatch fixture。"""
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    yield mp
    mp.undo()

def test_csv_export_automated(monkeypatch, qtbot, your_main_window_fixture):
    # ... （启动防火墙等设置） ...
    window = your_main_window_fixture # 获取 MainWindow 实例

    # 创建一个临时目录用于测试导出
    # with tempfile.TemporaryDirectory() as tmpdir: # Now using default path from conftest
        # 可以指定完整路径，或者只指定目录让 log_tab 生成文件名
        # 选项1: 指定完整文件名
        # auto_csv_path = os.path.join(tmpdir, "automated_log_export.csv")
        # 选项2: 只指定目录，文件名会自动生成 (如果 log_tab 支持)
        # 为了简单和可预测，我们最好在测试中指定完整的文件名
    
    # 由于 conftest 现在设置了默认导出目录，我们可以依赖它
    # 如果特定测试需要不同的路径，它仍然可以在测试函数内部用 monkeypatch.setenv 覆盖
    # auto_csv_path = os.path.join(tmpdir, "test_export.csv") 
    # monkeypatch.setenv('FIREWALL_AUTO_EXPORT_CSV_PATH', auto_csv_path) # This would override conftest session setting
    
    # 我们需要一个方法来知道实际导出的文件名，因为它是带时间戳的
    # 我们可以检查 DEFAULT_TEST_CSV_EXPORT_DIR 目录中的最新文件
    # 或者，如果 LogTab 提供了信号或方法来获取最后导出的文件名，那会更好

    log_tab = window.log_tab # 假设您可以这样访问 LogTab 实例
    
    # 确保 log_tab 中有数据 (这里可能需要先产生一些日志)
    # ... 产生一些日志到UI ...
    # 例如，直接调用 add_log_entry (如果测试需要，并注意线程安全)
    # log_tab.add_log_entry({"log_type": "packet", "packet_info": {...}, "timestamp": "..."})
    # qtbot.wait(100) # 等待UI更新

    # 获取导出前目录中的文件列表
    files_before_export = set(os.listdir(DEFAULT_TEST_CSV_EXPORT_DIR))

    log_tab._export_filtered_logs_to_csv() # 直接调用导出方法

    # 获取导出后目录中的文件列表
    files_after_export = set(os.listdir(DEFAULT_TEST_CSV_EXPORT_DIR))
    
    new_files = files_after_export - files_before_export
    assert len(new_files) == 1, "A new CSV file should have been exported"
    exported_csv_filename = new_files.pop()
    exported_csv_filepath = os.path.join(DEFAULT_TEST_CSV_EXPORT_DIR, exported_csv_filename)

    # 验证文件是否已创建
    assert os.path.exists(exported_csv_filepath)
    print(f"Automated CSV export successful. File created at: {exported_csv_filepath}")
        
    # 可选：验证CSV内容
    with open(exported_csv_filepath, 'r', encoding='utf-8') as f:
        content = f.read()
        assert "Timestamp,Log Type" in content # 简单检查表头
            # ... 更详细的内容检查 ...

    # monkeypatch 会在测试退出时自动恢复环境变量
