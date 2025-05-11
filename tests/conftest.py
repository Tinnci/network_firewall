# tests/conftest.py
import pytest
import subprocess
import sys
import os
import time
import ctypes
import re
from .helpers import rule_helper, log_parser

LOG_FILE_PATH = "logs/firewall.log"
# 根据 firewall.core.packet_interceptor 的日志，或者 main.py 中更早的、可靠的启动完成标志
# "Firewall application started and ready." - 如果有这样的日志会更好
# "Packet interceptor started." - 似乎是 PacketInterceptor 模块中的日志
FIREWALL_READY_MESSAGE = r"Packet interceptor started" # 使用r""处理正则表达式特殊字符，尽管这里没有
FIREWALL_START_TIMEOUT_SECONDS = 45 # 增加超时时间

# Global or session-scoped storage for test results
# This dictionary will store results for each test.
_session_test_results = {}

FIREWALL_START_TIMEOUT = 10 # seconds
LOG_DIR = "logs"
MAIN_LOG_FILE = os.path.join(LOG_DIR, "firewall.log")
SUMMARY_LOG_FILE = os.path.join(LOG_DIR, "test_session_block_summary.log") # Define summary log file path

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
        if os.path.exists(LOG_FILE_PATH):
            with open(LOG_FILE_PATH, 'w') as f:
                f.write("")
            print(f"启动前已清空日志文件: {LOG_FILE_PATH}")
        # 确保日志目录存在
        log_dir = os.path.dirname(LOG_FILE_PATH)
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
def firewall_service(request):
    """会话级别的fixture，用于启动和停止防火墙主程序 (main.py)"""
    print("\n启动防火墙服务 (main.py)...")
    firewall_process = None
    original_skip_local_env = os.environ.get('FIREWALL_EFFECTIVE_SKIP_LOCAL')
    os.environ['FIREWALL_EFFECTIVE_SKIP_LOCAL'] = "0"
    print("Conftest: Set FIREWALL_EFFECTIVE_SKIP_LOCAL=0 for testing.")

    original_auto_start_env = os.environ.get('AUTO_START_FIREWALL_FOR_TESTING')
    os.environ['AUTO_START_FIREWALL_FOR_TESTING'] = "1"
    print("Conftest: Set AUTO_START_FIREWALL_FOR_TESTING=1 for testing.")

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
            
            if os.path.exists(LOG_FILE_PATH):
                try:
                    with open(LOG_FILE_PATH, 'r', encoding='utf-8') as f:
                        current_log_content = f.readlines()
                        # 只检查新行，避免重复处理大型日志
                        new_lines = [line for i, line in enumerate(current_log_content) if (LOG_FILE_PATH, i) not in log_lines_checked_for_ready]
                        
                        for line_num_original, line_content in enumerate(current_log_content):
                            log_lines_checked_for_ready.add((LOG_FILE_PATH, line_num_original))

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
            pytest.fail(f"防火墙应用未在 {FIREWALL_START_TIMEOUT_SECONDS} 秒内发出就绪信号 ('{FIREWALL_READY_MESSAGE}' 未在 {LOG_FILE_PATH} 中找到)。")
        
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

        # 清理/恢复环境变量
        if original_skip_local_env is None:
            if 'FIREWALL_EFFECTIVE_SKIP_LOCAL' in os.environ:
                del os.environ['FIREWALL_EFFECTIVE_SKIP_LOCAL']
                print("Conftest: Cleared FIREWALL_EFFECTIVE_SKIP_LOCAL environment variable.")
        else:
            os.environ['FIREWALL_EFFECTIVE_SKIP_LOCAL'] = original_skip_local_env
            print(f"Conftest: Restored FIREWALL_EFFECTIVE_SKIP_LOCAL to original value: '{original_skip_local_env}'.")

        # 清理/恢复 AUTO_START_FIREWALL_FOR_TESTING 环境变量
        if original_auto_start_env is None:
            if 'AUTO_START_FIREWALL_FOR_TESTING' in os.environ:
                del os.environ['AUTO_START_FIREWALL_FOR_TESTING']
                print("Conftest: Cleared AUTO_START_FIREWALL_FOR_TESTING environment variable.")
        else:
            os.environ['AUTO_START_FIREWALL_FOR_TESTING'] = original_auto_start_env
            print(f"Conftest: Restored AUTO_START_FIREWALL_FOR_TESTING to original value: '{original_auto_start_env}'.")

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
