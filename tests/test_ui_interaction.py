import pytest
import sys
from PyQt6.QtWidgets import QApplication

# 尝试从项目结构导入 MainWindow
# 根据您的项目结构，路径可能需要调整
# 例如，如果 firewall 是顶级包，并且 main_window.py 在 firewall.ui 中
try:
    from firewall.ui.main_window import MainWindow
    from .screenshots.screenshot_util import take_qt_window_screenshot # 使用相对导入 .screenshots
    MAIN_WINDOW_IMPORTED = True
    SCREENSHOT_UTIL_IMPORTED = True
except ImportError as e:
    print(f"错误: 无法导入 MainWindow 或 take_qt_window_screenshot: {e}. 请检查PYTHONPATH和项目结构。")
    MainWindow = None
    take_qt_window_screenshot = None # type: ignore
    MAIN_WINDOW_IMPORTED = False
    SCREENSHOT_UTIL_IMPORTED = False

@pytest.mark.skipif(not (MAIN_WINDOW_IMPORTED and SCREENSHOT_UTIL_IMPORTED),
                    reason="MainWindow或截图工具无法导入，跳过UI截图测试")
def test_main_window_screenshot(qtbot):
    """测试主窗口截图 (用例 5.1 部分)"""
    print("\n开始测试: 主窗口截图")

    # QApplication 实例由 qtbot 确保
    app = QApplication.instance()
    if not app: # Fallback if qtbot isn't fully set up or running outside full pytest-qt
        app = QApplication(sys.argv)

    window = None
    try:
        window = MainWindow()
        qtbot.addWidget(window) # 注册窗口到qtbot，以便进行交互和等待
        window.show() # 显示窗口

        # 等待窗口可见并处理事件，确保它已完全渲染
        qtbot.waitUntil(window.isVisible, timeout=5000) 
        # qtbot.waitExposed(window, timeout=5000) # 确保窗口已暴露给窗口系统
        QApplication.processEvents() # 处理任何挂起的事件
        # time.sleep(1) # 短暂的硬等待，有时有助于确保渲染完成

        assert window.isVisible(), "主窗口在调用 show() 后应该可见"

        print(f"尝试截取窗口: {window.windowTitle()}")
        screenshot_path = take_qt_window_screenshot(window, "main_firewall_window_startup")
        
        assert screenshot_path is not None, "应成功截取主窗口的图像"
        print(f"主窗口截图已保存: {screenshot_path}")

    except Exception as e:
        pytest.fail(f"创建、显示或截取 MainWindow 时发生错误: {e}")
    finally:
        if window and hasattr(window, 'close'):
            # window.close() # 测试结束时关闭窗口
            pass # qtbot 可能会处理窗口的清理

    print("主窗口截图测试完成。")

# 注意：
# 1. 要运行此测试并与UI交互，您通常会使用 pytest-qt。
#    在 conftest.py 中，pytest-qt 会提供 qtbot fixture。
#    确保 pytest-qt 已安装并在您的测试命令中使用 (例如，直接运行 pytest)。
# 2. UI测试可能需要以特定方式运行（例如，在有显示环境的机器上）。
# 3. 防火墙程序本身可能需要在管理员权限下运行才能完全正常工作，
#    这可能会影响UI测试的执行方式和范围。
#    此处的测试主要验证UI组件是否可以基本加载，而不是完整的端到端功能。
