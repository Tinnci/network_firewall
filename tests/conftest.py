# tests/conftest.py
import pytest
from .helpers import rule_helper # 使用相对导入

@pytest.fixture(scope="function") # function scope: 每个测试函数执行前后都会运行
def manage_rules():
    """Pytest fixture来管理rules.yaml文件"""
    rule_helper.backup_rules()
    # 开始测试前，可以应用一个干净的默认规则状态
    default_rules = rule_helper.get_default_rules()
    rule_helper.apply_rules(default_rules)
    yield # 测试将在此处运行
    rule_helper.restore_rules()
    print("规则文件已在测试后恢复。")
