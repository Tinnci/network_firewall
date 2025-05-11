# tests/helpers/rule_helper.py
import yaml
import shutil
import os
from typing import Dict, Any

RULES_FILE_PATH = 'rules.yaml' # 假设在项目根目录
BACKUP_RULES_FILE_PATH = 'rules.yaml.backup'

def backup_rules():
    """备份当前的rules.yaml文件"""
    if os.path.exists(RULES_FILE_PATH):
        shutil.copyfile(RULES_FILE_PATH, BACKUP_RULES_FILE_PATH)
        print(f"规则文件已备份到 {BACKUP_RULES_FILE_PATH}")

def restore_rules():
    """恢复备份的rules.yaml文件"""
    if os.path.exists(BACKUP_RULES_FILE_PATH):
        shutil.copyfile(BACKUP_RULES_FILE_PATH, RULES_FILE_PATH)
        os.remove(BACKUP_RULES_FILE_PATH)
        print("规则文件已从备份恢复")

def get_default_rules() -> Dict[str, Any]:
    """获取一份默认的空规则结构，用于测试"""
    return {
        'ip_blacklist': [],
        'ip_whitelist': [],
        'port_blacklist': [],
        'port_whitelist': [],
        'content_filters': [],
        'protocol_filter': {'tcp': True, 'udp': True}
    }

def apply_rules(rules_config: Dict[str, Any]):
    """将指定的规则配置写入rules.yaml文件"""
    try:
        with open(RULES_FILE_PATH, 'w', encoding='utf-8') as f:
            yaml.dump(rules_config, f, default_flow_style=False, allow_unicode=True)
        print(f"测试规则已应用到 {RULES_FILE_PATH}")
        # 此处可能需要短暂延时或发送信号给防火墙以重新加载规则
        # import time
        # time.sleep(1) # 简单的延时，实际中可能需要更可靠的机制
    except Exception as e:
        print(f"应用规则失败: {e}")