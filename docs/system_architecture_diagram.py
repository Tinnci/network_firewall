# system_architecture_diagram.py
# 需要先安装 graphviz: pip install graphviz
# 并且系统中需要安装 Graphviz 的可执行文件，并将其添加到PATH环境变量
# (访问 https://graphviz.org/download/ 下载)

from graphviz import Digraph

def generate_system_architecture_diagram():
    """
    生成防火墙系统架构图
    """
    dot = Digraph('Firewall_System_Architecture', comment='防火墙系统架构图', format='png')
    dot.attr(rankdir='TB', labelloc="t", label="防火墙系统架构图", fontsize="20") # TB: Top to Bottom, LR: Left to Right

    # 设置全局字体为 "Microsoft YaHei"
    dot.attr('graph', fontname='Microsoft YaHei')
    dot.attr('node', fontname='Microsoft YaHei')
    dot.attr('edge', fontname='Microsoft YaHei')

    # 定义节点样式
    ui_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightblue'}
    core_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightgreen'}
    util_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightyellow'}
    data_style = {'shape': 'cylinder', 'style': 'filled', 'fillcolor': 'lightgray'} # 或者用 'folder'
    driver_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'orange'}
    important_style = {'color': 'red', 'penwidth': '2.0'} # 关键流程的边框

    # 用户界面层
    with dot.subgraph(name='cluster_ui') as ui_cluster:
        ui_cluster.attr(label='用户界面层 (UI Layer)', style='filled', color='skyblue')
        ui_cluster.node('MainWindow', **ui_style, **important_style) # 主窗口 - 关键
        ui_cluster.node('IpFilterTab', 'IP过滤标签页', **ui_style)
        ui_cluster.node('PortFilterTab', '端口过滤标签页', **ui_style)
        ui_cluster.node('ContentFilterTab', '内容过滤标签页', **ui_style)
        ui_cluster.node('TrafficMonitorTab', '流量监控标签页', **ui_style)
        ui_cluster.node('LogTab', '日志标签页', **ui_style)
        ui_cluster.node('PerformanceTab', '性能监控标签页', **ui_style)
        ui_cluster.node('AdvancedSettingsTab', '高级设置标签页', **ui_style)
        # UI内部关系 (简化表示)
        dot.edge('MainWindow', 'IpFilterTab', label='管理')
        dot.edge('MainWindow', 'PortFilterTab', label='管理')
        dot.edge('MainWindow', 'ContentFilterTab', label='管理')
        dot.edge('MainWindow', 'TrafficMonitorTab', label='管理')
        dot.edge('MainWindow', 'LogTab', label='管理')
        dot.edge('MainWindow', 'PerformanceTab', label='管理')
        dot.edge('MainWindow', 'AdvancedSettingsTab', label='管理')


    # 核心逻辑层
    with dot.subgraph(name='cluster_core') as core_cluster:
        core_cluster.attr(label='核心逻辑层 (Core Logic Layer)', style='filled', color='palegreen')
        core_cluster.node('FirewallCore', 'Firewall 主控', **core_style, **important_style) # 防火墙核心 - 关键
        core_cluster.node('PacketInterceptor', **core_style, **important_style) # 数据包拦截器 - 关键
        core_cluster.node('RuleManager', **core_style, **important_style) # 规则管理器 - 关键
        core_cluster.node('RuleStorage', 'RuleStorage (规则存储)', **core_style)
        core_cluster.node('RuleValidator', 'RuleValidator (规则验证)', **core_style)
        core_cluster.node('PacketAnalyzer', **core_style, **important_style) # 数据包分析器 - 关键
        core_cluster.node('PacketProcessor', **core_style, **important_style) # 数据包处理器 - 关键

        # 核心内部关系
        dot.edge('FirewallCore', 'PacketInterceptor', label='控制')
        dot.edge('FirewallCore', 'RuleManager', label='使用/更新')
        dot.edge('FirewallCore', 'PacketAnalyzer', label='配置')
        dot.edge('FirewallCore', 'PacketProcessor', label='控制/配置')
        dot.edge('RuleManager', 'RuleStorage', label='调用')
        dot.edge('RuleManager', 'RuleValidator', label='调用')
        dot.edge('PacketInterceptor', 'PacketProcessor', label='传递数据包')
        dot.edge('PacketProcessor', 'PacketAnalyzer', label='请求分析')
        dot.edge('PacketAnalyzer', 'RuleManager', label='获取规则')
        dot.edge('PacketProcessor', 'PacketInterceptor', label='发送/丢弃决策')


    # 工具与配置层
    with dot.subgraph(name='cluster_utils') as util_cluster:
        util_cluster.attr(label='工具与配置层 (Utilities & Config)', style='filled', color='khaki')
        util_cluster.node('ConfigLoader', 'Config (配置加载)', **util_style)
        util_cluster.node('LoggingUtils', **util_style)
        util_cluster.node('NetworkUtils', **util_style)
        util_cluster.node('PerformanceUtils', **util_style)

    # 数据存储
    with dot.subgraph(name='cluster_data') as data_cluster:
        data_cluster.attr(label='数据存储 (Data Storage)', style='filled', color='lightgrey')
        data_cluster.node('rules.yaml', **data_style)
        data_cluster.node('config.yaml', **data_style) # 假设有config.yaml
        data_cluster.node('firewall.log', 'logs/firewall.log', **data_style)

    # 操作系统/驱动
    with dot.subgraph(name='cluster_os') as os_cluster:
        os_cluster.attr(label='操作系统/驱动 (OS/Driver)', style='filled', color='peachpuff')
        os_cluster.node('PyDivert', 'PyDivert/WinDivert 驱动', **driver_style, **important_style) # PyDivert - 关键
        os_cluster.node('NetworkStack', '操作系统网络协议栈', **driver_style)

    # 主要交互关系
    dot.edge('MainWindow', 'FirewallCore', label='用户操作/状态更新')
    dot.edge('FirewallCore', 'LoggingUtils', label='记录日志')
    dot.edge('FirewallCore', 'ConfigLoader', label='读取配置')
    dot.edge('RuleManager', 'rules.yaml', label='读/写')
    dot.edge('ConfigLoader', 'config.yaml', label='读取')
    dot.edge('LoggingUtils', 'firewall.log', label='写入')
    dot.edge('LoggingUtils', 'LogTab', label='显示日志 (通过信号)')
    dot.edge('PacketInterceptor', 'PyDivert', label='使用 (捕获/注入)')
    dot.edge('PyDivert', 'NetworkStack', label='交互')
    dot.edge('PerformanceUtils', 'PerformanceTab', label='提供数据')
    dot.edge('NetworkUtils', 'RuleValidator', label='提供验证函数')
    dot.edge('NetworkUtils', 'PacketAnalyzer', label='提供验证函数')
    dot.edge('PacketProcessor', 'TrafficMonitorTab', label='更新流量 (通过信号)')


    # 渲染并保存
    try:
        dot.render('firewall_system_architecture', view=False)
        print("系统架构图已保存为 firewall_system_architecture.png")
    except Exception as e:
        print(f"生成系统架构图失败: {e}")
        print("请确保已安装Graphviz并将其添加到系统PATH。")

if __name__ == '__main__':
    generate_system_architecture_diagram()
