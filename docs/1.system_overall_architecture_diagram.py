# system_overall_architecture_diagram.py
from graphviz import Digraph

def generate_system_overall_architecture_diagram():
    """
    生成防火墙系统总体架构图
    """
    dot = Digraph('Firewall_System_Overall_Architecture', comment='防火墙系统总体架构图', format='png')
    dot.attr(rankdir='TB', labelloc="t", label="防火墙系统总体架构图", fontsize="20")

    # 设置全局字体为 "Microsoft YaHei"
    dot.attr('graph', fontname='Microsoft YaHei')
    dot.attr('node', fontname='Microsoft YaHei')
    dot.attr('edge', fontname='Microsoft YaHei')

    # 定义节点样式
    ui_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightblue'}
    core_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightgreen'}
    core_sub_style = {'shape': 'box', 'style': 'rounded,filled', 'fillcolor': 'palegreen'}
    util_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightyellow'}
    data_style = {'shape': 'cylinder', 'style': 'filled', 'fillcolor': 'lightgray'}
    driver_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'orange'}
    important_style = {'color': 'red', 'penwidth': '2.0'} # 关键组件的边框

    # 用户界面层
    with dot.subgraph(name='cluster_ui_layer') as ui_cluster:
        ui_cluster.attr(label='用户界面层 (UI Layer)', style='filled', color='skyblue')
        ui_cluster.node('MainWindow', 'MainWindow (主窗口)', **ui_style, **important_style)
        ui_cluster.node('UITabs', '功能标签页\n(IP/端口/内容过滤, 流量/日志/性能监控等)', **ui_style)
        dot.edge('MainWindow', 'UITabs', label='管理交互')

    # 核心逻辑层
    with dot.subgraph(name='cluster_core_logic_layer') as core_cluster:
        core_cluster.attr(label='核心逻辑层 (Core Logic Layer)', style='filled', color='lightcoral')
        core_cluster.node('FirewallCore', 'Firewall (主控)', **core_style, **important_style)

        with core_cluster.subgraph(name='cluster_packet_handling') as packet_handling_cluster:
            packet_handling_cluster.attr(label='数据包处理核心', style='dashed', color='black')
            packet_handling_cluster.node('PacketInterceptor', 'PacketInterceptor\n(数据包拦截模块)', **core_sub_style, **important_style)
            packet_handling_cluster.node('PacketAnalyzer', 'PacketAnalyzer\n(数据包分析模块)', **core_sub_style, **important_style)
            packet_handling_cluster.node('PacketProcessor', 'PacketProcessor\n(数据包处理模块)', **core_sub_style, **important_style)

        with core_cluster.subgraph(name='cluster_rule_management') as rule_management_cluster:
            rule_management_cluster.attr(label='规则管理核心', style='dashed', color='black')
            rule_management_cluster.node('RuleManager', 'RuleManager\n(规则管理模块)', **core_sub_style, **important_style)
            rule_management_cluster.node('RuleStorage', 'RuleStorage', **core_sub_style)
            rule_management_cluster.node('RuleValidator', 'RuleValidator', **core_sub_style)

        # 核心内部关系
        dot.edge('FirewallCore', 'PacketInterceptor', label='控制')
        dot.edge('FirewallCore', 'PacketAnalyzer', label='配置')
        dot.edge('FirewallCore', 'PacketProcessor', label='控制')
        dot.edge('FirewallCore', 'RuleManager', label='使用/更新')
        dot.edge('PacketInterceptor', 'PacketProcessor', label='原始数据包')
        dot.edge('PacketProcessor', 'PacketAnalyzer', label='请求分析')
        dot.edge('PacketAnalyzer', 'RuleManager', label='获取规则')
        dot.edge('RuleManager', 'RuleStorage', label='读/写')
        dot.edge('RuleManager', 'RuleValidator', label='调用')


    # 工具与配置层
    with dot.subgraph(name='cluster_utils_config_layer') as util_cluster:
        util_cluster.attr(label='工具与配置层 (Utilities & Config Layer)', style='filled', color='khaki')
        util_cluster.node('Config', 'Config (配置管理)', **util_style)
        util_cluster.node('LoggingUtils', 'LoggingUtils (日志工具)', **util_style)
        util_cluster.node('NetworkUtils', 'NetworkUtils (网络工具)', **util_style)
        util_cluster.node('PerformanceUtils', 'PerformanceUtils (性能工具)', **util_style)

    # 操作系统/驱动层 (与核心逻辑层交互紧密，放在其下方)
    with dot.subgraph(name='cluster_os_driver_layer') as os_cluster:
        os_cluster.attr(label='操作系统/驱动层 (OS/Driver Layer)', style='filled', color='peachpuff')
        os_cluster.node('PyDivert', 'PyDivert/WinDivert 驱动', **driver_style, **important_style)
        os_cluster.node('OSNetworkStack', '操作系统网络协议栈', **driver_style)
        dot.edge('PacketInterceptor', 'PyDivert', label='调用')
        dot.edge('PyDivert', 'OSNetworkStack', label='交互')


    # 数据存储 (与规则管理和日志工具交互)
    with dot.subgraph(name='cluster_data_storage') as data_cluster:
        data_cluster.attr(label='数据存储 (Data Storage)', style='filled', color='lightgrey')
        data_cluster.node('rules.yaml', 'rules.yaml (规则文件)', **data_style)
        data_cluster.node('config.yaml_file', 'config.yaml (配置文件)', **data_style) # Renamed to avoid conflict with Config node
        data_cluster.node('firewall.log', 'logs/firewall.log (日志文件)', **data_style)
        dot.edge('RuleStorage', 'rules.yaml', label='读/写')
        dot.edge('Config', 'config.yaml_file', label='读取')
        dot.edge('LoggingUtils', 'firewall.log', label='写入')

    # 主要层间交互
    dot.edge('MainWindow', 'FirewallCore', label='用户指令/状态反馈')
    dot.edge('FirewallCore', 'LoggingUtils', label='记录日志')
    dot.edge('FirewallCore', 'Config', label='获取配置')
    dot.edge('UITabs', 'LoggingUtils', label='显示日志 (通过信号)', dir='back', constraint='false')
    dot.edge('UITabs', 'PerformanceUtils', label='显示性能 (通过信号)', dir='back', constraint='false')
    dot.edge('RuleValidator', 'NetworkUtils', label='使用验证函数')
    dot.edge('PacketAnalyzer', 'NetworkUtils', label='使用验证函数')


    try:
        dot.render('firewall_system_overall_architecture', view=False, cleanup=True)
        print("系统总体架构图已保存为 firewall_system_overall_architecture.png")
    except Exception as e:
        print(f"生成系统总体架构图失败: {e}\n请确保已安装Graphviz并将其添加到系统PATH。")

if __name__ == '__main__':
    generate_system_overall_architecture_diagram()