# system_data_flow_diagram.py
from graphviz import Digraph

def generate_system_data_flow_diagram():
    """
    生成防火墙系统数据流程图 (数据包的完整处理流程)
    """
    dot = Digraph('Firewall_System_Data_Flow', comment='防火墙系统数据流程图', format='png')
    dot.attr(rankdir='TB', labelloc="t", label="防火墙系统数据流程图", fontsize="20")

    # 设置全局字体为 "Microsoft YaHei"
    dot.attr('graph', fontname='Microsoft YaHei')
    dot.attr('node', fontname='Microsoft YaHei')
    dot.attr('edge', fontname='Microsoft YaHei')

    # 定义节点样式
    io_style = {'shape': 'parallelogram', 'style': 'filled', 'fillcolor': 'lightblue'}
    process_style = {'shape': 'box', 'style': 'rounded,filled', 'fillcolor': 'lightyellow'}
    core_module_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightgreen'}
    decision_style = {'shape': 'diamond', 'style': 'filled', 'fillcolor': 'lightcoral'}
    action_style = {'shape': 'ellipse', 'style': 'filled', 'fillcolor': 'palegreen'}
    important_style = {'color': 'red', 'penwidth': '2.0'}

    # 节点定义
    dot.node('Start', '网络数据包到达', **io_style)
    dot.node('PyDivertCapture', 'PyDivert驱动捕获', **core_module_style)
    dot.node('InterceptorReceive', 'PacketInterceptor接收数据包', **core_module_style, **important_style)
    dot.node('ProcessorHandle', 'PacketProcessor处理请求', **core_module_style)
    dot.node('AnalyzerRequest', '请求PacketAnalyzer分析', **process_style)
    dot.node('RuleManagerAccess', 'RuleManager提供规则', **core_module_style)
    dot.node('AnalyzerAnalyze', 'PacketAnalyzer执行规则匹配\n(协议, IP, 端口, 内容)', **core_module_style, **important_style)
    dot.node('AnalyzerResult', 'PacketAnalyzer返回分析结果\n(允许/拦截)', **process_style)
    dot.node('ProcessorAction', 'PacketProcessor执行动作', **core_module_style, **important_style)
    dot.node('DecisionAllow', '是否允许?', **decision_style, **important_style)
    dot.node('InterceptorSend', 'PacketInterceptor发送数据包', **core_module_style)
    dot.node('PyDivertInject', 'PyDivert驱动注入数据包', **core_module_style)
    dot.node('PacketOut', '数据包发出', **io_style, **important_style)
    dot.node('PacketDrop', '数据包丢弃', **action_style, **important_style)
    dot.node('UpdateStats', '更新统计信息', **process_style)
    dot.node('LogEvent', '记录日志事件', **process_style)
    dot.node('UICallback', '触发UI回调 (流量/日志)', **process_style)
    dot.node('UIUpdate', 'UI界面更新', **io_style, **important_style)

    # 边连接
    dot.edge('Start', 'PyDivertCapture')
    dot.edge('PyDivertCapture', 'InterceptorReceive')
    dot.edge('InterceptorReceive', 'ProcessorHandle', label='原始数据包')
    dot.edge('ProcessorHandle', 'AnalyzerRequest')
    dot.edge('RuleManagerAccess', 'AnalyzerAnalyze', label='当前规则')
    dot.edge('AnalyzerRequest', 'AnalyzerAnalyze', label='数据包')
    dot.edge('AnalyzerAnalyze', 'AnalyzerResult')
    dot.edge('AnalyzerResult', 'ProcessorAction')
    dot.edge('ProcessorAction', 'DecisionAllow')

    dot.edge('DecisionAllow', 'InterceptorSend', label='是 (允许)')
    dot.edge('InterceptorSend', 'PyDivertInject')
    dot.edge('PyDivertInject', 'PacketOut')
    dot.edge('PacketOut', 'UpdateStats')

    dot.edge('DecisionAllow', 'PacketDrop', label='否 (拦截)')
    dot.edge('PacketDrop', 'UpdateStats')

    dot.edge('UpdateStats', 'LogEvent')
    dot.edge('LogEvent', 'UICallback')
    dot.edge('UICallback', 'UIUpdate')

    try:
        dot.render('firewall_system_data_flow', view=False, cleanup=True)
        print("系统数据流程图已保存为 firewall_system_data_flow.png")
    except Exception as e:
        print(f"生成系统数据流程图失败: {e}\n请确保已安装Graphviz并将其添加到系统PATH。")

if __name__ == '__main__':
    generate_system_data_flow_diagram()
