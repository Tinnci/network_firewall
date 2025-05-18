# packet_capture_protocol_filter_flowchart.py
from graphviz import Digraph

def generate_packet_capture_protocol_filter_flowchart():
    """
    生成数据包捕获与协议过滤流程图
    """
    dot = Digraph('Firewall_Packet_Capture_Protocol_Filter', comment='数据包捕获与协议过滤流程图', format='svg')
    dot.attr(rankdir='TB', labelloc="t", label="数据包捕获与协议过滤流程图", fontsize="20")

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
    dot.node('Start', '网络数据包到达\n(来自操作系统网络协议栈)', **io_style)
    dot.node('PyDivertDriver', 'PyDivert/WinDivert驱动', **core_module_style, **important_style)
    dot.node('InterceptorRecvLoop', 'PacketInterceptor._receive_loop()', **core_module_style, **important_style)
    dot.node('RecvPacket', 'divert.recv()\n接收数据包', **process_style)
    dot.node('PassToProcessor', '调用PacketProcessor.handle_packet()', **process_style)
    dot.node('ProcessorRequestsAnalysis', 'PacketProcessor请求\nPacketAnalyzer分析', **core_module_style)
    dot.node('AnalyzerChecksProtocol', 'PacketAnalyzer: 检查协议类型\n(TCP/UDP?)', **decision_style, **important_style)
    dot.node('NonTCPUDP', '非TCP/UDP数据包?', **decision_style) # Added for clarity
    dot.node('AllowNonTCPUDP', '默认放行 (非TCP/UDP)', **action_style)
    dot.node('CheckTCPAllowed', 'TCP协议是否允许?', **decision_style)
    dot.node('CheckUDPAllowed', 'UDP协议是否允许?', **decision_style)
    dot.node('BlockProtocol', '标记拦截 (协议禁止)', **action_style, **important_style)
    dot.node('ContinueToIPFilter', '继续进行IP地址过滤', **process_style)

    # 边连接
    dot.edge('Start', 'PyDivertDriver')
    dot.edge('PyDivertDriver', 'InterceptorRecvLoop', label='捕获')
    dot.edge('InterceptorRecvLoop', 'RecvPacket')
    dot.edge('RecvPacket', 'PassToProcessor', label='获得数据包')
    dot.edge('PassToProcessor', 'ProcessorRequestsAnalysis')
    dot.edge('ProcessorRequestsAnalysis', 'AnalyzerChecksProtocol', label='分析请求')

    dot.edge('AnalyzerChecksProtocol', 'NonTCPUDP', label='是TCP或UDP')
    dot.edge('AnalyzerChecksProtocol', 'AllowNonTCPUDP', label='其他协议') # Path for non-TCP/UDP

    dot.edge('NonTCPUDP', 'CheckTCPAllowed', label='是TCP')
    dot.edge('NonTCPUDP', 'CheckUDPAllowed', label='是UDP')


    dot.edge('CheckTCPAllowed', 'BlockProtocol', label='否 (TCP禁止)')
    dot.edge('CheckTCPAllowed', 'ContinueToIPFilter', label='是 (TCP允许)')

    dot.edge('CheckUDPAllowed', 'BlockProtocol', label='否 (UDP禁止)')
    dot.edge('CheckUDPAllowed', 'ContinueToIPFilter', label='是 (UDP允许)')

    # 最终流向 (简化，实际会返回给Processor)
    # dot.edge('AllowNonTCPUDP', 'EndProtocolFilter')
    # dot.edge('BlockProtocol', 'EndProtocolFilter')
    # dot.edge('ContinueToIPFilter', 'EndProtocolFilter')
    # dot.node('EndProtocolFilter', '协议过滤结束', shape='component', style='filled', fillcolor='whitesmoke')


    try:
        dot.render('firewall_packet_capture_protocol_filter', view=False, cleanup=True)
        print("数据包捕获与协议过滤流程图已保存为 firewall_packet_capture_protocol_filter.svg")
    except Exception as e:
        print(f"生成数据包捕获与协议过滤流程图失败: {e}\n请确保已安装Graphviz并将其添加到系统PATH。")

if __name__ == '__main__':
    # 为了方便，您可以取消注释来一次性生成所有图表
    # generate_system_overall_architecture_diagram()
    # generate_system_data_flow_diagram()
    generate_packet_capture_protocol_filter_flowchart()
