# packet_flow_diagram.py
# 需要先安装 graphviz: pip install graphviz
# 并且系统中需要安装 Graphviz 的可执行文件，并将其添加到PATH环境变量

from graphviz import Digraph

def generate_packet_flow_diagram():
    """
    生成防火墙数据包处理流程图
    """
    dot = Digraph('Firewall_Packet_Flow', comment='防火墙数据包处理流程图', format='svg')
    dot.attr(rankdir='TB', labelloc="t", label="防火墙数据包处理流程图", fontsize="20")

    # 设置全局字体为 "Microsoft YaHei"
    dot.attr('graph', fontname='Microsoft YaHei')
    dot.attr('node', fontname='Microsoft YaHei')
    dot.attr('edge', fontname='Microsoft YaHei')

    # 定义节点样式
    process_style = {'shape': 'box', 'style': 'rounded'}
    decision_style = {'shape': 'diamond', 'style': 'filled', 'fillcolor': 'lightyellow'}
    io_style = {'shape': 'parallelogram', 'style': 'filled', 'fillcolor': 'lightblue'} # 输入输出
    action_style = {'shape': 'ellipse', 'style': 'filled', 'fillcolor': 'lightgreen'} # 动作
    important_style = {'color': 'red', 'penwidth': '2.0'} # 关键流程的边框

    # 流程节点
    dot.node('A', '网络数据包到达\n(来自网络协议栈)', **io_style)
    dot.node('B', 'PyDivert驱动捕获数据包', **process_style)
    dot.node('C', 'PacketInterceptor接收数据包', **process_style, **important_style)
    dot.node('D', 'PacketProcessor.handle_packet()', **process_style)
    dot.node('E', 'PacketAnalyzer.should_pass()\n(规则匹配引擎)', **process_style, **important_style)

    # 规则匹配子流程 (简化为一个大节点，可以在内部再细化)
    # 为了图表简洁，这里不完全展开所有规则判断，而是用一个概括性的节点
    # 实际论文中，这一部分可以单独绘制更详细的规则匹配流程图
    dot.node('F_PROTO', '1. 协议过滤 (TCP/UDP)?', **decision_style, **important_style)
    dot.node('F_IP_WL', '2. IP白名单匹配?', **decision_style, **important_style)
    dot.node('F_IP_BL', '3. IP黑名单匹配?', **decision_style, **important_style)
    dot.node('F_PORT_WL', '4. 端口白名单匹配?', **decision_style, **important_style)
    dot.node('F_PORT_BL', '5. 端口黑名单匹配?', **decision_style, **important_style)
    dot.node('F_CONTENT', '6. 内容过滤匹配?', **decision_style, **important_style)

    dot.node('G_ALLOW_IP_WL', '标记: 放行 (IP白名单)', **action_style)
    dot.node('G_ALLOW_PORT_WL', '标记: 放行 (端口白名单)', **action_style)
    dot.node('G_ALLOW_DEFAULT', '标记: 放行 (默认)', **action_style)
    dot.node('G_BLOCK', '标记: 拦截', **action_style)


    dot.node('H', 'PacketAnalyzer返回分析结果\n(放行/拦截)', **process_style)
    dot.node('I', 'PacketProcessor执行动作', **process_style, **important_style)
    dot.node('J_DECISION', '结果是"放行"?', **decision_style, **important_style)
    dot.node('K_SEND', '调用 _send_packet_safe()', **process_style)
    dot.node('L_INTERCEPTOR_SEND', 'PacketInterceptor.send()', **process_style)
    dot.node('M_PYDIVERT_SEND', 'PyDivert注入数据包', **process_style)
    dot.node('N_PACKET_OUT', '数据包发出至网络', **io_style, **important_style)
    dot.node('O_DROP', '数据包丢弃', **action_style, **important_style)
    dot.node('P', 'PacketProcessor更新统计', **process_style)
    dot.node('Q', '调用回调 (Firewall -> MainWindow -> UI)', **process_style)
    dot.node('R', 'UI界面更新 (流量/日志)', **io_style, **important_style)

    # 流程连接
    dot.edge('A', 'B')
    dot.edge('B', 'C')
    dot.edge('C', 'D')
    dot.edge('D', 'E')
    dot.edge('E', 'F_PROTO')

    # 规则匹配流程
    dot.edge('F_PROTO', 'G_BLOCK', label='不允许的协议')
    dot.edge('F_PROTO', 'F_IP_WL', label='允许的协议')

    dot.edge('F_IP_WL', 'G_ALLOW_IP_WL', label='是 (匹配白名单)')
    dot.edge('F_IP_WL', 'F_IP_BL', label='否')

    dot.edge('F_IP_BL', 'G_BLOCK', label='是 (匹配黑名单)')
    dot.edge('F_IP_BL', 'F_PORT_WL', label='否')

    dot.edge('F_PORT_WL', 'G_ALLOW_PORT_WL', label='是 (匹配白名单)')
    dot.edge('F_PORT_WL', 'F_PORT_BL', label='否')

    dot.edge('F_PORT_BL', 'G_BLOCK', label='是 (匹配黑名单)')
    dot.edge('F_PORT_BL', 'F_CONTENT', label='否')

    dot.edge('F_CONTENT', 'G_BLOCK', label='是 (匹配内容)')
    dot.edge('F_CONTENT', 'G_ALLOW_DEFAULT', label='否 (默认放行)')

    # 连接规则匹配结果到后续流程
    dot.edge('G_ALLOW_IP_WL', 'H')
    dot.edge('G_ALLOW_PORT_WL', 'H')
    dot.edge('G_ALLOW_DEFAULT', 'H')
    dot.edge('G_BLOCK', 'H')


    dot.edge('H', 'I')
    dot.edge('I', 'J_DECISION')
    dot.edge('J_DECISION', 'K_SEND', label='是 (放行)')
    dot.edge('K_SEND', 'L_INTERCEPTOR_SEND')
    dot.edge('L_INTERCEPTOR_SEND', 'M_PYDIVERT_SEND')
    dot.edge('M_PYDIVERT_SEND', 'N_PACKET_OUT')
    dot.edge('J_DECISION', 'O_DROP', label='否 (拦截)')

    # 后续共同流程
    dot.edge('N_PACKET_OUT', 'P') # 放行后也更新统计和UI
    dot.edge('O_DROP', 'P')      # 拦截后也更新统计和UI
    dot.edge('P', 'Q')
    dot.edge('Q', 'R')


    # 渲染并保存
    try:
        dot.render('firewall_packet_flow', view=False)
        print("数据包处理流程图已保存为 firewall_packet_flow.svg")
    except Exception as e:
        print(f"生成数据包处理流程图失败: {e}")
        print("请确保已安装Graphviz并将其添加到系统PATH。")

if __name__ == '__main__':
    generate_packet_flow_diagram()
