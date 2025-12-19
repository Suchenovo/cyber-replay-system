from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
from datetime import datetime


class TrafficAnalyzer:
    """流量分析器"""

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = None

    def load_packets(self):
        """加载数据包"""
        if self.packets is None:
            self.packets = rdpcap(self.pcap_file)
        return self.packets

    def full_analysis(self):
        """完整分析"""
        return {
            "protocols": self.analyze_protocols(),
            "flows": self.analyze_flows(),
            "attack_path": self.analyze_attack_path(),
            "statistics": self.get_statistics(),
        }

    def analyze_protocols(self):
        """协议分析"""
        packets = self.load_packets()

        protocol_stats = Counter()
        for pkt in packets:
            if IP in pkt:
                if TCP in pkt:
                    protocol_stats["TCP"] += 1
                elif UDP in pkt:
                    protocol_stats["UDP"] += 1
                elif ICMP in pkt:
                    protocol_stats["ICMP"] += 1
                else:
                    protocol_stats["Other IP"] += 1
            else:
                protocol_stats["Non-IP"] += 1

        return {
            "protocol_distribution": [
                {"name": proto, "value": count}
                for proto, count in protocol_stats.items()
            ]
        }

    def analyze_flows(self):
        """流量会话分析"""
        packets = self.load_packets()

        flows = defaultdict(
            lambda: {"packets": 0, "bytes": 0, "start_time": None, "end_time": None}
        )

        for pkt in packets:
            if IP in pkt:
                # 定义流的五元组
                if TCP in pkt:
                    flow_key = (
                        pkt[IP].src,
                        pkt[TCP].sport,
                        pkt[IP].dst,
                        pkt[TCP].dport,
                        "TCP",
                    )
                elif UDP in pkt:
                    flow_key = (
                        pkt[IP].src,
                        pkt[UDP].sport,
                        pkt[IP].dst,
                        pkt[UDP].dport,
                        "UDP",
                    )
                else:
                    continue

                flow = flows[flow_key]
                flow["packets"] += 1
                flow["bytes"] += len(pkt)

                pkt_time = float(pkt.time)
                if flow["start_time"] is None:
                    flow["start_time"] = pkt_time
                flow["end_time"] = pkt_time

        # 转换为列表并排序
        flow_list = []
        for flow_key, stats in flows.items():
            flow_list.append(
                {
                    "src_ip": flow_key[0],
                    "src_port": flow_key[1],
                    "dst_ip": flow_key[2],
                    "dst_port": flow_key[3],
                    "protocol": flow_key[4],
                    "packets": stats["packets"],
                    "bytes": stats["bytes"],
                    "duration": (
                        stats["end_time"] - stats["start_time"]
                        if stats["start_time"]
                        else 0
                    ),
                }
            )

        # 按数据包数量排序
        flow_list.sort(key=lambda x: x["packets"], reverse=True)

        return {"total_flows": len(flow_list), "top_flows": flow_list[:20]}

    def analyze_attack_path(self):
        """攻击路径分析"""
        packets = self.load_packets()

        # 构建通信关系图
        connections = defaultdict(lambda: {"count": 0, "protocols": set()})
        nodes = set()

        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                nodes.add(src)
                nodes.add(dst)

                key = (src, dst)
                connections[key]["count"] += 1

                if TCP in pkt:
                    connections[key]["protocols"].add("TCP")
                elif UDP in pkt:
                    connections[key]["protocols"].add("UDP")
                elif ICMP in pkt:
                    connections[key]["protocols"].add("ICMP")

        # 识别潜在的攻击特征
        attack_indicators = []
        for (src, dst), info in connections.items():
            # 大量数据包可能表示扫描或DDoS
            if info["count"] > 100:
                attack_indicators.append(
                    {
                        "type": "high_traffic",
                        "src": src,
                        "dst": dst,
                        "count": info["count"],
                    }
                )

        return {
            "nodes": list(nodes),
            "connections": [
                {
                    "source": src,
                    "target": dst,
                    "count": info["count"],
                    "protocols": list(info["protocols"]),
                }
                for (src, dst), info in connections.items()
            ],
            "attack_indicators": attack_indicators,
        }

    def get_attack_path_graph(self):
        """生成攻击路径图（ECharts格式）"""
        analysis = self.analyze_attack_path()

        # 转换为ECharts图格式
        nodes_data = []
        links_data = []
        categories = [{"name": "正常主机"}, {"name": "可疑主机"}, {"name": "攻击源"}]

        # 识别攻击源（发送大量数据包的节点）
        node_stats = defaultdict(lambda: {"sent": 0, "received": 0})
        for conn in analysis["connections"]:
            node_stats[conn["source"]]["sent"] += conn["count"]
            node_stats[conn["target"]]["received"] += conn["count"]

        # 创建节点
        for node in analysis["nodes"]:
            stats = node_stats[node]
            # 判断节点类型
            if stats["sent"] > 1000:
                category = 2  # 攻击源
                symbol_size = 50
            elif stats["sent"] > 100 or stats["received"] > 100:
                category = 1  # 可疑
                symbol_size = 35
            else:
                category = 0  # 正常
                symbol_size = 25

            nodes_data.append(
                {
                    "id": node,
                    "name": node,
                    "symbolSize": symbol_size,
                    "category": category,
                    "label": {"show": True},
                }
            )

        # 创建连接
        for conn in analysis["connections"]:
            links_data.append(
                {
                    "source": conn["source"],
                    "target": conn["target"],
                    "value": conn["count"],
                    "lineStyle": {
                        "width": min(conn["count"] / 10, 10),
                        "curveness": 0.2,
                    },
                }
            )

        return {"nodes": nodes_data, "links": links_data, "categories": categories}

    def get_statistics(self):
        """获取统计信息"""
        packets = self.load_packets()

        if len(packets) == 0:
            return {}

        total_bytes = sum(len(pkt) for pkt in packets)
        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        duration = end_time - start_time

        # IP统计
        src_ips = Counter()
        dst_ips = Counter()

        for pkt in packets:
            if IP in pkt:
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1

        return {
            "total_packets": len(packets),
            "total_bytes": total_bytes,
            "duration": duration,
            "avg_packet_size": total_bytes / len(packets),
            "packets_per_second": len(packets) / duration if duration > 0 else 0,
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "top_talkers": [
                {"ip": ip, "packets": count} for ip, count in src_ips.most_common(10)
            ],
        }

    def get_timeline_data(self):
        """获取时间线数据"""
        packets = self.load_packets()

        if len(packets) == 0:
            return {"timeline": []}

        # 按时间窗口聚合
        time_windows = defaultdict(lambda: {"packets": 0, "bytes": 0})

        start_time = float(packets[0].time)
        window_size = 1.0  # 1秒窗口

        for pkt in packets:
            pkt_time = float(pkt.time)
            window = int((pkt_time - start_time) / window_size)
            time_windows[window]["packets"] += 1
            time_windows[window]["bytes"] += len(pkt)

        # 转换为时间线数据
        timeline = []
        for window in sorted(time_windows.keys()):
            timeline.append(
                {
                    "time": start_time + window * window_size,
                    "packets": time_windows[window]["packets"],
                    "bytes": time_windows[window]["bytes"],
                }
            )

        return {"timeline": timeline}
