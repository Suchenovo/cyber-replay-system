from scapy.all import PcapReader, IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
import os

class TrafficAnalyzer:
    """
    终极流量分析器 (All-in-One 一次遍历版)
    集成：ECharts适配 + Top-N截断 + 内置时间线
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file

    def _get_protocol_name(self, pkt):
        if TCP in pkt: return "TCP"
        if UDP in pkt: return "UDP"
        if ICMP in pkt: return "ICMP"
        return "Other"

    def full_analysis(self):
        # --- 1. 初始化容器 ---
        total_packets = 0
        total_bytes = 0
        start_time = None
        end_time = None
        
        protocol_stats = Counter()
        src_ips = Counter()
        connection_counts = defaultdict(int)
        flow_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        
        # [新增] 时间线容器：按秒聚合
        timeline_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

        # --- 2. 极速流式读取 (只读一遍，全量计算) ---
        try:
            with PcapReader(self.pcap_file) as reader:
                for pkt in reader:
                    total_packets += 1
                    pkt_len = len(pkt)
                    total_bytes += pkt_len
                    
                    try:
                        pkt_time = float(pkt.time)
                        # [新增] 顺手更新时间线
                        ts_second = int(pkt_time)
                        timeline_stats[ts_second]["packets"] += 1
                        timeline_stats[ts_second]["bytes"] += pkt_len
                    except:
                        continue

                    if start_time is None: start_time = pkt_time
                    end_time = pkt_time

                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        proto = self._get_protocol_name(pkt)
                        
                        protocol_stats[proto] += 1
                        src_ips[src] += 1
                        connection_counts[(src, dst)] += 1

                        if proto in ["TCP", "UDP"]:
                            flow_key = (src, dst, proto)
                            flow_stats[flow_key]["packets"] += 1
                            flow_stats[flow_key]["bytes"] += pkt_len
                    else:
                        protocol_stats["Non-IP"] += 1
        except Exception as e:
            print(f"解析警告: {e}")

        # --- 3. 数据组装 ---
        duration = (end_time - start_time) if (start_time and end_time) else 0

        # A. 统计概览
        statistics = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": duration,
            "packets_per_second": total_packets / duration if duration > 0 else 0,
            "top_talkers": [{"ip": ip, "packets": c} for ip, c in src_ips.most_common(10)]
        }

        # B. 协议分布
        protocols = {"protocol_distribution": [{"name": k, "value": v} for k, v in protocol_stats.items()]}

        # C. 流量会话 (Top 50)
        sorted_flows = sorted(flow_stats.items(), key=lambda x: x[1]['packets'], reverse=True)[:50]
        top_flows = []
        for (src, dst, proto), info in sorted_flows:
            top_flows.append({
                "src_ip": src, "src_port": "*", "dst_ip": dst, "dst_port": "*", "protocol": proto,
                "packets": info["packets"], "bytes": info["bytes"]
            })
        flows_data = {"top_flows": top_flows}

        # D. 攻击路径图 (Top 100)
        limit_links = 100 
        sorted_links = sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)[:limit_links]
        valid_nodes = set()
        echarts_links = []
        
        for (src, dst), count in sorted_links:
            valid_nodes.add(src)
            valid_nodes.add(dst)
            echarts_links.append({
                "source": src, "target": dst, "value": count,
                "lineStyle": {"width": min(count / 5, 5), "curveness": 0.2}
            })

        categories = [{"name": "正常主机"}, {"name": "活跃主机"}, {"name": "高频节点"}]
        echarts_nodes = []
        for node in valid_nodes:
            sent_count = src_ips[node]
            if sent_count > 1000: cat = 2
            elif sent_count > 100: cat = 1
            else: cat = 0
            
            echarts_nodes.append({
                "id": node, "name": node, "symbolSize": 20 + (cat * 10),
                "category": cat, "label": {"show": True}
            })

        attack_path_data = {
            "nodes": echarts_nodes,
            "links": echarts_links,
            "categories": categories
        }

        # E. [新增] 格式化时间线数据
        timeline_list = []
        for ts in sorted(timeline_stats.keys()):
            timeline_list.append({
                "time": ts,
                "packets": timeline_stats[ts]["packets"],
                "bytes": timeline_stats[ts]["bytes"]
            })

        # 返回大礼包
        return {
            "statistics": statistics,
            "protocols": protocols,
            "flows": flows_data,
            "attack_path": attack_path_data,
            "timeline": {"timeline": timeline_list} # 直接返回时间线
        }

    # 兼容接口（保留，以防万一）
    def get_timeline_data(self): return self.full_analysis()["timeline"]
    def get_statistics(self): return self.full_analysis()["statistics"]
    def analyze_protocols(self): return self.full_analysis()["protocols"]
    def analyze_flows(self): return self.full_analysis()["flows"]
    def get_attack_path_graph(self): return self.full_analysis()["attack_path"]
    def analyze_attack_path(self): return self.full_analysis()["attack_path"]