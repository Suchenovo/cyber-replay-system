import os
import re
import socket
from collections import defaultdict, Counter
from typing import Dict, Any, List, Tuple
import dpkt


class TrafficAnalyzer:
    """
    高性能流量分析器 (生产级架构)
    特性:
    1. 极致性能: 采用 dpkt 替代 scapy，解析速度提升 10x-20x。
    2. 深度解析: 提取应用层 Payload (HTTP, DNS等)。
    3. 规则引擎: 内置基于正则的恶意特征匹配。
    4. 健壮性: 兼容 PCAP 和 PCAPNG，完善的异常捕获。
    """

    # --- 轻量级威胁检测规则引擎 (预编译正则以提升性能) ---
    THREAT_SIGNATURES = {
        "SQL_Injection": re.compile(
            rb"(?i)(union\s+select|select.*from|insert\s+into|drop\s+table|1=1)"
        ),
        "XSS_Attack": re.compile(rb"(?i)(<script>|javascript:|onerror=)"),
        "Path_Traversal": re.compile(rb"(?i)(\.\./\.\./|/etc/passwd|/bin/sh)"),
        "Command_Injection": re.compile(rb"(?i)(;\s*ls|\|\s*cat|`.*`)"),
    }

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file

    @staticmethod
    def _inet_to_str(inet: bytes) -> str:
        """将字节格式的 IP 转换为字符串，兼顾 IPv4 和 IPv6"""
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            try:
                return socket.inet_ntop(socket.AF_INET6, inet)
            except ValueError:
                return "Unknown"

    def _get_reader(self, f: Any) -> Any:
        """智能适配 PCAP 和 PCAPNG 格式"""
        try:
            # 先尝试标准 pcap
            return dpkt.pcap.Reader(f)
        except ValueError:
            # 回退到 pcapng
            f.seek(0)
            return dpkt.pcapng.Reader(f)

    def full_analysis(self) -> Dict[str, Any]:
        """全量流式分析入口 (O(n) 时间复杂度，极低内存消耗)"""

        # --- 1. 状态容器初始化 ---
        total_packets = 0
        total_bytes = 0
        start_time = None
        end_time = None

        protocol_stats = Counter()
        src_ips = Counter()
        connection_counts = defaultdict(int)

        # 记录 5元组 统计
        flow_stats = defaultdict(lambda: {"packets": 0, "bytes": 0, "threats": set()})
        # 时间线
        timeline_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        # 威胁告警列表
        alerts: List[Dict[str, Any]] = []

        # --- 2. 基于 dpkt 的高性能流式解析 ---
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"File not found: {self.pcap_file}")

        # 使用二进制方式读取，dpkt 需要
        with open(self.pcap_file, "rb") as f:
            try:
                pcap_reader = self._get_reader(f)

                for timestamp, buf in pcap_reader:
                    total_packets += 1
                    pkt_len = len(buf)
                    total_bytes += pkt_len

                    # 时间线聚合
                    if start_time is None:
                        start_time = timestamp
                    end_time = timestamp
                    ts_second = int(timestamp)
                    timeline_stats[ts_second]["packets"] += 1
                    timeline_stats[ts_second]["bytes"] += pkt_len

                    # 链路层解析 (默认按以太网解析，如果包损坏则跳过)
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        continue

                    # 仅处理 IP 数据包 (IPv4/IPv6)
                    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        protocol_stats["Non-IP"] += 1
                        continue

                    ip = eth.data
                    src_ip = self._inet_to_str(ip.src)
                    dst_ip = self._inet_to_str(ip.dst)
                    src_ips[src_ip] += 1
                    connection_counts[(src_ip, dst_ip)] += 1

                    # 传输层解析
                    proto_name = "Other"
                    src_port, dst_port = "*", "*"
                    payload = b""

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        proto_name = "TCP"
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                        payload = ip.data.data
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        proto_name = "UDP"
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                        payload = ip.data.data
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        proto_name = "ICMP"

                    protocol_stats[proto_name] += 1

                    # 记录 Flow (五元组或三元组)
                    if proto_name in ["TCP", "UDP"]:
                        flow_key = (src_ip, dst_ip, proto_name, src_port, dst_port)
                        flow_stats[flow_key]["packets"] += 1
                        flow_stats[flow_key]["bytes"] += pkt_len

                    # --- 3. 应用层解析与规则匹配 (深度流量检查 DPI) ---
                    if payload:
                        # 简单的特征匹配
                        for threat_name, pattern in self.THREAT_SIGNATURES.items():
                            if pattern.search(payload):
                                alert_info = {
                                    "time": timestamp,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "port": dst_port,
                                    "threat_type": threat_name,
                                    "protocol": proto_name,
                                }
                                alerts.append(alert_info)
                                # 在流级别标记此流包含威胁
                                if proto_name in ["TCP", "UDP"]:
                                    flow_stats[flow_key]["threats"].add(threat_name)

            except Exception as e:
                # OOM 或格式损坏时优雅降级，保留已解析的数据
                print(f"[Warning] PCAP parser stopped early due to: {e}")

        # --- 4. 数据格式化与组装 ---
        duration = (end_time - start_time) if (start_time and end_time) else 0

        statistics = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration": duration,
            "packets_per_second": total_packets / duration if duration > 0 else 0,
            "top_talkers": [
                {"ip": ip, "packets": c} for ip, c in src_ips.most_common(10)
            ],
            "total_threats": len(alerts),  # 新增维度：总威胁数
        }

        protocols = {
            "protocol_distribution": [
                {"name": k, "value": v} for k, v in protocol_stats.items()
            ]
        }

        # 流量会话 (按包数量 Top 50)
        sorted_flows = sorted(
            flow_stats.items(), key=lambda x: x[1]["packets"], reverse=True
        )[:50]
        top_flows = []
        for (src, dst, proto, sport, dport), info in sorted_flows:
            top_flows.append(
                {
                    "src_ip": src,
                    "src_port": sport,
                    "dst_ip": dst,
                    "dst_port": dport,
                    "protocol": proto,
                    "packets": info["packets"],
                    "bytes": info["bytes"],
                    "threats": list(info["threats"]),  # 包含该流命中的威胁标签
                }
            )

        # 攻击路径图 (Top 100 链路)
        limit_links = 100
        sorted_links = sorted(
            connection_counts.items(), key=lambda x: x[1], reverse=True
        )[:limit_links]
        valid_nodes = set()
        echarts_links = []

        for (src, dst), count in sorted_links:
            valid_nodes.add(src)
            valid_nodes.add(dst)
            echarts_links.append(
                {
                    "source": src,
                    "target": dst,
                    "value": count,
                    "lineStyle": {"width": min(count / 5, 5), "curveness": 0.2},
                }
            )

        echarts_nodes = []
        for node in valid_nodes:
            sent_count = src_ips[node]
            # 根据发包量简单分类
            if sent_count > 1000:
                cat = 2
            elif sent_count > 100:
                cat = 1
            else:
                cat = 0

            echarts_nodes.append(
                {
                    "id": node,
                    "name": node,
                    "symbolSize": 20 + (cat * 10),
                    "category": cat,
                    "label": {"show": True},
                }
            )

        attack_path_data = {
            "nodes": echarts_nodes,
            "links": echarts_links,
            "categories": [
                {"name": "正常主机"},
                {"name": "活跃主机"},
                {"name": "高频节点"},
            ],
        }

        # 时间线聚合
        timeline_list = [
            {"time": ts, "packets": info["packets"], "bytes": info["bytes"]}
            for ts, info in sorted(timeline_stats.items())
        ]

        return {
            "statistics": statistics,
            "protocols": protocols,
            "flows": {"top_flows": top_flows},
            "attack_path": attack_path_data,
            "timeline": {"timeline": timeline_list},
            "threat_alerts": alerts,  # [新增] 将规则引擎捕获的恶意流量独立返回
        }

    # 兼容原有的拆分接口
    def get_timeline_data(self):
        return self.full_analysis()["timeline"]

    def get_statistics(self):
        return self.full_analysis()["statistics"]

    def analyze_protocols(self):
        return self.full_analysis()["protocols"]

    def analyze_flows(self):
        return self.full_analysis()["flows"]

    def get_attack_path_graph(self):
        return self.full_analysis()["attack_path"]

    def analyze_attack_path(self):
        return self.full_analysis()["attack_path"]
