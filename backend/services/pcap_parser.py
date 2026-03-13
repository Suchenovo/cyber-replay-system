import os
import socket
from collections import Counter
from typing import Dict, Any, List
import dpkt


class PCAPParser:
    """PCAP文件解析器 (全量 dpkt 极速版)"""

    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file

    @staticmethod
    def _inet_to_str(inet: bytes) -> str:
        """将字节格式的 IP 转换为字符串"""
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
            return dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            return dpkt.pcapng.Reader(f)

    def _get_tcp_flags(self, flags: int) -> str:
        """解析 TCP 标志位，还原为类似 Scapy 的字符串表示"""
        ret = []
        if flags & dpkt.tcp.TH_FIN:
            ret.append("F")
        if flags & dpkt.tcp.TH_SYN:
            ret.append("S")
        if flags & dpkt.tcp.TH_RST:
            ret.append("R")
        if flags & dpkt.tcp.TH_PUSH:
            ret.append("P")
        if flags & dpkt.tcp.TH_ACK:
            ret.append("A")
        if flags & dpkt.tcp.TH_URG:
            ret.append("U")
        if flags & dpkt.tcp.TH_ECE:
            ret.append("E")
        if flags & dpkt.tcp.TH_CWR:
            ret.append("C")
        return "".join(ret) if ret else "none"

    def get_basic_info(self) -> Dict[str, Any]:
        """获取基本信息 (流式统计，极速版)"""
        count = 0
        try:
            if os.path.exists(self.pcap_file):
                with open(self.pcap_file, "rb") as f:
                    reader = self._get_reader(f)
                    # 仅遍历计数，避免任何反序列化开销
                    for _ in reader:
                        count += 1
        except Exception as e:
            print(f"Warning: Error getting basic info: {e}")

        return {
            "total_packets": count,
            "file_size": (
                os.path.getsize(self.pcap_file) if os.path.exists(self.pcap_file) else 0
            ),
            "format": "PCAP/PCAPNG",
        }

    def get_detailed_info(self) -> Dict[str, Any]:
        """获取详细信息 (完整统计面板数据)"""
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()

        start_time = None
        end_time = None
        packet_count = 0

        try:
            with open(self.pcap_file, "rb") as f:
                reader = self._get_reader(f)
                for timestamp, buf in reader:
                    packet_count += 1

                    # 1. 时间戳统计
                    if start_time is None:
                        start_time = timestamp
                    end_time = timestamp

                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue  # 忽略损坏的包

                    # 2. 协议与IP统计
                    if isinstance(eth.data, dpkt.arp.ARP):
                        protocols["ARP"] += 1
                        continue

                    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        continue

                    ip = eth.data
                    protocols["IP"] += 1
                    src_ip = self._inet_to_str(ip.src)
                    dst_ip = self._inet_to_str(ip.dst)
                    src_ips[src_ip] += 1
                    dst_ips[dst_ip] += 1

                    if isinstance(ip.data, dpkt.tcp.TCP):
                        protocols["TCP"] += 1
                        src_ports[ip.data.sport] += 1
                        dst_ports[ip.data.dport] += 1
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        protocols["UDP"] += 1
                        src_ports[ip.data.sport] += 1
                        dst_ports[ip.data.dport] += 1
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        protocols["ICMP"] += 1

        except Exception as e:
            print(f"Warning: Error parsing detailed info: {e}")

        duration = (end_time - start_time) if (start_time and end_time) else 0

        return {
            "total_packets": packet_count,
            "duration": duration,
            "start_time": start_time or 0,
            "end_time": end_time or 0,
            "protocols": dict(protocols.most_common()),
            "top_src_ips": [
                {"ip": ip, "count": count} for ip, count in src_ips.most_common(10)
            ],
            "top_dst_ips": [
                {"ip": ip, "count": count} for ip, count in dst_ips.most_common(10)
            ],
            "top_src_ports": [
                {"port": port, "count": count}
                for port, count in src_ports.most_common(10)
            ],
            "top_dst_ports": [
                {"port": port, "count": count}
                for port, count in dst_ports.most_common(10)
            ],
        }

    def get_packets_summary(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取数据包摘要 (用于前端列表预览)"""
        summary = []

        try:
            with open(self.pcap_file, "rb") as f:
                reader = self._get_reader(f)
                for i, (timestamp, buf) in enumerate(reader):
                    if i >= limit:
                        break

                    packet_info = {"index": i, "time": timestamp, "length": len(buf)}

                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                            ip = eth.data
                            packet_info.update(
                                {
                                    "src_ip": self._inet_to_str(ip.src),
                                    "dst_ip": self._inet_to_str(ip.dst),
                                    "protocol": ip.p,  # IP 协议号
                                }
                            )

                            if isinstance(ip.data, dpkt.tcp.TCP):
                                packet_info.update(
                                    {
                                        "src_port": ip.data.sport,
                                        "dst_port": ip.data.dport,
                                        "flags": self._get_tcp_flags(ip.data.flags),
                                    }
                                )
                            elif isinstance(ip.data, dpkt.udp.UDP):
                                packet_info.update(
                                    {
                                        "src_port": ip.data.sport,
                                        "dst_port": ip.data.dport,
                                    }
                                )
                    except Exception:
                        pass  # 忽略解析失败的层级，保留基础信息

                    summary.append(packet_info)
        except Exception as e:
            print(f"Warning: Error getting summary: {e}")

        return summary
