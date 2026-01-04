from scapy.all import PcapReader, IP, TCP, UDP, ICMP, ARP
from collections import Counter
import os

class PCAPParser:
    """PCAP文件解析器 (OOM优化版：流式读取)"""

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        # 移除 self.packets，禁止全量缓存

    def get_basic_info(self):
        """获取基本信息 (流式统计)"""
        count = 0
        try:
            # 仅遍历计数，不占用内存
            # 注意：对于GB级大文件，此步骤可能耗时较长，但在Python层面这是最安全的做法
            for _ in PcapReader(self.pcap_file):
                count += 1
        except Exception:
            pass
            
        return {
            "total_packets": count,
            "file_size": os.path.getsize(self.pcap_file),
            "format": "PCAP",
        }

    def get_detailed_info(self):
        """获取详细信息 (流式处理，防止OOM)"""
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()
        
        start_time = None
        end_time = None
        packet_count = 0

        try:
            # 使用上下文管理器打开流式读取
            with PcapReader(self.pcap_file) as reader:
                for pkt in reader:
                    packet_count += 1
                    
                    # 1. 时间戳统计
                    try:
                        ts = float(pkt.time)
                        if start_time is None:
                            start_time = ts
                        end_time = ts
                    except (AttributeError, ValueError):
                        pass

                    # 2. 协议与IP统计
                    if IP in pkt:
                        protocols["IP"] += 1
                        src_ips[pkt[IP].src] += 1
                        dst_ips[pkt[IP].dst] += 1

                        if TCP in pkt:
                            protocols["TCP"] += 1
                            src_ports[pkt[TCP].sport] += 1
                            dst_ports[pkt[TCP].dport] += 1
                        elif UDP in pkt:
                            protocols["UDP"] += 1
                            src_ports[pkt[UDP].sport] += 1
                            dst_ports[pkt[UDP].dport] += 1
                        elif ICMP in pkt:
                            protocols["ICMP"] += 1

                    if ARP in pkt:
                        protocols["ARP"] += 1
                        
        except Exception as e:
            print(f"Warning: Error parsing pcap stream: {e}")

        # 计算持续时间
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

    def get_packets_summary(self, limit=100):
        """获取数据包摘要 (流式读取前 N 个)"""
        summary = []
        
        try:
            with PcapReader(self.pcap_file) as reader:
                for i, pkt in enumerate(reader):
                    if i >= limit:
                        break
                        
                    packet_info = {
                        "index": i, 
                        "time": float(pkt.time) if hasattr(pkt, 'time') else 0.0, 
                        "length": len(pkt)
                    }

                    if IP in pkt:
                        packet_info.update(
                            {
                                "src_ip": pkt[IP].src,
                                "dst_ip": pkt[IP].dst,
                                "protocol": pkt[IP].proto,
                            }
                        )

                        if TCP in pkt:
                            packet_info.update(
                                {
                                    "src_port": pkt[TCP].sport,
                                    "dst_port": pkt[TCP].dport,
                                    "flags": str(pkt[TCP].flags),
                                }
                            )
                        elif UDP in pkt:
                            packet_info.update(
                                {"src_port": pkt[UDP].sport, "dst_port": pkt[UDP].dport}
                            )

                    summary.append(packet_info)
        except Exception as e:
            print(f"Warning: Error getting summary: {e}")

        return summary