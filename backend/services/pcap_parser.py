from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, ICMP, ARP
from collections import Counter
import os


class PCAPParser:
    """PCAP文件解析器"""

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = None

    def load_packets(self, max_packets=None):
        """加载数据包"""
        if self.packets is None:
            try:
                if max_packets:
                    self.packets = rdpcap(self.pcap_file, count=max_packets)
                else:
                    self.packets = rdpcap(self.pcap_file)
            except Exception as e:
                raise Exception(f"加载PCAP文件失败: {str(e)}")
        return self.packets

    def get_basic_info(self):
        """获取基本信息"""
        packets = self.load_packets(max_packets=1000)

        return {
            "total_packets": len(packets),
            "file_size": os.path.getsize(self.pcap_file),
            "format": "PCAP",
        }

    def get_detailed_info(self):
        """获取详细信息"""
        packets = self.load_packets()

        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()

        for pkt in packets:
            # 统计协议
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

        # 获取时间信息
        if len(packets) > 0:
            start_time = float(packets[0].time)
            end_time = float(packets[-1].time)
            duration = end_time - start_time
        else:
            start_time = end_time = duration = 0

        return {
            "total_packets": len(packets),
            "duration": duration,
            "start_time": start_time,
            "end_time": end_time,
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
        """获取数据包摘要"""
        packets = self.load_packets(max_packets=limit)

        summary = []
        for i, pkt in enumerate(packets):
            packet_info = {"index": i, "time": float(pkt.time), "length": len(pkt)}

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

        return summary
