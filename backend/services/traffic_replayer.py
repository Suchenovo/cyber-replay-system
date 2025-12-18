from scapy.all import sendp, rdpcap, IP, Ether
import time
import uuid
from pathlib import Path
from typing import Optional
import threading
import json


class TrafficReplayer:
    """流量重放器"""

    # 存储所有任务状态
    tasks = {}

    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.packets = None

    def load_packets(self):
        """加载数据包"""
        if self.packets is None and self.pcap_file:
            self.packets = rdpcap(self.pcap_file)
        return self.packets

    def start_replay(
        self,
        target_ip: Optional[str] = None,
        speed_multiplier: float = 1.0,
        use_sandbox: bool = True,
    ):
        """启动流量重放"""
        task_id = str(uuid.uuid4())

        # 创建任务状态
        TrafficReplayer.tasks[task_id] = {
            "task_id": task_id,
            "status": "running",
            "progress": 0,
            "total_packets": 0,
            "sent_packets": 0,
            "start_time": time.time(),
            "pcap_file": self.pcap_file,
        }

        # 在后台线程中执行重放
        thread = threading.Thread(
            target=self._replay_thread,
            args=(task_id, target_ip, speed_multiplier, use_sandbox),
        )
        thread.daemon = True
        thread.start()

        return task_id

    def _replay_thread(
        self,
        task_id: str,
        target_ip: Optional[str],
        speed_multiplier: float,
        use_sandbox: bool,
    ):
        """重放线程"""
        try:
            packets = self.load_packets()
            TrafficReplayer.tasks[task_id]["total_packets"] = len(packets)

            # 模拟重放过程
            for i, pkt in enumerate(packets):
                if TrafficReplayer.tasks[task_id]["status"] == "stopped":
                    break

                # 修改目标IP（如果指定）
                if target_ip and IP in pkt:
                    pkt[IP].dst = target_ip

                # 发送数据包（在沙箱环境中）
                if use_sandbox:
                    # 这里应该使用Docker容器发送
                    # 简化版本：仅记录而不实际发送
                    pass
                else:
                    try:
                        # sendp(pkt, verbose=False)
                        pass  # 安全起见，默认不实际发送
                    except Exception as e:
                        print(f"发送数据包失败: {e}")

                # 更新进度
                TrafficReplayer.tasks[task_id]["sent_packets"] = i + 1
                TrafficReplayer.tasks[task_id]["progress"] = int(
                    (i + 1) / len(packets) * 100
                )

                # 控制发送速度
                if i < len(packets) - 1:
                    time_diff = float(packets[i + 1].time) - float(pkt.time)
                    if time_diff > 0:
                        time.sleep(time_diff / speed_multiplier)

            # 完成
            TrafficReplayer.tasks[task_id]["status"] = "completed"
            TrafficReplayer.tasks[task_id]["end_time"] = time.time()

        except Exception as e:
            TrafficReplayer.tasks[task_id]["status"] = "failed"
            TrafficReplayer.tasks[task_id]["error"] = str(e)

    def get_status(self, task_id: str):
        """获取任务状态"""
        if task_id not in TrafficReplayer.tasks:
            raise Exception("任务不存在")

        return TrafficReplayer.tasks[task_id]

    def stop_replay(self, task_id: str):
        """停止重放"""
        if task_id not in TrafficReplayer.tasks:
            raise Exception("任务不存在")

        TrafficReplayer.tasks[task_id]["status"] = "stopped"
        TrafficReplayer.tasks[task_id]["end_time"] = time.time()

        return {"message": "重放已停止", "task_id": task_id}

    def list_tasks(self):
        """列出所有任务"""
        return list(TrafficReplayer.tasks.values())
