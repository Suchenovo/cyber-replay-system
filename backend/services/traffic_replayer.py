import docker
import time
import json
import threading
import os
import tarfile
import io
import uuid
import logging
from scapy.all import sendp, rdpcap, IP, conf, PcapReader
from typing import Optional

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrafficReplayer:
    """流量重放器 (优化版：支持沙箱独立进程与流式进度)"""

    tasks = {}

    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.packets = None
        # 初始化 Docker 客户端
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker client init failed: {e}")
            self.docker_client = None

    def _copy_to_container(self, container, src_path, dst_path):
        """将文件复制到容器内"""
        try:
            with open(src_path, 'rb') as f:
                file_data = f.read()
            
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                tar_info = tarfile.TarInfo(name=os.path.basename(dst_path))
                tar_info.size = len(file_data)
                tar.addfile(tar_info, io.BytesIO(file_data))
            
            tar_stream.seek(0)
            container.put_archive(path=os.path.dirname(dst_path), data=tar_stream)
        except Exception as e:
            logger.error(f"Failed to copy file to container: {e}")
            raise

    def _generate_replay_script(self, pcap_path, status_path, stop_path, target_ip, speed):
        """生成在沙箱内运行的 Python 脚本内容"""
        # 注意：这个脚本是注入到容器里运行的，不能依赖外部环境
        script_content = f"""
import sys
import time
import json
import os
from scapy.all import PcapReader, IP, sendp, conf

# 关闭 Scapy 冗余输出
conf.verb = 0

pcap_path = "{pcap_path}"
status_path = "{status_path}"
stop_path = "{stop_path}"
target_ip = "{target_ip}"
speed = {speed}

def update_status(sent, total, status="running", error=None):
    data = {{
        "sent_packets": sent,
        "total_packets": total,
        "status": status,
        "error": error,
        "timestamp": time.time()
    }}
    # 原子写入：先写临时文件再重命名，防止读取时文件不完整
    tmp_path = status_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f)
    os.rename(tmp_path, status_path)

try:
    # 1. 预统计总包数 (为了进度条)
    total_packets = 0
    # 使用 PcapReader 避免内存溢出，但这需要读两遍文件
    # 对于巨大文件，建议直接根据文件大小估算或跳过此步
    for _ in PcapReader(pcap_path):
        total_packets += 1
    
    update_status(0, total_packets, "running")

    # 2. 开始重放
    sent_count = 0
    last_time = None
    
    # 再次打开流式读取
    reader = PcapReader(pcap_path)
    
    for pkt in reader:
        # 检查停止信号
        if os.path.exists(stop_path):
            update_status(sent_count, total_packets, "stopped")
            sys.exit(0)

        # 修改目标 IP
        if target_ip != "None" and IP in pkt:
            pkt[IP].dst = target_ip

        # 发送
        sendp(pkt)
        sent_count += 1

        # 速度控制
        if last_time is not None:
            # 简单的时间差计算，实际可能需要更复杂的调度
            wait = (float(pkt.time) - float(last_time)) / speed
            if wait > 0:
                time.sleep(wait)
        last_time = pkt.time

        # 每 10 个包更新一次状态，减少 I/O
        if sent_count % 10 == 0:
            update_status(sent_count, total_packets)

    update_status(sent_count, total_packets, "completed")

except Exception as e:
    update_status(0, 0, "failed", str(e))
    sys.exit(1)
"""
        return script_content

    def start_replay(self, target_ip: Optional[str] = None, speed_multiplier: float = 1.0, use_sandbox: bool = True):
        task_id = str(uuid.uuid4())
        
        # 初始化任务状态
        TrafficReplayer.tasks[task_id] = {
            "task_id": task_id,
            "status": "initializing",
            "progress": 0,
            "total_packets": 0,
            "sent_packets": 0,
            "start_time": time.time(),
            "mode": "sandbox" if use_sandbox else "local"
        }

        # 启动管理线程
        thread = threading.Thread(
            target=self._task_manager_thread,
            args=(task_id, target_ip, speed_multiplier, use_sandbox),
        )
        thread.daemon = True
        thread.start()

        return task_id

    def _task_manager_thread(self, task_id, target_ip, speed_multiplier, use_sandbox):
        """任务管理线程：负责启动重放并监控进度"""
        try:
            if use_sandbox:
                self._run_sandbox_replay(task_id, target_ip, speed_multiplier)
            else:
                self._run_local_replay(task_id, target_ip, speed_multiplier)
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            TrafficReplayer.tasks[task_id]["status"] = "failed"
            TrafficReplayer.tasks[task_id]["error"] = str(e)

    def _run_sandbox_replay(self, task_id, target_ip, speed):
        """沙箱模式执行逻辑"""
        if not self.docker_client:
            raise Exception("Docker client not available")

        container = self.docker_client.containers.get('cyber-replay-sandbox')
        
        # 定义容器内路径
        sandbox_pcap = f"/tmp/{task_id}.pcap"
        sandbox_script = f"/tmp/replay_{task_id}.py"
        status_file = f"/tmp/{task_id}.status"
        stop_file = f"/tmp/{task_id}.stop"

        # 1. 上传 PCAP
        self._copy_to_container(container, self.pcap_file, sandbox_pcap)

        # 2. 生成并上传脚本
        script_content = self._generate_replay_script(
            sandbox_pcap, status_file, stop_file, 
            target_ip if target_ip else "None", speed
        )
        local_script_path = f"/tmp/replay_{task_id}.py"
        with open(local_script_path, "w") as f:
            f.write(script_content)
        self._copy_to_container(container, local_script_path, sandbox_script)
        os.remove(local_script_path) # 清理本地临时文件

        # 3. 异步启动脚本 (detach=True)
        # 使用 nohup 确保后台运行
        cmd = f"python3 {sandbox_script}"
        container.exec_run(cmd, detach=True)

        # 4. 监控循环
        TrafficReplayer.tasks[task_id]["status"] = "running"
        
        while True:
            # 检查是否收到停止指令
            if TrafficReplayer.tasks[task_id].get("stop_requested"):
                # 创建停止标记文件
                container.exec_run(f"touch {stop_file}")
            
            # 读取进度文件
            try:
                # exec_run 返回 (exit_code, output)
                exit_code, output = container.exec_run(f"cat {status_file}")
                if exit_code == 0 and output:
                    status_data = json.loads(output.decode('utf-8'))
                    
                    # 更新内存中的任务状态
                    TrafficReplayer.tasks[task_id]["sent_packets"] = status_data["sent_packets"]
                    TrafficReplayer.tasks[task_id]["total_packets"] = status_data["total_packets"]
                    
                    if status_data["total_packets"] > 0:
                        progress = int((status_data["sent_packets"] / status_data["total_packets"]) * 100)
                        TrafficReplayer.tasks[task_id]["progress"] = progress

                    # 检查脚本报告的状态
                    script_status = status_data.get("status")
                    if script_status in ["completed", "stopped", "failed"]:
                        TrafficReplayer.tasks[task_id]["status"] = script_status
                        if script_status == "failed":
                            TrafficReplayer.tasks[task_id]["error"] = status_data.get("error")
                        break
            except Exception:
                # 可能文件还没生成，忽略
                pass

            time.sleep(1) # 1秒轮询一次

        # 清理容器内文件 (可选)
        container.exec_run(f"rm {sandbox_pcap} {sandbox_script} {status_file} {stop_file}")

    def _run_local_replay(self, task_id, target_ip, speed):
        """本地模式执行逻辑 (保持原有逻辑但增加流式读取)"""
        TrafficReplayer.tasks[task_id]["status"] = "running"
        
        try:
            # 预统计
            total = 0
            for _ in PcapReader(self.pcap_file): total += 1
            TrafficReplayer.tasks[task_id]["total_packets"] = total

            reader = PcapReader(self.pcap_file)
            last_time = None

            for i, pkt in enumerate(reader):
                if TrafficReplayer.tasks[task_id].get("stop_requested"):
                    TrafficReplayer.tasks[task_id]["status"] = "stopped"
                    return

                if target_ip and IP in pkt:
                    pkt[IP].dst = target_ip

                sendp(pkt, verbose=0)

                # 更新进度
                TrafficReplayer.tasks[task_id]["sent_packets"] = i + 1
                if total > 0:
                    TrafficReplayer.tasks[task_id]["progress"] = int(((i + 1) / total) * 100)

                # 简单控速
                if last_time:
                    wait = (float(pkt.time) - float(last_time)) / speed
                    if wait > 0: time.sleep(wait)
                last_time = pkt.time

            TrafficReplayer.tasks[task_id]["status"] = "completed"

        except Exception as e:
            TrafficReplayer.tasks[task_id]["status"] = "failed"
            TrafficReplayer.tasks[task_id]["error"] = str(e)

    def get_status(self, task_id: str):
        return TrafficReplayer.tasks.get(task_id, {"status": "not_found"})

    def stop_replay(self, task_id: str):
        if task_id in TrafficReplayer.tasks:
            # 设置标志位，让监控线程去处理实际停止逻辑
            TrafficReplayer.tasks[task_id]["stop_requested"] = True
            return {"message": "Stopping task...", "task_id": task_id}
        raise Exception("Task not found")

    def list_tasks(self):
        return list(TrafficReplayer.tasks.values())