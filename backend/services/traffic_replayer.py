import docker
import time
import json
import threading
import os
import tarfile
import io
import uuid
import logging
import redis
from scapy.all import sendp, PcapReader, IP, conf
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 获取 Redis 连接配置
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379

class TrafficReplayer:
    """流量重放器 (Redis 持久化版)"""

    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        self.packets = None
        # 初始化 Docker
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker client init failed: {e}")
            self.docker_client = None
        
        # 初始化 Redis
        try:
            self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis = None

    # --- Redis 辅助方法 ---
    def _save_task(self, task_id, data):
        """保存任务状态到 Redis"""
        if self.redis:
            self.redis.set(f"replay_task:{task_id}", json.dumps(data))
    
    def _get_task(self, task_id):
        """从 Redis 获取任务状态"""
        if self.redis:
            data = self.redis.get(f"replay_task:{task_id}")
            return json.loads(data) if data else None
        return None

    def _copy_to_container(self, container, src_path, dst_path):
        """将文件复制到容器内 (同上一步)"""
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
        """生成沙箱脚本 (同上一步)"""
        return f"""
import sys, time, json, os
from scapy.all import PcapReader, IP, sendp, conf
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
    tmp_path = status_path + ".tmp"
    with open(tmp_path, "w") as f: json.dump(data, f)
    os.rename(tmp_path, status_path)

try:
    total_packets = 0
    # 快速预扫描
    for _ in PcapReader(pcap_path): total_packets += 1
    update_status(0, total_packets, "running")

    sent_count = 0
    last_time = None
    reader = PcapReader(pcap_path)
    
    for pkt in reader:
        if os.path.exists(stop_path):
            update_status(sent_count, total_packets, "stopped")
            sys.exit(0)

        if target_ip != "None" and IP in pkt:
            pkt[IP].dst = target_ip

        sendp(pkt)
        sent_count += 1

        if last_time is not None:
            wait = (float(pkt.time) - float(last_time)) / speed
            if wait > 0: time.sleep(wait)
        last_time = pkt.time

        if sent_count % 10 == 0:
            update_status(sent_count, total_packets)

    update_status(sent_count, total_packets, "completed")
except Exception as e:
    update_status(0, 0, "failed", str(e))
    sys.exit(1)
"""

    def start_replay(self, target_ip: Optional[str] = None, speed_multiplier: float = 1.0, use_sandbox: bool = True):
        task_id = str(uuid.uuid4())
        
        # 初始化状态
        initial_state = {
            "task_id": task_id,
            "status": "initializing",
            "progress": 0,
            "total_packets": 0,
            "sent_packets": 0,
            "start_time": time.time(),
            "mode": "sandbox" if use_sandbox else "local"
        }
        self._save_task(task_id, initial_state)

        # 启动管理线程
        thread = threading.Thread(
            target=self._task_manager_thread,
            args=(task_id, target_ip, speed_multiplier, use_sandbox),
        )
        thread.daemon = True
        thread.start()

        return task_id

    def _task_manager_thread(self, task_id, target_ip, speed_multiplier, use_sandbox):
        try:
            if use_sandbox:
                self._run_sandbox_replay(task_id, target_ip, speed_multiplier)
            else:
                self._run_local_replay(task_id, target_ip, speed_multiplier)
        except Exception as e:
            logger.error(f"Task {task_id} failed: {e}")
            task = self._get_task(task_id) or {}
            task.update({"status": "failed", "error": str(e)})
            self._save_task(task_id, task)

    def _run_sandbox_replay(self, task_id, target_ip, speed):
        if not self.docker_client: raise Exception("Docker client not available")
        container = self.docker_client.containers.get('cyber-replay-sandbox')
        
        sandbox_pcap = f"/tmp/{task_id}.pcap"
        sandbox_script = f"/tmp/replay_{task_id}.py"
        status_file = f"/tmp/{task_id}.status"
        stop_file = f"/tmp/{task_id}.stop"

        self._copy_to_container(container, self.pcap_file, sandbox_pcap)
        script_content = self._generate_replay_script(
            sandbox_pcap, status_file, stop_file, target_ip or "None", speed
        )
        local_script_path = f"/tmp/replay_{task_id}.py"
        with open(local_script_path, "w") as f: f.write(script_content)
        self._copy_to_container(container, local_script_path, sandbox_script)
        os.remove(local_script_path)

        container.exec_run(f"python3 {sandbox_script}", detach=True)
        
        # 更新状态为运行中
        task = self._get_task(task_id)
        task["status"] = "running"
        self._save_task(task_id, task)
        
        while True:
            # 重新获取最新状态（检查是否有停止请求）
            current_task = self._get_task(task_id)
            if current_task.get("stop_requested"):
                container.exec_run(f"touch {stop_file}")
            
            try:
                exit_code, output = container.exec_run(f"cat {status_file}")
                if exit_code == 0 and output:
                    status_data = json.loads(output.decode('utf-8'))
                    
                    # 合并状态
                    current_task.update({
                        "sent_packets": status_data["sent_packets"],
                        "total_packets": status_data["total_packets"]
                    })
                    
                    if status_data["total_packets"] > 0:
                        current_task["progress"] = int((status_data["sent_packets"] / status_data["total_packets"]) * 100)

                    script_status = status_data.get("status")
                    if script_status in ["completed", "stopped", "failed"]:
                        current_task["status"] = script_status
                        if script_status == "failed":
                            current_task["error"] = status_data.get("error")
                        self._save_task(task_id, current_task)
                        break
                    
                    self._save_task(task_id, current_task)
            except Exception:
                pass

            time.sleep(1)
        
        container.exec_run(f"rm {sandbox_pcap} {sandbox_script} {status_file} {stop_file}")

    def _run_local_replay(self, task_id, target_ip, speed):
        task = self._get_task(task_id)
        task["status"] = "running"
        self._save_task(task_id, task)
        
        try:
            total = 0
            for _ in PcapReader(self.pcap_file): total += 1
            task["total_packets"] = total
            self._save_task(task_id, task)

            reader = PcapReader(self.pcap_file)
            last_time = None

            for i, pkt in enumerate(reader):
                # 重新检查停止信号
                task = self._get_task(task_id)
                if task.get("stop_requested"):
                    task["status"] = "stopped"
                    self._save_task(task_id, task)
                    return

                if target_ip and IP in pkt: pkt[IP].dst = target_ip
                sendp(pkt, verbose=0)

                # 更新进度
                if i % 10 == 0:
                    task["sent_packets"] = i + 1
                    if total > 0:
                        task["progress"] = int(((i + 1) / total) * 100)
                    self._save_task(task_id, task)

                if last_time:
                    wait = (float(pkt.time) - float(last_time)) / speed
                    if wait > 0: time.sleep(wait)
                last_time = pkt.time

            task["status"] = "completed"
            task["progress"] = 100
            self._save_task(task_id, task)

        except Exception as e:
            task["status"] = "failed"
            task["error"] = str(e)
            self._save_task(task_id, task)

    def get_status(self, task_id: str):
        task = self._get_task(task_id)
        if not task:
            raise Exception("任务不存在")
        return task

    def stop_replay(self, task_id: str):
        task = self._get_task(task_id)
        if task:
            task["stop_requested"] = True
            self._save_task(task_id, task)
            return {"message": "Stopping task...", "task_id": task_id}
        raise Exception("Task not found")

    def list_tasks(self):
        if not self.redis: return []
        keys = self.redis.keys("replay_task:*")
        tasks = []
        for k in keys:
            data = self.redis.get(k)
            if data: tasks.append(json.loads(data))
        return tasks